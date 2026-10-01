"""
empower_care_prod_lambda_cryptokeys

Serves POST /crypto/session-key.

It sits behind the same request validator as every other protected API, so a
caller still needs a valid ANZ token. What is different here:

  - the authorizer must use a SEPARATE quota bucket for this resource, so a
    key fetch does not spend a business call,
  - source_ips is enforced here even though it is not enforced platform wide,
  - a well behaved client calls this ONCE A DAY. Anything more is a signal.

What it hands out, once a day, per vendor:

  request_encryption_key   the vendor encrypts every request_value directly
                           with this. AES-256-GCM, fresh random iv each time
  kek_response             a key encryption key. The platform locks each
                           response DEK with it, the vendor unlocks. It never
                           touches business data
  kek_id                   names today's pair. The vendor puts it in every
                           request label as "kid"

Nothing about the key is stored. It is derived on demand from the master seed,
so this function has no database of its own.

Environment variables
---------------------
PAYLOAD_SEED_SECRET_ID   Secrets Manager id of the master seed
KEY_ISSUE_TABLE          DynamoDB table counting issues per client per epoch
MAX_ISSUES_PER_EPOCH     Default 10
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError

from empower_crypto import (
    ALG, REQUEST_ALG, DEFAULT_EPOCH_SECONDS, GRACE_SECONDS, IST,
    b64u, derive_keys, epoch_id_for, read_crypto_profile, build_envelope,
)

log = logging.getLogger()
log.setLevel(logging.INFO)

_ddb = boto3.client("dynamodb")
MAX_ISSUES = int(os.environ.get("MAX_ISSUES_PER_EPOCH", "10"))


def lambda_handler(event, context):
    started_at = time.perf_counter()
    profile = read_crypto_profile(event)
    client_ref = profile["client_ref"]
    request_id = profile["request_id"]

    # NOTE: never log request_encryption_key, kek_response, the seed, the bearer token
    # or client_secret. kek_id and client_ref only.
    log.info(json.dumps({
        "request_id": request_id,
        "client_ref": client_ref,
        "source_ip": _source_ip(event),
        "event": "key_request",
    }))

    # The body is optional. If a vendor names an algorithm, it must be ours.
    requested_alg = (event.get("body-json") or {}).get("alg")
    if requested_alg not in (None, REQUEST_ALG, ALG):
        return _reject(request_id, "CRY401",
                       f"Requests use {REQUEST_ALG}, responses use {ALG}", started_at)

    if not _source_ip_allowed(event, profile):
        return _reject(request_id, "CRY403",
                       "Source address is not permitted for this client", started_at)

    epoch_seconds = profile["epoch_seconds"] or DEFAULT_EPOCH_SECONDS
    now = time.time()
    epoch_id = epoch_id_for(now, epoch_seconds)

    if not _count_issue(client_ref, epoch_id):
        return _reject(request_id, "CRY429",
                       "Key issue limit reached for this period", started_at, 429)

    kek_id, kek_req, kek_res = derive_keys(client_ref, profile["key_version"], epoch_id)

    epoch_start = datetime.fromtimestamp(epoch_id * epoch_seconds, IST)
    epoch_end = epoch_start + timedelta(seconds=epoch_seconds)

    body = build_envelope(request_id, started_at=started_at)
    body.update({
        "kek_id": kek_id,
        "request_alg": REQUEST_ALG,                # A256GCM, directly with the key below
        "response_alg": ALG,                       # A256GCMKW, DEK wrapped with kek_response
        "request_encryption_key": b64u(kek_req),   # vendor encrypts requests with this
        "kek_response": b64u(kek_res),             # vendor unwraps the response DEK with this
        "not_before": epoch_start.isoformat(),
        "not_after": (epoch_end + timedelta(seconds=GRACE_SECONDS)).isoformat(),
        "next_rotation_at": epoch_end.isoformat(),
        "epoch_seconds": epoch_seconds,
        "grace_seconds": GRACE_SECONDS,
    })

    log.info(json.dumps({
        "request_id": request_id, "client_ref": client_ref,
        "kek_id": kek_id, "event": "key_issued",
    }))
    return body


def _source_ip(event):
    return ((event.get("context") or {}).get("source-ip")
            or (event.get("params", {}).get("header", {}) or {}).get("X-Forwarded-For", ""))


def _source_ip_allowed(event, profile):
    """Enforce source_ips here first. One endpoint, called once a day, low risk."""
    allowed = (event.get("context") or {}).get("source-ips", "")
    if not allowed:
        return True   # no allowlist configured for this client
    caller = (_source_ip(event) or "").split(",")[0].strip()
    return caller in {ip.strip() for ip in allowed.split(",") if ip.strip()}


def _count_issue(client_ref, epoch_id):
    """Atomic per epoch counter. Returns False once the client is over the cap."""
    table = os.environ.get("KEY_ISSUE_TABLE")
    if not table:
        return True

    try:
        result = _ddb.update_item(
            TableName=table,
            Key={"client_ref": {"S": client_ref}, "epoch_id": {"N": str(epoch_id)}},
            UpdateExpression="SET issues = if_not_exists(issues, :zero) + :one, "
                             "ttl_epoch = if_not_exists(ttl_epoch, :ttl)",
            ExpressionAttributeValues={
                ":zero": {"N": "0"},
                ":one": {"N": "1"},
                ":ttl": {"N": str(int(time.time()) + 172800)},
            },
            ReturnValues="UPDATED_NEW",
        )
        issues = int(result["Attributes"]["issues"]["N"])
        if issues > MAX_ISSUES:
            log.warning("client %s exceeded key issue cap: %s", client_ref, issues)
            return False
        if issues > 3:
            log.warning("client %s has fetched %s keys this epoch", client_ref, issues)
        return True
    except ClientError as exc:
        log.error("issue counter unavailable: %s", exc)
        return False   # fail closed


def _reject(request_id, code, message, started_at, status=400):
    envelope = build_envelope(
        request_id, response_code=status, error_code=code,
        error_message=message, message="Request rejected", started_at=started_at,
    )
    envelope["encrypted"] = False
    return envelope
