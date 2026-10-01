"""
empower_care_prod_lambda_requestvalidator

The existing REQUEST-type Lambda authorizer, with the crypto profile added.

What is new compared to the current production code:

  1. Reads four extra attributes from keyrolemapping and returns them in the
     authorizer context: client_ref, crypto_mode, key_version, epoch_seconds.
  2. Uses a SEPARATE quota bucket for /crypto/* so a key fetch does not spend
     a business call.
  3. Scopes the Allow policy to the incoming methodArn instead of a wildcard.
  4. Logs no tokens and no secrets.
  5. AUTH_MODE=sample, for a self-contained sample stack where ANZ is not
     reachable. Tokens are HS256, signed with a secret held in Secrets Manager,
     so only someone with access to the AWS account can mint one. Never use
     sample mode for real vendors.

Environment variables
---------------------
AUTH_MODE            "anz" (default) or "sample"
SAMPLE_TOKEN_SECRET_ID  Secrets Manager id of the HS256 secret, sample mode only
KEYROLE_TABLE        empower_care_prod_dydb_keyrolemapping
TOKEN_LIMIT_TABLE    empower_care_prod_valid_token_limit
ANZ_VALIDATE_URL     ANZ tokenvalidate endpoint
ANZ_INVALIDATE_URL   ANZ invalidatetoken endpoint
CLIENT_KEY_HASH      "sha256" (default) or "md5" for the legacy lookup key
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time

import boto3
import urllib3
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

_ddb = boto3.client("dynamodb")
_sm = boto3.client("secretsmanager")
_http = urllib3.PoolManager()
_sample_secret_cache = {"value": None, "expires_at": 0.0}

ANZ_TIMEOUT = urllib3.Timeout(connect=2.0, read=5.0)


class Unauthorized(Exception):
    pass


def lambda_handler(event, context):
    method_arn = event.get("methodArn", "*")
    resource_path = _resource_path(event)
    source_ip = ((event.get("requestContext") or {}).get("identity") or {}).get("sourceIp", "")

    try:
        token = _bearer_token(event)
    except Unauthorized:
        # API Gateway turns this into a 401 before any business Lambda runs.
        raise Exception("Unauthorized")

    sample_mode = os.environ.get("AUTH_MODE", "anz") == "sample"
    if sample_mode:
        claims = _verify_sample_token(token)
        if claims is None:
            return _deny(method_arn, "sample token failed verification")
        claimed = claims.get("merchant_id") or claims.get("client_id")
    else:
        claimed = _claimed_client(token)
    if not claimed:
        return _deny(method_arn, "no merchant_id or client_id claim")

    mapping = _load_mapping(claimed)
    if mapping is None:
        return _deny(method_arn, f"no mapping for {_short(claimed)}")

    # Key fetches must not spend the client's business quota.
    bucket = "crypto" if resource_path.startswith("/crypto") else "business"
    if not _consume_quota(token, claimed, mapping, bucket):
        if not sample_mode:
            _invalidate_at_anz(token)
        return _deny(method_arn, f"quota exhausted on {bucket} bucket")

    # Sample tokens were already verified cryptographically above.
    if not sample_mode and not _validate_with_anz(token, claimed):
        return _deny(method_arn, "ANZ rejected the token")

    log.info(json.dumps({
        "event": "allow", "client_ref": claimed, "path": resource_path,
        "bucket": bucket, "source_ip": source_ip,
    }))

    return {
        "principalId": claimed,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                # Scoped to the incoming method, not a wildcard.
                "Resource": [method_arn],
            }],
        },
        "context": {
            # existing
            "role_id": mapping["role_id"],
            "allowed_ids": mapping["allowed_ids"],
            # new, for the crypto layer
            "client_ref": claimed,
            "crypto_mode": mapping["crypto_mode"],
            "key_version": str(mapping["key_version"]),
            "epoch_seconds": str(mapping["epoch_seconds"]),
            "source_ips": mapping["source_ips"],
        },
    }


# ---------------------------------------------------------------------------

def _resource_path(event):
    ctx = event.get("requestContext") or {}
    return ctx.get("resourcePath") or ctx.get("path") or event.get("path", "")


def _bearer_token(event):
    headers = event.get("headers") or {}
    raw = headers.get("Authorization") or headers.get("authorization")
    if not raw:
        raise Unauthorized("no Authorization header")
    return raw[7:].strip() if raw.lower().startswith("bearer ") else raw.strip()


def _claimed_client(token):
    """Decode without verifying. This identifies the CLAIM, it establishes no
    trust. Trust comes from the ANZ tokenvalidate call below."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return None
    return claims.get("merchant_id") or claims.get("client_id")


def _client_key(value):
    """SHA-256 for new records. Set CLIENT_KEY_HASH=md5 while migrating."""
    if os.environ.get("CLIENT_KEY_HASH", "sha256") == "md5":
        return hashlib.md5(value.encode()).hexdigest()   # noqa: S324 legacy only
    return hashlib.sha256(value.encode()).hexdigest()


def _load_mapping(claimed):
    try:
        item = _ddb.get_item(
            TableName=os.environ["KEYROLE_TABLE"],
            Key={"client_id": {"S": _client_key(claimed)}},
        ).get("Item")
    except ClientError as exc:
        log.error("mapping lookup failed: %s", exc)
        return None

    if not item:
        return None

    return {
        "role_id": item.get("role_id", {}).get("S", ""),
        "allowed_ids": item.get("allowed_ids", {}).get("S", ""),
        "limit": int(item.get("limit", {}).get("N", "1")),
        "source_ips": item.get("source_ips", {}).get("S", ""),
        # new attributes, with safe defaults for records not yet backfilled
        "crypto_mode": item.get("crypto_mode", {}).get("S", "off"),
        "key_version": int(item.get("key_version", {}).get("N", "1")),
        "epoch_seconds": int(item.get("epoch_seconds", {}).get("N", "86400")),
    }


def _consume_quota(token, claimed, mapping, bucket):
    """One atomic update. if_not_exists creates the record on first use, so two
    concurrent first requests cannot overwrite each other."""
    table = os.environ.get("TOKEN_LIMIT_TABLE")
    if not table:
        return True

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        result = _ddb.update_item(
            TableName=table,
            Key={
                "token": {"S": f"{bucket}#{token_hash}"},
                "client_id": {"S": _client_key(claimed)},
            },
            UpdateExpression=(
                "SET available_limit = if_not_exists(available_limit, :start) - :one, "
                "ttl_epoch = if_not_exists(ttl_epoch, :ttl)"
            ),
            ExpressionAttributeValues={
                ":start": {"N": str(mapping["limit"])},
                ":one": {"N": "1"},
                ":ttl": {"N": str(int(time.time()) + 86400)},
            },
            ReturnValues="UPDATED_NEW",
        )
        return int(result["Attributes"]["available_limit"]["N"]) >= 0
    except ClientError as exc:
        log.error("quota update failed: %s", exc)
        return False   # fail closed


def _validate_with_anz(token, claimed):
    url = os.environ.get("ANZ_VALIDATE_URL")
    if not url:
        # Fail closed. Without ANZ, an unsigned token proves nothing.
        log.error("ANZ_VALIDATE_URL is not set, denying")
        return False
    try:
        response = _http.request(
            "POST", url,
            body=json.dumps({"merchant_id": claimed}).encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=ANZ_TIMEOUT, retries=False,
        )
        if response.status != 200:
            return False
        return json.loads(response.data).get("status") is True
    except Exception as exc:
        log.error("ANZ validation failed: %s", exc)
        return False   # fail closed


def _b64u_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _sample_secret():
    now = time.time()
    if _sample_secret_cache["value"] and now < _sample_secret_cache["expires_at"]:
        return _sample_secret_cache["value"]
    raw = _sm.get_secret_value(SecretId=os.environ["SAMPLE_TOKEN_SECRET_ID"])["SecretString"]
    secret = json.loads(raw)["secret"].encode()
    if len(secret) < 32:
        raise ValueError("sample token secret shorter than 32 characters")
    _sample_secret_cache.update(value=secret, expires_at=now + 300)
    return secret


def _verify_sample_token(token):
    """HS256 only. Signature, then expiry. Returns the claims or None."""
    try:
        header_seg, payload_seg, signature_seg = token.split(".")
        header = json.loads(_b64u_decode(header_seg))
        if header.get("alg") != "HS256":
            return None                     # refuses alg none and anything else
        expected = hmac.new(_sample_secret(), f"{header_seg}.{payload_seg}".encode(),
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64u_decode(signature_seg)):
            return None
        claims = json.loads(_b64u_decode(payload_seg))
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or exp < time.time():
            return None
        return claims
    except Exception as exc:
        log.warning("sample token rejected: %s", type(exc).__name__)
        return None


def _invalidate_at_anz(token):
    url = os.environ.get("ANZ_INVALIDATE_URL")
    if not url:
        return
    try:
        _http.request("POST", url, headers={"Authorization": f"Bearer {token}"},
                      timeout=ANZ_TIMEOUT, retries=False)
    except Exception as exc:
        log.warning("ANZ invalidation failed: %s", exc)


def _deny(method_arn, reason):
    log.warning(json.dumps({"event": "deny", "reason": reason}))
    return {
        "principalId": "unknown",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": "Deny",
                "Resource": [method_arn],
            }],
        },
    }


def _short(value):
    return hashlib.sha256(value.encode()).hexdigest()[:12]
