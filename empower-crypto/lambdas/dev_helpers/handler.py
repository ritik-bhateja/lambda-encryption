"""
empower_care_<env>_dev_helpers  --  SAMPLE STACKS ONLY, OFF BY DEFAULT

Postman cannot do AES-GCM (its sandbox ships crypto-js, which has no GCM
mode), so it cannot build a request_value on its own. These two routes play
the vendor for the CALLER'S OWN keys, so a Postman collection can drive the
deployed API:

    POST /dev/seal   { "path": "/employee", "payload": {...} }  ->  { "request_value": "..." }
    POST /dev/open   { "response_key": "...", "response_value": "..." }  ->  { "response_data": ... }

They sit on a SEPARATE API that the template only creates when
EnableDevHelpers=true and Env is not prod. They still require a valid token
and only ever derive keys for the vendor behind that token. Even so, this is a
seal and open oracle: never enable it anywhere real vendors connect.
"""

import json
import logging
import time

import empower_crypto as ec

log = logging.getLogger()
log.setLevel(logging.INFO)


def lambda_handler(event, context):
    started_at = time.perf_counter()
    profile = ec.read_crypto_profile(event)
    body = event.get("body-json") or {}
    request_id = profile["request_id"]

    try:
        epoch_id = ec.epoch_id_for(time.time(), profile["epoch_seconds"])
        kid, request_key, kek_response = ec.derive_keys(
            profile["client_ref"], profile["key_version"], epoch_id)

        if profile["path"].endswith("/dev/seal"):
            request_value = ec.seal_request(
                body.get("payload") or {}, request_key, kid, profile["client_ref"],
                body.get("path", "/employee"), body.get("method", "POST"))
            result = ec.build_envelope(request_id, started_at=started_at)
            result.update({"request_value": request_value, "kid": kid})
            return result

        if profile["path"].endswith("/dev/open"):
            label = ec.read_key(body["response_key"])
            opened = ec.open_envelope(
                body["response_key"], body["response_value"],
                client_ref=profile["client_ref"], key_version=profile["key_version"],
                epoch_seconds=profile["epoch_seconds"],
                path=label.get("pth", ""), method=label.get("mtd", "POST"),
                kek_direction="res", check_replay=False)
            result = ec.build_envelope(request_id, started_at=started_at)
            result.update(opened)
            return result

        return _fail(request_id, 404, "DEV404", "Unknown dev route", started_at)

    except ec.CryptoError as exc:
        log.warning("dev helper rejected %s: %s", exc.code, exc.log_detail)
        return _fail(request_id, exc.http_status, exc.code, "Could not process", started_at)
    except (KeyError, TypeError, ValueError) as exc:
        log.warning("dev helper bad input: %s", type(exc).__name__)
        return _fail(request_id, 400, "DEV400", "Bad input", started_at)


def _fail(request_id, status, code, message, started_at):
    result = ec.build_envelope(request_id, response_code=status, error_code=code,
                               error_message=message, message="Request rejected",
                               started_at=started_at)
    result["encrypted"] = False
    return result
