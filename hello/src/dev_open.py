"""DEV ONLY. Plays any vendor, with that vendor's key. NO API route: invoke only, IAM protected.

    {"op": "seal_request", "vendor": "HELLO_VENDOR", "payload": {...}, "path": "/hello"}
        -> {"request_key": ...}
    {"op": "open_reply", "vendor": "HELLO_VENDOR", "response_key": ..., "response_value": ...}
        -> the decrypted reply

A seal and open oracle for every vendor key it can read. Never give it an HTTP route.
"""

import json

from payload_crypto import CryptoError, get_vendor_keys, open_reply, seal_request


def handler(event, context):
    if isinstance(event.get("body"), str):          # tolerate an API-shaped event
        event = json.loads(event["body"])
    op = event.get("op", "open_reply")
    try:
        keys = get_vendor_keys(event.get("vendor") or "HELLO_VENDOR")
        if op == "seal_request":
            payload = event.get("payload")
            if not isinstance(payload, dict):
                return {"ok": False, "error": "CRY400", "message": "payload must be a JSON object"}
            return {"ok": True, **seal_request(payload, keys.key, keys.key_id, keys.vendor,
                                               event.get("path", "/hello"), event.get("method", "POST"))}
        if op == "open_reply":
            rk, rv = event.get("response_key"), event.get("response_value")
            if not isinstance(rk, str) or not isinstance(rv, str):
                return {"ok": False, "error": "CRY400", "message": "send response_key and response_value"}
            return {"ok": True, "reply": open_reply(rk, rv, keys.key)}
        return {"ok": False, "error": "CRY400", "message": f"unknown op {op}"}
    except CryptoError as exc:
        print(f"{op} failed {exc.code}: {exc.detail}")
        return {"ok": False, "error": exc.code, "message": "operation failed"}
