"""payload_crypto decorators: every event shape, many vendors, cache, rotation, attacks."""

import json
import os
import sys
import time

import boto3
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "layer", "python"))

import payload_crypto as pc  # noqa: E402

VENDORS = ["ACME", "GLOBEX", "INITECH"]


@pytest.fixture
def aws():
    with mock_aws():
        os.environ.update(AWS_DEFAULT_REGION="ap-south-1", PAYLOAD_NONCE_TABLE="nonce",
                          PAYLOAD_KEY_SECRET_TEMPLATE="payload-keys/{vendor}")
        os.environ.pop("PAYLOAD_ALLOWED_VENDORS", None)
        pc._clients.clear()
        pc.clear_key_cache()
        sm = boto3.client("secretsmanager")
        keys = {}
        for v in VENDORS:
            keys[v] = os.urandom(32)
            sm.create_secret(Name=f"payload-keys/{v}",
                             SecretString=json.dumps({"key_id": f"{v}-v1", "key_hex": keys[v].hex()}))
        boto3.client("dynamodb").create_table(
            TableName="nonce", BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "nonce_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "nonce_id", "KeyType": "HASH"}])
        yield keys


# The "existing" business handlers, unchanged apart from the decorator.

@pc.secure_api()
def proxy_handler(event, context):
    body = json.loads(event["body"]) if event.get("body") else {}
    return {"statusCode": 201, "headers": {"X-Trace": "t1"},
            "body": json.dumps({"hello": body.get("name", "world"), "seen": body})}


@pc.secure_api()
def get_handler(event, context):
    return {"statusCode": 200, "body": json.dumps({"id": event["pathParameters"]["id"]})}


@pc.secure_api(plain_fields=("response_code",))
def mapping_handler(event, context):
    return {"response_code": 200, "response_data": {"echo": event["body-json"]}}


SEEN_EVENTS = []


@pc.secure_api()
def logging_handler(event, context):
    SEEN_EVENTS.append(json.dumps(event, default=str))
    return {"statusCode": 200, "body": "{}"}


def http_api_event(vendor, body, path="/hello", method="POST", stage="$default"):
    raw_path = path if stage == "$default" else f"/{stage}{path}"
    return {"version": "2.0", "rawPath": raw_path, "headers": {"x-vendor-id": vendor} if vendor else {},
            "requestContext": {"http": {"method": method, "path": raw_path}, "stage": stage},
            "body": json.dumps(body) if body is not None else None, "isBase64Encoded": False}


def rest_proxy_event(vendor, body, path="/orders", method="POST"):
    return {"resource": path, "path": path, "httpMethod": method, "headers": {"X-Vendor-Id": vendor},
            "requestContext": {"stage": "dev"}, "body": json.dumps(body) if body is not None else None}


def mapping_event(vendor, body, path="/employee", method="POST"):
    return {"body-json": body, "params": {"header": {"X-Vendor-Id": vendor}},
            "context": {"resource-path": path, "http-method": method}}


def seal(keys, vendor, payload, path="/hello", method="POST", **label_changes):
    """A validly encrypted request, optionally with label fields changed."""
    if not label_changes:
        return pc.seal_request(payload, keys[vendor], f"{vendor}-v1", vendor, path, method)
    label = {"v": 1, "alg": "A256GCM", "kid": f"{vendor}-v1", "cid": vendor, "pth": path,
             "mtd": method, "iat": int(time.time()), "jti": os.urandom(16).hex()}
    label.update(label_changes)
    seg = pc.b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
    iv = os.urandom(12)
    sealed = AESGCM(keys[vendor]).encrypt(iv, json.dumps(payload).encode(), seg.encode())
    return {"request_key": ".".join([seg, pc.b64u(iv), pc.b64u(sealed[:-16]), pc.b64u(sealed[-16:])])}


def open_proxy(out, key):
    body = json.loads(out["body"])
    assert set(body) == {"response_key", "response_value"}
    return pc.open_reply(body["response_key"], body["response_value"], key)


def err(out):
    if "statusCode" in out:
        return out["statusCode"], json.loads(out["body"])["error"]
    return out["response_code"], out["response_error_code"]


# ------------------------------------------------------------------ shapes ----

def test_http_api_round_trip_keeps_status_and_headers(aws):
    out = proxy_handler(http_api_event("ACME", seal(aws, "ACME", {"name": "care"})), None)
    assert out["statusCode"] == 201 and out["headers"]["X-Trace"] == "t1"
    assert "care" not in out["body"]
    assert open_proxy(out, aws["ACME"]) == {"hello": "care", "seen": {"name": "care"}}


def test_http_api_named_stage_is_stripped(aws):
    out = proxy_handler(http_api_event("ACME", seal(aws, "ACME", {"name": "s"}), stage="dev"), None)
    assert out["statusCode"] == 201


def test_rest_proxy_round_trip(aws):
    out = proxy_handler(rest_proxy_event("GLOBEX", seal(aws, "GLOBEX", {"name": "g"}, path="/orders")), None)
    assert open_proxy(out, aws["GLOBEX"])["hello"] == "g"


def test_mapping_template_round_trip_with_plain_status(aws):
    out = mapping_handler(mapping_event("INITECH", seal(aws, "INITECH", {"a": 1}, path="/employee")), None)
    assert set(out) == {"response_code", "response_key", "response_value"}
    assert out["response_code"] == 200
    got = pc.open_reply(out["response_key"], out["response_value"], aws["INITECH"])
    assert got == {"response_code": 200, "response_data": {"echo": {"a": 1}}}


def test_get_without_body_still_seals_reply(aws):
    ev = http_api_event("ACME", None, path="/items/7", method="GET")
    ev["pathParameters"] = {"id": "7"}
    out = get_handler(ev, None)
    assert open_proxy(out, aws["ACME"]) == {"id": "7"}


def test_handler_returning_plain_dict_is_sealed(aws):
    @pc.secure_api()
    def bare(event, context):
        return {"ok": True}
    out = bare(http_api_event("ACME", seal(aws, "ACME", {})), None)
    assert out["statusCode"] == 200 and open_proxy(out, aws["ACME"]) == {"ok": True}


def test_error_status_from_handler_is_still_sealed(aws):
    @pc.secure_api()
    def not_found(event, context):
        return {"statusCode": 404, "body": json.dumps({"error": "EMP404", "employee": "E1"})}
    out = not_found(http_api_event("ACME", seal(aws, "ACME", {})), None)
    assert out["statusCode"] == 404 and "E1" not in out["body"]


# ------------------------------------------------------------------ vendors ----

def test_each_vendor_uses_its_own_key(aws):
    for v in VENDORS:
        out = proxy_handler(http_api_event(v, seal(aws, v, {"name": v})), None)
        assert open_proxy(out, aws[v])["hello"] == v
        other = VENDORS[(VENDORS.index(v) + 1) % len(VENDORS)]
        with pytest.raises(pc.CryptoError):
            open_proxy(out, aws[other])


def test_header_naming_another_vendor_is_refused(aws):
    out = proxy_handler(http_api_event("GLOBEX", seal(aws, "ACME", {"name": "x"})), None)
    assert err(out) == (400, "CRY412")


def test_missing_header_says_so(aws):
    out = proxy_handler(http_api_event(None, {"request_key": "a.b.c.d"}), None)
    assert json.loads(out["body"]) == {"error": "CRY400", "message": "X-Vendor-Id header is required"}


def test_missing_bad_and_unknown_vendor(aws):
    assert err(proxy_handler(http_api_event(None, {"request_key": "a.b.c.d"}), None)) == (400, "CRY400")
    assert err(proxy_handler(http_api_event("../etc", {"request_key": "a.b.c.d"}), None)) == (400, "CRY400")
    assert err(proxy_handler(http_api_event("NOPE", {"request_key": "a.b.c.d"}), None)) == (400, "CRY410")


def test_allow_list_refuses_before_any_aws_call(aws, monkeypatch):
    monkeypatch.setenv("PAYLOAD_ALLOWED_VENDORS", "ACME, GLOBEX")
    calls = []
    monkeypatch.setattr(pc, "_client", lambda name: calls.append(name))
    assert err(proxy_handler(http_api_event("INITECH", {"request_key": "a.b.c.d"}), None)) == (400, "CRY410")
    assert calls == []


def test_keys_are_cached(aws, monkeypatch):
    real = pc._client("secretsmanager")
    calls = []

    class Counting:
        def get_secret_value(self, **kw):
            calls.append(kw["SecretId"])
            return real.get_secret_value(**kw)
    monkeypatch.setitem(pc._clients, "secretsmanager", Counting())
    for _ in range(3):
        proxy_handler(http_api_event("ACME", seal(aws, "ACME", {})), None)
    proxy_handler(http_api_event("GLOBEX", seal(aws, "GLOBEX", {})), None)
    assert calls == ["payload-keys/ACME", "payload-keys/GLOBEX"]


def test_unknown_vendor_miss_is_cached(aws, monkeypatch):
    real = pc._client("secretsmanager")
    calls = []

    class Counting:
        def get_secret_value(self, **kw):
            calls.append(1)
            return real.get_secret_value(**kw)
    monkeypatch.setitem(pc._clients, "secretsmanager", Counting())
    for _ in range(5):
        proxy_handler(http_api_event("NOPE", {"request_key": "a.b.c.d"}), None)
    assert len(calls) == 1


def test_rotation_accepts_previous_key_and_replies_with_current(aws):
    new = os.urandom(32)
    boto3.client("secretsmanager").put_secret_value(
        SecretId="payload-keys/ACME", SecretString=json.dumps({
            "key_id": "ACME-v2", "key_hex": new.hex(),
            "previous_key_id": "ACME-v1", "previous_key_hex": aws["ACME"].hex()}))
    pc.clear_key_cache()
    out = proxy_handler(http_api_event("ACME", seal(aws, "ACME", {"name": "old"})), None)
    assert open_proxy(out, new)["hello"] == "old"


def test_keys_never_reach_the_handler_event_or_repr(aws):
    SEEN_EVENTS.clear()
    logging_handler(http_api_event("ACME", seal(aws, "ACME", {})), None)
    assert aws["ACME"].hex() not in SEEN_EVENTS[0]
    keys = pc.get_vendor_keys("ACME")
    assert aws["ACME"].hex() not in repr(keys) and "key=" not in repr(keys)


def test_current_vendor_keys_outside_a_call_is_an_error(aws):
    with pytest.raises(pc.CryptoError):
        pc.current_vendor_keys()


# ------------------------------------------------------------------ attacks ----

@pytest.mark.parametrize("body,code", [
    ({"name": "plain"}, "CRY426"),
    ({"request_value": "a.b.c.d"}, "CRY426"),
    ({"request_key": "a.b.c"}, "CRY400"),
    ({"request_key": "x", "name": "extra"}, "CRY400"),
])
def test_malformed(aws, body, code):
    assert err(proxy_handler(http_api_event("ACME", body), None)) == (400, code)


def test_not_json_body(aws):
    ev = http_api_event("ACME", None)
    ev["body"] = "not json"
    assert err(proxy_handler(ev, None)) == (400, "CRY400")


def test_replay(aws):
    req = seal(aws, "ACME", {"name": "r"})
    assert proxy_handler(http_api_event("ACME", req), None)["statusCode"] == 201
    assert err(proxy_handler(http_api_event("ACME", req), None)) == (400, "CRY409")


def test_same_jti_for_two_vendors_does_not_collide(aws):
    a = seal(aws, "ACME", {}, jti="shared")
    g = seal(aws, "GLOBEX", {}, jti="shared")
    assert proxy_handler(http_api_event("ACME", a), None)["statusCode"] == 201
    assert proxy_handler(http_api_event("GLOBEX", g), None)["statusCode"] == 201


def test_wrong_key(aws):
    req = pc.seal_request({}, os.urandom(32), "ACME-v1", "ACME", "/hello", "POST")
    assert err(proxy_handler(http_api_event("ACME", req), None)) == (400, "CRY422")


def test_tampered_and_spliced(aws):
    a = seal(aws, "ACME", {"n": 1})["request_key"].split(".")
    b = seal(aws, "ACME", {"n": 2})["request_key"].split(".")
    spliced = {"request_key": ".".join([b[0]] + a[1:])}
    assert err(proxy_handler(http_api_event("ACME", spliced), None)) == (400, "CRY422")
    # b's jti is now burned (checked before decrypting), so tamper with a fresh one
    c = seal(aws, "ACME", {"n": 3})["request_key"].split(".")
    ct = bytearray(pc.b64u_decode(c[2])); ct[0] ^= 1
    c[2] = pc.b64u(bytes(ct))
    assert err(proxy_handler(http_api_event("ACME", {"request_key": ".".join(c)}), None)) == (400, "CRY422")


@pytest.mark.parametrize("changes,code", [
    ({"pth": "/other"}, "CRY412"),
    ({"mtd": "PUT"}, "CRY412"),
    ({"kid": "ACME-v0"}, "CRY410"),
    ({"alg": "A128GCM"}, "CRY401"),
    ({"iat": int(time.time()) - 600}, "CRY413"),
    ({"v": 2}, "CRY400"),
])
def test_label_checks(aws, changes, code):
    assert err(proxy_handler(http_api_event("ACME", seal(aws, "ACME", {}, **changes)), None)) == (400, code)


def test_mapping_errors_use_the_envelope(aws):
    out = mapping_handler(mapping_event("ACME", {"name": "plain"}), None)
    assert out == {"response_code": 400, "response_error_code": "CRY426",
                   "response_error_message": "Encryption required for this client"}


def test_secrets_manager_outage_fails_closed(aws, monkeypatch):
    from botocore.exceptions import ClientError

    class Down:
        def get_secret_value(self, **kw):
            raise ClientError({"Error": {"Code": "ThrottlingException"}}, "GetSecretValue")
    monkeypatch.setitem(pc._clients, "secretsmanager", Down())
    out = proxy_handler(http_api_event("ACME", seal(aws, "ACME", {})), None)
    assert err(out) == (500, "CRY500")


def test_sealing_failure_never_returns_plaintext(aws, monkeypatch):
    monkeypatch.setattr(pc, "seal_reply", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    out = proxy_handler(http_api_event("ACME", seal(aws, "ACME", {"name": "secret-name"})), None)
    assert err(out) == (500, "CRY500") and "secret-name" not in out["body"]
