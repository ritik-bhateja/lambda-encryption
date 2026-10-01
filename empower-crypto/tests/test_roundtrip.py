"""
Unit tests for the crypto layer. No network needed.

    pytest tests/ -v

Request:  request_value = label.iv.ciphertext.tag, encrypted directly.
Response: response_key + response_value envelope, unchanged from v2.0.
"""

import base64
import json
import os
import sys
import time

import pytest
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "layer", "python"))

SEED_SECRET = "test-payload-seed"
NONCE_TABLE = "test-nonce"
PATH, METHOD, CLIENT = "/employee", "POST", "MERCH_A"


@pytest.fixture(autouse=True)
def ec(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("PAYLOAD_SEED_SECRET_ID", SEED_SECRET)
    monkeypatch.setenv("PAYLOAD_NONCE_TABLE", NONCE_TABLE)

    with mock_aws():
        import boto3
        boto3.client("secretsmanager").create_secret(
            Name=SEED_SECRET,
            SecretString=json.dumps({"seed_b64": base64.b64encode(b"x" * 32).decode()}),
        )
        boto3.client("dynamodb").create_table(
            TableName=NONCE_TABLE,
            KeySchema=[{"AttributeName": "nonce_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "nonce_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        import empower_crypto as module
        module._seed_cache.update(value=None, expires_at=0)
        module._key_cache.clear()
        module._sm = boto3.client("secretsmanager")
        module._ddb = boto3.client("dynamodb")
        yield module


def _keys(ec, client=CLIENT, version=1, epoch_offset=0):
    epoch = ec.epoch_id_for(time.time(), 86400) + epoch_offset
    return ec.derive_keys(client, version, epoch)       # (kid, request_key, kek_response)


def _seal(ec, obj=None, client=CLIENT, path=PATH, key=None, kid=None, **kw):
    k_id, req_key, _ = _keys(ec, client=kw.pop("key_client", client), **kw)
    return ec.seal_request(obj or {"a": 1}, key or req_key, kid or k_id, client, path, METHOD)


def _open(ec, value, client=CLIENT, version=1, path=PATH, **kw):
    return ec.open_request(value, client, version, 86400, path, METHOD, **kw)


def _edit_label(ec, value, **changes):
    parts = value.split(".")
    label = json.loads(ec.b64u_decode(parts[0]))
    label.update(changes)
    parts[0] = ec.b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
    return ".".join(parts)


# --- request: happy path and format --------------------------------------

def test_request_round_trip(ec):
    value = _seal(ec, {"employee_code": "EMP001"})
    assert _open(ec, value) == {"employee_code": "EMP001"}


def test_request_value_has_four_parts_and_readable_label(ec):
    value = _seal(ec)
    parts = value.split(".")
    assert len(parts) == 4
    label = json.loads(ec.b64u_decode(parts[0]))
    assert {"v", "alg", "kid", "cid", "pth", "mtd", "iat", "jti"} == set(label)
    assert label["alg"] == "A256GCM"
    assert len(ec.b64u_decode(parts[1])) == 12     # iv
    assert len(ec.b64u_decode(parts[3])) == 16     # tag


def test_every_request_gets_a_fresh_iv_and_jti(ec):
    a, b = _seal(ec).split("."), _seal(ec).split(".")
    assert a[1] != b[1]
    assert json.loads(ec.b64u_decode(a[0]))["jti"] != json.loads(ec.b64u_decode(b[0]))["jti"]


# --- request: one time use and the glue -------------------------------------

def test_request_value_is_one_time_use(ec):
    value = _seal(ec)
    _open(ec, value)
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, value)
    assert exc.value.code == "CRY409"


def test_label_spliced_onto_other_data_rejected(ec):
    a = _seal(ec, {"code": "A"}).split(".")
    b = _seal(ec, {"code": "B"}).split(".")
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, ".".join([a[0], b[1], b[2], b[3]]))
    assert exc.value.code == "CRY422"


def test_editing_the_label_breaks_the_seal(ec):
    value = _seal(ec)
    iat = json.loads(ec.b64u_decode(value.split(".")[0]))["iat"]
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, _edit_label(ec, value, iat=iat - 1))
    assert exc.value.code == "CRY422"


def test_tampered_ciphertext(ec):
    parts = _seal(ec).split(".")
    parts[2] = parts[2][:-2] + ("AA" if not parts[2].endswith("AA") else "BB")
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, ".".join(parts))
    assert exc.value.code == "CRY422"


def test_tampered_tag(ec):
    parts = _seal(ec).split(".")
    parts[3] = ec.b64u(b"\x00" * 16)
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, ".".join(parts))
    assert exc.value.code == "CRY422"


# --- request: keys ------------------------------------------------------------

def test_wrong_key_rejected(ec):
    _, _, kek_response = _keys(ec)
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, _seal(ec, key=kek_response))
    assert exc.value.code == "CRY422"


def test_another_vendors_key_rejected(ec):
    _, other_key, _ = _keys(ec, client="MERCH_B")
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, _seal(ec, key=other_key))
    assert exc.value.code == "CRY422"


def test_key_version_bump_revokes(ec):
    value = _seal(ec, version=1)
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, value, version=2)
    assert exc.value.code == "CRY410"


def test_old_epoch_key_rejected(ec):
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, _seal(ec, epoch_offset=-5))
    assert exc.value.code == "CRY410"


def test_clients_get_different_keys(ec):
    assert _keys(ec, client="MERCH_A")[1] != _keys(ec, client="MERCH_B")[1]


# --- request: binding and shape ----------------------------------------------

def test_endpoint_binding(ec):
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, _seal(ec, path="/policy"))
    assert exc.value.code == "CRY412"


def test_client_binding(ec):
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, _seal(ec), client="MERCH_B")
    assert exc.value.code == "CRY412"


def test_skew_rejected(ec, monkeypatch):
    value = _seal(ec)
    future = time.time() + 3600
    monkeypatch.setattr(ec.time, "time", lambda: future)
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, value)
    assert exc.value.code == "CRY413"


@pytest.mark.parametrize("bad", ["", "a.b.c", "a.b.c.d.e", "!!!.x.y.z"])
def test_malformed_request_value(ec, bad):
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, bad)
    assert exc.value.code == "CRY400"


def test_wrong_alg_rejected(ec):
    with pytest.raises(ec.CryptoError) as exc:
        _open(ec, _edit_label(ec, _seal(ec), alg="A128GCM"))
    assert exc.value.code == "CRY401"


# --- response: unchanged envelope ---------------------------------------------

def test_response_envelope_round_trip(ec):
    kid, _, kek_response = _keys(ec)
    key, value = ec.seal({"response_data": {"x": 1}}, kek_response, kid, CLIENT, PATH, METHOD)
    assert ec.open_envelope(key, value, CLIENT, 1, 86400, PATH, METHOD, check_replay=False) == \
        {"response_data": {"x": 1}}


def test_response_uses_a_fresh_dek_every_time(ec):
    kid, _, kek_response = _keys(ec)
    k1, _ = ec.seal({"a": 1}, kek_response, kid, CLIENT, PATH, METHOD)
    k2, _ = ec.seal({"a": 1}, kek_response, kid, CLIENT, PATH, METHOD)
    assert json.loads(ec.b64u_decode(k1))["edek"] != json.loads(ec.b64u_decode(k2))["edek"]


def test_response_key_is_glued_to_response_value(ec):
    kid, _, kek_response = _keys(ec)
    k1, _ = ec.seal({"a": 1}, kek_response, kid, CLIENT, PATH, METHOD)
    _, v2 = ec.seal({"a": 2}, kek_response, kid, CLIENT, PATH, METHOD)
    with pytest.raises(ec.CryptoError) as exc:
        ec.open_envelope(k1, v2, CLIENT, 1, 86400, PATH, METHOD, check_replay=False)
    assert exc.value.code == "CRY422"


def test_response_compression_shrinks_a_relay_page(ec):
    kid, _, kek_response = _keys(ec)
    page = {"records": [{"claim_id": f"CLM{i:06d}", "status": "SETTLED", "policy_no": "POL123456",
                         "currency": "INR", "amount": 15000 + i} for i in range(500)]}
    key, value = ec.seal(page, kek_response, kid, CLIENT, "/claims", METHOD)
    assert len(key) + len(value) < len(json.dumps(page))
    assert ec.open_envelope(key, value, CLIENT, 1, 86400, "/claims", METHOD, check_replay=False) == page


def test_request_key_cannot_open_responses(ec):
    kid, request_key, kek_response = _keys(ec)
    key, value = ec.seal({"a": 1}, kek_response, kid, CLIENT, PATH, METHOD)
    with pytest.raises(ec.CryptoError):
        ec.open_envelope(key, value, CLIENT, 1, 86400, PATH, METHOD,
                         kek_direction="req", check_replay=False)


def test_missing_context_does_not_mean_off(ec, monkeypatch):
    monkeypatch.setenv("CRYPTO_DEFAULT_MODE", "required")
    assert ec.read_crypto_profile({})["mode"] == "required"
