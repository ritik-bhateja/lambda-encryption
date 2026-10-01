"""
Local API Gateway emulator for the Empower Care crypto example.

Runs the REAL Lambda code. Nothing here is a reimplementation: it builds the
same event shape the VTL mapping template produces, calls the real authorizer,
then calls the real business handler.

What it fakes, so the project runs on a laptop with no AWS account:
  - Secrets Manager and DynamoDB, via moto in process
  - the ANZ auth service, at /mock-anz/*
  - Hasura, at /mock-hasura/v1/graphql

    python local_gateway.py          then point Postman at http://localhost:8080

DO NOT deploy this file. It is a test harness.
"""

import base64
import json
import os
import secrets
import time
import uuid

from flask import Flask, jsonify, request
from moto import mock_aws

# --------------------------------------------------------------------------
# moto has to be running before any handler module creates a boto3 client
# --------------------------------------------------------------------------
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-south-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")

_mock = mock_aws()
_mock.start()

import boto3  # noqa: E402

PORT = int(os.environ.get("PORT", "8080"))
BASE = os.environ.get("PUBLIC_BASE_URL", f"http://localhost:{PORT}")

KEYROLE_TABLE = "empower_care_prod_dydb_keyrolemapping"
TOKEN_LIMIT_TABLE = "empower_care_prod_valid_token_limit"
NONCE_TABLE = "empower_care_prod_dydb_payload_nonce"
KEY_ISSUE_TABLE = "empower_care_prod_key_issue_count"
SEED_SECRET = "empower-care-prod-secret-payload-seed-v1"
ENGINE_SECRET = "empower-care-prod-secret-api-engine-config-v1"

os.environ.update({
    "KEYROLE_TABLE": KEYROLE_TABLE,
    "TOKEN_LIMIT_TABLE": TOKEN_LIMIT_TABLE,
    "PAYLOAD_NONCE_TABLE": NONCE_TABLE,
    "KEY_ISSUE_TABLE": KEY_ISSUE_TABLE,
    "PAYLOAD_SEED_SECRET_ID": SEED_SECRET,
    "API_ENGINE_SECRET_ID": ENGINE_SECRET,
    "ANZ_VALIDATE_URL": f"{BASE}/mock-anz/tokenvalidate",
    "ANZ_INVALIDATE_URL": f"{BASE}/mock-anz/invalidatetoken",
    "CRYPTO_DEFAULT_MODE": "required",
    "CLIENT_KEY_HASH": "sha256",
    "MAX_ISSUES_PER_EPOCH": "50",
})

# --------------------------------------------------------------------------
# Seed the fake AWS account
# --------------------------------------------------------------------------

ddb = boto3.client("dynamodb")
sm = boto3.client("secretsmanager")

CLIENTS = {
    # merchant_id      crypto_mode   epoch_seconds
    "MERCH_ENCRYPTED": ("required", 86400),
    "MERCH_OPTIONAL": ("optional", 86400),
    "MERCH_PLAIN": ("off", 86400),
    "MERCH_HOURLY": ("required", 3600),
}


def _client_key(value):
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()


def bootstrap():
    ddb.create_table(
        TableName=KEYROLE_TABLE,
        KeySchema=[{"AttributeName": "client_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "client_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.create_table(
        TableName=TOKEN_LIMIT_TABLE,
        KeySchema=[{"AttributeName": "token", "KeyType": "HASH"},
                   {"AttributeName": "client_id", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "token", "AttributeType": "S"},
                              {"AttributeName": "client_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.create_table(
        TableName=NONCE_TABLE,
        KeySchema=[{"AttributeName": "nonce_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "nonce_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ddb.create_table(
        TableName=KEY_ISSUE_TABLE,
        KeySchema=[{"AttributeName": "client_ref", "KeyType": "HASH"},
                   {"AttributeName": "epoch_id", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "client_ref", "AttributeType": "S"},
                              {"AttributeName": "epoch_id", "AttributeType": "N"}],
        BillingMode="PAY_PER_REQUEST",
    )

    for merchant, (mode, epoch_seconds) in CLIENTS.items():
        ddb.put_item(TableName=KEYROLE_TABLE, Item={
            "client_id": {"S": _client_key(merchant)},
            "role_id": {"S": "empower_role_freshdesk_inherited"},
            "allowed_ids": {"S": ""},
            "limit": {"N": "100000"},
            "source_ips": {"S": ""},
            "crypto_mode": {"S": mode},
            "key_version": {"N": "1"},
            "epoch_seconds": {"N": str(epoch_seconds)},
        })

    sm.create_secret(
        Name=SEED_SECRET,
        SecretString=json.dumps({
            # 32 random bytes. In production this is generated once and never logged.
            "seed_b64": base64.b64encode(secrets.token_bytes(32)).decode()
        }),
    )
    sm.create_secret(
        Name=ENGINE_SECRET,
        SecretString=json.dumps({
            "API_ENGINE_SECRET_KEY": "local-dev-admin-secret",
            "API_ENGINE_ENDPOINT": f"{BASE}/mock-hasura/v1/graphql",
        }),
    )


bootstrap()

# --------------------------------------------------------------------------
# Now the real handlers can be imported
# --------------------------------------------------------------------------
import sys  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "layer", "python"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lambdas", "cryptokeys"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lambdas", "employee_api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lambdas", "request_validator"))

import importlib.util  # noqa: E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_here = os.path.dirname(os.path.abspath(__file__))
validator = _load("rv_handler", os.path.join(_here, "lambdas/request_validator/handler.py"))
cryptokeys = _load("ck_handler", os.path.join(_here, "lambdas/cryptokeys/handler.py"))
employee = _load("emp_handler", os.path.join(_here, "lambdas/employee_api/handler.py"))

app = Flask(__name__)
STAGE = "prod"

EMPLOYEES = {
    "EMP001": {"employee_id": "EMP001", "employee_full_name": "Asha Menon",
               "status": "ACTIVE", "employee_mail_id": "asha.menon@example.invalid"},
    "EMP002": {"employee_id": "EMP002", "employee_full_name": "Rohit Nair",
               "status": "INACTIVE", "employee_mail_id": "rohit.nair@example.invalid"},
}


# --------------------------------------------------------------------------
# Mock ANZ auth service
# --------------------------------------------------------------------------

@app.post("/mock-anz/api/merchants/get_token")
def anz_get_token():
    body = request.get_json(silent=True) or {}
    merchant = body.get("key") or body.get("client_id") or "MERCH_ENCRYPTED"
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64u(json.dumps({
        "merchant_id": merchant,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }).encode())
    return jsonify({
        "status": True,
        "access_token": f"{header}.{payload}.localdevsignature",
        "expires_in": 3600,
        "token_type": "Bearer",
    })


@app.post("/mock-anz/tokenvalidate")
def anz_validate():
    auth = request.headers.get("Authorization", "")
    return jsonify({"status": bool(auth)}), (200 if auth else 401)


@app.post("/mock-anz/invalidatetoken")
def anz_invalidate():
    return jsonify({"status": True})


# --------------------------------------------------------------------------
# Mock Hasura
# --------------------------------------------------------------------------

@app.post("/mock-hasura/v1/graphql")
def hasura():
    if request.headers.get("x-hasura-admin-secret") != "local-dev-admin-secret":
        return jsonify({"errors": [{"message": "invalid admin secret"}]}), 200
    if not request.headers.get("X-Hasura-Role"):
        return jsonify({"errors": [{"message": "role header missing"}]}), 200

    code = ((request.get_json(silent=True) or {}).get("variables") or {}).get("_employee_code")
    row = EMPLOYEES.get(code)
    return jsonify({"data": {"employee_information_master": [row] if row else []}})


# --------------------------------------------------------------------------
# The emulated API Gateway
# --------------------------------------------------------------------------

def _authorize(resource_path):
    """Run the real Lambda authorizer and return its context, or an error."""
    event = {
        "type": "REQUEST",
        "methodArn": f"arn:aws:execute-api:ap-south-1:000000000000:local/{STAGE}/POST{resource_path}",
        "headers": dict(request.headers),
        "requestContext": {
            "resourcePath": resource_path,
            "httpMethod": "POST",
            "identity": {"sourceIp": request.remote_addr or "127.0.0.1"},
        },
    }
    try:
        policy = validator.lambda_handler(event, None)
    except Exception as exc:
        if "Unauthorized" in str(exc):
            return None, (jsonify({"message": "Unauthorized"}), 401)
        raise
    effect = policy["policyDocument"]["Statement"][0]["Effect"]
    if effect != "Allow":
        return None, (jsonify({"message": "User is not authorized to access this resource"}), 403)
    return policy.get("context", {}), None


def _build_event(auth_context, resource_path):
    """Exactly what infra/mapping_template.vtl produces."""
    return {
        "body-json": request.get_json(silent=True) or {},
        "params": {
            "header": dict(request.headers),
            "querystring": dict(request.args),
            "path": {},
        },
        "context": {
            "request-id": str(uuid.uuid4()),
            "resource-path": resource_path,
            "stage": STAGE,
            "http-method": "POST",
            "source-ip": request.remote_addr or "127.0.0.1",
            # existing
            "x-Hasura-Role": auth_context.get("role_id", ""),
            "X-Hasura-User-Id": auth_context.get("allowed_ids", ""),
            # new
            "client-ref": auth_context.get("client_ref", ""),
            "crypto-mode": auth_context.get("crypto_mode", "off"),
            "key-version": auth_context.get("key_version", "1"),
            "epoch-seconds": auth_context.get("epoch_seconds", "86400"),
            "source-ips": auth_context.get("source_ips", ""),
        },
    }


def _invoke(handler, resource_path):
    auth_context, error = _authorize(resource_path)
    if error:
        return error
    result = handler(_build_event(auth_context, resource_path), None)
    return jsonify(result), int(result.get("response_code", 200))


@app.post(f"/{STAGE}/crypto/session-key")
def session_key():
    return _invoke(cryptokeys.lambda_handler, "/crypto/session-key")


@app.post(f"/{STAGE}/employee")
def employee_api():
    return _invoke(employee.lambda_handler, "/employee")


# --------------------------------------------------------------------------
# Dev only crypto helpers, so Postman can build and read a ciphertext
#
# Postman cannot do AES-GCM key wrapping: its sandbox ships crypto-js, which
# has no GCM mode. So the sandbox exposes seal and open, and the Postman
# pre-request scripts call them. A real partner uses a JOSE library instead.
#
# NEVER deploy these routes. They exist only in local_gateway.py.
# --------------------------------------------------------------------------

def _keks_for_token(token):
    import empower_crypto as ec
    segment = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    merchant = claims.get("merchant_id") or claims.get("client_id")
    epoch_seconds = CLIENTS.get(merchant, ("required", 86400))[1]
    epoch_id = ec.epoch_id_for(time.time(), epoch_seconds)
    kek_id, kek_req, kek_res = ec.derive_keys(merchant, 1, epoch_id)
    return merchant, kek_id, kek_req, kek_res


@app.post("/dev/seal")
def dev_seal():
    """Plays the VENDOR: builds a request_value for Postman."""
    import empower_crypto as ec
    body = request.get_json(silent=True) or {}
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    merchant, kid, request_key, _ = _keks_for_token(token)
    request_value = ec.seal_request(
        body.get("payload", {}), request_key, kid, merchant,
        body.get("path", "/employee"), body.get("method", "POST"),
    )
    return jsonify({"request_value": request_value, "kid": kid, "client_ref": merchant})


@app.post("/dev/open")
def dev_open():
    """Plays the VENDOR: opens a response's response_key + response_value."""
    import empower_crypto as ec
    body = request.get_json(silent=True) or {}
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    merchant, _, _, kek_res = _keks_for_token(token)
    key_obj = ec.read_key(body["response_key"])
    opened = ec.open_envelope(
        body["response_key"], body["response_value"],
        client_ref=merchant, key_version=1,
        epoch_seconds=CLIENTS.get(merchant, ("required", 86400))[1],
        path=key_obj["pth"], method=key_obj["mtd"],
        kek_direction="res", check_replay=False,
    )
    return jsonify(opened)


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "clients": {m: c[0] for m, c in CLIENTS.items()},
        "endpoints": [
            f"POST /{STAGE}/crypto/session-key",
            f"POST /{STAGE}/employee",
            "POST /mock-anz/api/merchants/get_token",
        ],
    })


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


if __name__ == "__main__":
    print(f"Empower Care crypto sandbox on {BASE}")
    print(f"  token     POST {BASE}/mock-anz/api/merchants/get_token")
    print(f"  key       POST {BASE}/{STAGE}/crypto/session-key")
    print(f"  employee  POST {BASE}/{STAGE}/employee")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
