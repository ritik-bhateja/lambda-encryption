"""
Request validator tests: sample-token mode and the ANZ fail-closed rule.

    pytest tests/ -v
"""

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import time

import pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "s" * 48
ARN = "arn:aws:execute-api:ap-south-1:111122223333:abc123/sample/POST/employee"


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_token(merchant="MERCH_ENCRYPTED", secret=SECRET, alg="HS256", exp_in=3600):
    header = b64u(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = b64u(json.dumps({"merchant_id": merchant, "iat": int(time.time()),
                               "exp": int(time.time()) + exp_in}).encode())
    sig = b64u(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def event(token, path="/employee"):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return {"type": "REQUEST", "methodArn": ARN, "headers": headers,
            "requestContext": {"resourcePath": path, "httpMethod": "POST",
                               "identity": {"sourceIp": "203.0.113.10"}}}


@pytest.fixture
def validator(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("KEYROLE_TABLE", "keyrole")
    monkeypatch.setenv("TOKEN_LIMIT_TABLE", "tokenlimit")
    monkeypatch.setenv("AUTH_MODE", "sample")
    monkeypatch.setenv("SAMPLE_TOKEN_SECRET_ID", "sample-token")
    monkeypatch.delenv("ANZ_VALIDATE_URL", raising=False)

    with mock_aws():
        import boto3
        ddb = boto3.client("dynamodb")
        ddb.create_table(TableName="keyrole",
                         KeySchema=[{"AttributeName": "client_id", "KeyType": "HASH"}],
                         AttributeDefinitions=[{"AttributeName": "client_id", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.create_table(TableName="tokenlimit",
                         KeySchema=[{"AttributeName": "token", "KeyType": "HASH"},
                                    {"AttributeName": "client_id", "KeyType": "RANGE"}],
                         AttributeDefinitions=[{"AttributeName": "token", "AttributeType": "S"},
                                               {"AttributeName": "client_id", "AttributeType": "S"}],
                         BillingMode="PAY_PER_REQUEST")
        ddb.put_item(TableName="keyrole", Item={
            "client_id": {"S": hashlib.sha256(b"MERCH_ENCRYPTED").hexdigest()},
            "role_id": {"S": "sample_role"}, "allowed_ids": {"S": ""},
            "limit": {"N": "1000"}, "source_ips": {"S": ""},
            "crypto_mode": {"S": "required"}, "key_version": {"N": "1"},
            "epoch_seconds": {"N": "86400"},
        })
        boto3.client("secretsmanager").create_secret(Name="sample-token",
                                                     SecretString=json.dumps({"secret": SECRET}))

        spec = importlib.util.spec_from_file_location(
            "rv_under_test", os.path.join(ROOT, "lambdas", "request_validator", "handler.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module


def effect(result):
    return result["policyDocument"]["Statement"][0]["Effect"]


def test_valid_sample_token_allows_with_crypto_context(validator):
    result = validator.lambda_handler(event(make_token()), None)
    assert effect(result) == "Allow"
    assert result["policyDocument"]["Statement"][0]["Resource"] == [ARN]
    ctx = result["context"]
    assert ctx["client_ref"] == "MERCH_ENCRYPTED"
    assert ctx["crypto_mode"] == "required"
    assert ctx["key_version"] == "1" and ctx["epoch_seconds"] == "86400"
    assert all(isinstance(v, str) for v in ctx.values())   # API Gateway needs flat strings


def test_forged_signature_denied(validator):
    assert effect(validator.lambda_handler(event(make_token(secret="x" * 48)), None)) == "Deny"


def test_expired_token_denied(validator):
    assert effect(validator.lambda_handler(event(make_token(exp_in=-10)), None)) == "Deny"


def test_alg_none_denied(validator):
    header = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64u(json.dumps({"merchant_id": "MERCH_ENCRYPTED", "exp": int(time.time()) + 3600}).encode())
    assert effect(validator.lambda_handler(event(f"{header}.{payload}."), None)) == "Deny"


def test_signed_but_unknown_vendor_denied(validator):
    assert effect(validator.lambda_handler(event(make_token(merchant="MERCH_NOBODY")), None)) == "Deny"


def test_garbage_token_denied(validator):
    assert effect(validator.lambda_handler(event("not-a-jwt"), None)) == "Deny"


def test_missing_header_is_unauthorized(validator):
    with pytest.raises(Exception, match="Unauthorized"):
        validator.lambda_handler(event(None), None)


def test_anz_mode_without_url_fails_closed(validator, monkeypatch):
    """An unsigned token must never be trusted just because ANZ is not configured."""
    monkeypatch.setenv("AUTH_MODE", "anz")
    unsigned = (b64u(b'{"alg":"none"}') + "." +
                b64u(json.dumps({"merchant_id": "MERCH_ENCRYPTED"}).encode()) + ".")
    assert effect(validator.lambda_handler(event(unsigned), None)) == "Deny"


def test_crypto_path_uses_its_own_quota_bucket(validator):
    token = make_token()
    validator.lambda_handler(event(token, "/crypto/session-key"), None)
    validator.lambda_handler(event(token, "/employee"), None)
    import boto3
    keys = {i["token"]["S"].split("#")[0]
            for i in boto3.client("dynamodb").scan(TableName="tokenlimit")["Items"]}
    assert keys == {"crypto", "business"}
