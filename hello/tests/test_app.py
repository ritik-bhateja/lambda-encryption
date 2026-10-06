"""Hello on payload_crypto: the plain handler behind @secure_api, and the dev tool."""

import json
import os
import sys

import boto3
import pytest
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.dirname(ROOT)
sys.path[:0] = [os.path.join(ROOT, "src"), os.path.join(LAB, "payload-crypto", "vendor"),
                os.path.join(LAB, "payload-crypto", "layer", "python")]

import payload_crypto as pc  # noqa: E402


@pytest.fixture
def env():
    with mock_aws():
        os.environ.update(AWS_DEFAULT_REGION="ap-south-1", PAYLOAD_NONCE_TABLE="nonce",
                          PAYLOAD_KEY_SECRET_TEMPLATE="empower_care_lambda_encryption/{vendor}/response-key")
        pc._clients.clear()
        pc.clear_key_cache()
        key = os.urandom(32)
        # The deployed secret holds only key_hex; key_id defaults to <vendor>-v1.
        boto3.client("secretsmanager").create_secret(
            Name="empower_care_lambda_encryption/TEST_VENDOR_UAT/response-key", SecretString=json.dumps({"key_hex": key.hex()}))
        boto3.client("dynamodb").create_table(
            TableName="nonce", BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "nonce_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "nonce_id", "KeyType": "HASH"}])
        import app, dev_open, vendor_client
        yield app, dev_open, vendor_client, key


def _event(body, vendor="TEST_VENDOR_UAT"):
    return {"version": "2.0", "rawPath": "/hello", "headers": {"x-vendor-id": vendor},
            "requestContext": {"http": {"method": "POST"}, "stage": "$default"},
            "body": json.dumps(body)}


def test_round_trip_with_vendor_client(env):
    app, _, vc, key = env
    out = app.handler(_event(vc.seal_request({"name": "care"}, key, "TEST_VENDOR_UAT", "/hello")), None)
    assert out["statusCode"] == 200
    body = json.loads(out["body"])
    assert set(body) == {"response_key", "response_value"}
    got = vc.open_reply(body["response_key"], body["response_value"], key, "TEST_VENDOR_UAT")
    assert got["response_data"] == {"message": "hello care", "received": {"name": "care"}}


def test_plain_json_is_refused(env):
    app, *_ = env
    out = app.handler(_event({"name": "care"}), None)
    assert (out["statusCode"], json.loads(out["body"])["error"]) == (400, "CRY426")


def test_unknown_vendor_header(env):
    app, _, vc, key = env
    out = app.handler(_event(vc.seal_request({}, key, "TEST_VENDOR_UAT", "/hello"), vendor="OTHER"), None)
    assert json.loads(out["body"])["error"] == "CRY410"


def test_dev_tool_seals_and_opens(env):
    app, dev_open, *_ = env
    sealed = dev_open.handler({"op": "seal_request", "vendor": "TEST_VENDOR_UAT", "payload": {"name": "d"}}, None)
    assert sealed["ok"]
    out = app.handler(_event({"request_key": sealed["request_key"]}), None)
    opened = dev_open.handler({"op": "open_reply", "vendor": "TEST_VENDOR_UAT", **json.loads(out["body"])}, None)
    assert opened["reply"]["response_data"]["message"] == "hello d"
