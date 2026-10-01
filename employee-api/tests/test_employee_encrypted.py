"""The prod employee_api handler, converted with @secure_api: real handler code, stubbed edges.

Stubbed: Hasura (requests.post), the Hasura secret (lambda_cache), the token helpers
(src.get_auth_role_by_token, jwt.decode) and the logging Lambda (lam.invoke).
Mocked with moto: the vendor key in Secrets Manager and the nonce table in DynamoDB.
"""

import importlib
import json
import os
import sys
import types

import boto3
import pytest
from moto import mock_aws

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.dirname(HERE)
sys.path[:0] = [HERE, os.path.join(LAB, "payload-crypto", "layer", "python"),
                os.path.join(LAB, "payload-crypto", "vendor")]

import payload_crypto as pc  # noqa: E402
import vendor_client as vc  # noqa: E402

EMPLOYEE = {"employee_code": "E1001", "employee_full_name": "Asha Menon", "department": "Claims"}


def install_stubs():
    """Modules the prod Lambda imports that are not part of this change."""
    lc = types.ModuleType("lambda_cache")

    class _SM:
        @staticmethod
        def cache(name, max_age_in_seconds):
            def deco(fn):
                def inner(event, context):
                    setattr(context, name, str({"API_ENGINE_SECRET_KEY": "hasura-admin", "API_ENGINE_ENDPOINT": "https://hasura.test/v1/graphql"}))
                    return fn(event, context)
                return inner
            return deco
    lc.secrets_manager = _SM()
    sys.modules["lambda_cache"] = lc

    jwt = types.ModuleType("jwt")
    jwt.decode = lambda token, **kw: {"client_id": "cognito-client-acme"}
    sys.modules["jwt"] = jwt

    from src.restructure import restructure_employee_response
    src = types.ModuleType("src")
    src.employee_by_employeecode = lambda code: {"query": "employee", "variables": {"code": code}}
    src.get_auth_role_by_token = lambda event: ("vendor_role", "")
    src.restructure_employee_response = restructure_employee_response
    sys.modules["src"] = src


class Ctx:
    """Lambda context: lambda_cache sets the secret as an attribute on it."""


@pytest.fixture
def api(monkeypatch):
    with mock_aws():
        os.environ.update(AWS_DEFAULT_REGION="ap-south-1", PAYLOAD_NONCE_TABLE="nonce",
                          PAYLOAD_KEY_SECRET_TEMPLATE="payload-keys/{vendor}")
        pc._clients.clear(); pc.clear_key_cache()
        key = os.urandom(32)
        boto3.client("secretsmanager").create_secret(
            Name="payload-keys/ACME", SecretString=json.dumps({"key_id": "ACME-v1", "key_hex": key.hex()}))
        boto3.client("dynamodb").create_table(
            TableName="nonce", BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "nonce_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "nonce_id", "KeyType": "HASH"}])

        install_stubs()
        sys.modules.pop("lambda_function", None)
        lf = importlib.import_module("lambda_function")

        hasura = {"calls": [], "reply": {"data": {"employee_information_master": [EMPLOYEE]}}}

        class Resp:
            status_code = 200
            def json(self):
                return hasura["reply"]
        monkeypatch.setattr(lf.requests, "post", lambda url, headers, json: hasura["calls"].append(json) or Resp())

        logged = []

        class Lam:
            def invoke(self, **kw):
                logged.append(json.loads(kw["Payload"]))
        monkeypatch.setattr(lf, "lam", Lam())
        yield lf, key, hasura, logged


def event(body, vendor="ACME"):
    """What the existing mapping template sends to the Lambda."""
    headers = {"Authorization": "Bearer eyJ.test.token", "Content-Type": "application/json"}
    if vendor:
        headers["X-Vendor-Id"] = vendor
    return {"body-json": body, "params": {"path": {}, "querystring": {}, "header": headers},
            "context": {"request-id": "req-123", "resource-path": "/employee", "stage": "prod",
                        "http-method": "POST", "source-ip": "10.0.0.1"}}


def sealed(key, payload):
    return vc.seal_request(payload, key, "ACME", "/employee", "POST")


def http_status(out):
    """The existing API Gateway response template: status = response_code when present and not 200."""
    return out["response_code"] if out.get("response_code") not in (None, 200) else 200


def opened(out, key):
    assert set(out) == {"response_code", "response_key", "response_value"}
    return vc.open_reply(out["response_key"], out["response_value"], key, "ACME")


def test_employee_found(api):
    lf, key, hasura, _ = api
    out = lf.lambda_handler(event(sealed(key, {"employee_code": " e1001 "})), Ctx())
    assert http_status(out) == 200 and "Asha" not in json.dumps(out)
    body = opened(out, key)
    assert body["response_code"] == 200 and body["request_id"] == "req-123"
    assert body["response_data"]["employee_information_master"] == EMPLOYEE
    assert hasura["calls"][0]["variables"]["code"] == "E1001"      # handler saw the decrypted, stripped code


def test_employee_not_found_is_200_emp404(api):
    lf, key, hasura, _ = api
    hasura["reply"] = {"data": {"employee_information_master": []}}
    out = lf.lambda_handler(event(sealed(key, {"employee_code": "E9"})), Ctx())
    assert http_status(out) == 200
    body = opened(out, key)
    assert (body["response_error_code"], body["response_error_message"]) == ("EMP404", "Employee is not available")


def test_missing_employee_code_is_400_and_still_sealed(api):
    lf, key, hasura, _ = api
    out = lf.lambda_handler(event(sealed(key, {"employee_code": ""})), Ctx())
    assert http_status(out) == 400
    assert opened(out, key)["response_message"].startswith("Functional error")
    assert hasura["calls"] == []


def test_hasura_error_is_500_and_still_sealed(api):
    lf, key, hasura, _ = api
    hasura["reply"] = {"errors": [{"message": "boom"}]}
    out = lf.lambda_handler(event(sealed(key, {"employee_code": "E1"})), Ctx())
    assert http_status(out) == 500 and opened(out, key)["response_message"] == "Something went wrong"


@pytest.mark.parametrize("body,vendor,code", [
    ({"employee_code": "E1001"}, "ACME", "CRY426"),     # plain JSON from an encrypted vendor
    (None, None, "CRY400"),                              # no X-Vendor-Id header
    (None, "NOPE", "CRY410"),                            # unknown vendor
])
def test_crypto_rejections_never_reach_business_code(api, body, vendor, code):
    lf, key, hasura, logged = api
    body = body if body is not None else sealed(key, {"employee_code": "E1001"})
    out = lf.lambda_handler(event(body, vendor), Ctx())
    assert out["response_code"] == 400 and out["response_error_code"] == code
    assert http_status(out) == 400
    assert hasura["calls"] == [] and logged == []


def test_replay_is_refused(api):
    lf, key, _, _ = api
    body = sealed(key, {"employee_code": "E1001"})
    assert http_status(lf.lambda_handler(event(body), Ctx())) == 200
    out = lf.lambda_handler(event(body), Ctx())
    assert out["response_error_code"] == "CRY409"


def test_api_logging_lambda_receives_plaintext(api):
    """Unchanged behaviour, called out on purpose: log_data runs inside the handler,
    so the logging Lambda gets the decrypted request and the unencrypted output."""
    lf, key, _, logged = api
    lf.lambda_handler(event(sealed(key, {"employee_code": "E1001"})), Ctx())
    assert logged[0]["request_body"] == {"employee_code": "E1001"}
    assert logged[0]["response_body"]["response_data"]["employee_information_master"]["employee_full_name"] == "Asha Menon"
