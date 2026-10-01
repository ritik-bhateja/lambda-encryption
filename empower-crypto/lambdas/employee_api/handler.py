"""
empower_care_prod_employee_api

The representative business Lambda, with payload encryption added.

The ONLY change from the current production handler is the one decorator line.
Everything below it works on plain dicts exactly as it does today: it never
imports a crypto library, never sees a key, and never knows whether the caller
encrypted anything.

Environment variables
---------------------
API_ENGINE_SECRET_ID     Secrets Manager id holding the Hasura config
LOGGING_FUNCTION_NAME    empower_care_prod_lambda_apilogging
PAYLOAD_SEED_SECRET_ID   read by the layer
PAYLOAD_NONCE_TABLE      read by the layer
CRYPTO_DEFAULT_MODE      "required" on this function, it is Gateway facing
"""

import json
import logging
import os
import time

import boto3
import urllib3

from empower_crypto import build_envelope, secure_payload

log = logging.getLogger()
log.setLevel(logging.INFO)

_sm = boto3.client("secretsmanager")
_lambda = boto3.client("lambda")
_http = urllib3.PoolManager()

_config_cache = {"value": None, "expires_at": 0.0}

EMPLOYEE_QUERY = """
query EmployeeByCode($_employee_code: String) {
  employee_information_master(where: {employee_id: {_eq: $_employee_code}}) {
    employee_id
    employee_full_name
    status
    employee_mail_id
  }
}
"""


def _hasura_config():
    """Same 300 second cache pattern the API engine already uses."""
    now = time.time()
    if _config_cache["value"] and now < _config_cache["expires_at"]:
        return _config_cache["value"]

    raw = _sm.get_secret_value(SecretId=os.environ["API_ENGINE_SECRET_ID"])["SecretString"]
    config = json.loads(raw)
    _config_cache["value"] = config
    _config_cache["expires_at"] = now + 300
    return config


def get_auth_role_by_token(event):
    """Unchanged. Reads the role API Gateway injected. Does not inspect the token."""
    ctx = event.get("context") or {}
    return ctx.get("x-Hasura-Role"), ctx.get("X-Hasura-User-Id")


def prepare_header(config, role, allowed_ids):
    headers = {
        "x-hasura-admin-secret": config["API_ENGINE_SECRET_KEY"],
        "Content-Type": "application/json",
        "X-Hasura-Role": role,
    }
    if allowed_ids:
        headers["X-Hasura-User-Id"] = allowed_ids
    return headers


def restructure(raw):
    """Flatten the Hasura result into the external contract."""
    rows = (raw.get("data") or {}).get("employee_information_master") or []
    if not rows:
        return None
    return {"employee_information_master": rows[0]}


# ---------------------------------------------------------------------------
# THE ONLY LINE THAT CHANGES
# ---------------------------------------------------------------------------
@secure_payload(api_name="employee")
def lambda_handler(event, context):
    started_at = time.perf_counter()
    ctx = event.get("context") or {}
    request_id = ctx.get("request-id", "unknown")

    # body-json has already been decrypted by the layer. Same shape as today.
    body = event.get("body-json") or {}
    employee_code = (body.get("employee_code") or "").strip().upper()

    if not employee_code:
        envelope = build_envelope(
            request_id, response_code=400, error_code="EMP400",
            error_message="employee_code is mandatory",
            message="Request rejected", started_at=started_at,
        )
        envelope["response_data"] = {}
        return envelope

    role, allowed_ids = get_auth_role_by_token(event)
    if not role:
        # Fail closed. A request without a role must never reach Hasura.
        envelope = build_envelope(
            request_id, response_code=403, error_code="EMP403",
            error_message="Authorization role missing",
            message="Request rejected", started_at=started_at,
        )
        envelope["response_data"] = {}
        return envelope

    config = _hasura_config()
    try:
        response = _http.request(
            "POST",
            config["API_ENGINE_ENDPOINT"],
            body=json.dumps({
                "query": EMPLOYEE_QUERY,
                "variables": {"_employee_code": employee_code},
            }).encode(),
            headers=prepare_header(config, role, allowed_ids),
            timeout=urllib3.Timeout(connect=2.0, read=8.0),   # explicit timeouts
            retries=False,
        )
        raw = json.loads(response.data)
    except Exception as exc:
        log.error("hasura call failed for %s: %s", request_id, exc)
        envelope = build_envelope(
            request_id, response_code=500, error_code="EMP500",
            error_message="Upstream data service unavailable",
            message="Request failed", started_at=started_at,
        )
        envelope["response_data"] = {}
        return envelope

    if "errors" in raw:
        # Never surface Hasura text to an external consumer.
        log.error("hasura errors for %s: %s", request_id, raw["errors"])
        envelope = build_envelope(
            request_id, response_code=500, error_code="EMP500",
            error_message="Query could not be completed",
            message="Request failed", started_at=started_at,
        )
        envelope["response_data"] = {}
        return envelope

    record = restructure(raw)
    if record is None:
        envelope = build_envelope(
            request_id, response_code=200, error_code="EMP404",
            error_message="Employee is not available",
            message="Request Successfully processed", started_at=started_at,
        )
        envelope["response_data"] = {}
    else:
        envelope = build_envelope(request_id, started_at=started_at)
        envelope["response_data"] = record

    _audit(event, body, envelope)
    return envelope


def _audit(event, request_body, envelope):
    """Async audit. Store request_value exactly as received plus its kid. Never
    write a plaintext body to S3. request_value is useless without that day's
    request encryption key, so the audit object is safe
    at rest.
    """
    ctx = event.get("context") or {}
    function_name = os.environ.get("LOGGING_FUNCTION_NAME")
    if not function_name:
        return

    original = event.get("_original_body") or {}
    payload = {
        "request_id": ctx.get("request-id"),
        "api_name": "employee",
        "api_endpoint": ctx.get("resource-path"),
        "stage": ctx.get("stage"),
        "method": ctx.get("http-method"),
        "client_ref": ctx.get("client-ref"),
        # kid is what lets an authorised support role decrypt this later
        "kid": original.get("kid"),
        # the envelope as received when the caller encrypted, otherwise masked
        "request_value": original.get("request_value") or _mask(request_body),
        "response_code": envelope.get("response_code"),
        "response_error_code": envelope.get("response_error_code"),
    }
    try:
        _lambda.invoke(
            FunctionName=function_name,
            InvocationType="Event",
            Payload=json.dumps(payload).encode(),
        )
    except Exception as exc:
        log.warning("audit invoke failed: %s", exc)


def _mask(body):
    return {k: "***" for k in body} if isinstance(body, dict) else "***"
