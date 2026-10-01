"""
empower_care_<env>_sample_employee_api

A sample business Lambda for the AWS sample stack. Same request and response
contract as the Employee API, but the data comes from a small fixture instead
of Hasura, so the stack runs without a database.

The ONLY encryption-related line is the decorator. Everything below it works
on plain dicts: it never imports a crypto library and never sees a key.

    POST /employee
    { "request_value": "<label>.<iv>.<ciphertext>.<tag>" }

    body-json inside the handler, already decrypted:
    { "employee_code": "EMP001" }
"""

import json
import logging
import time

from empower_crypto import build_envelope, secure_payload

log = logging.getLogger()
log.setLevel(logging.INFO)

EMPLOYEES = {
    "EMP001": {"employee_id": "EMP001", "employee_full_name": "Asha Menon",
               "status": "ACTIVE", "employee_mail_id": "asha.menon@example.invalid"},
    "EMP002": {"employee_id": "EMP002", "employee_full_name": "Rohit Nair",
               "status": "INACTIVE", "employee_mail_id": "rohit.nair@example.invalid"},
    "EMP003": {"employee_id": "EMP003", "employee_full_name": "Meera Iyer",
               "status": "ACTIVE", "employee_mail_id": "meera.iyer@example.invalid"},
}


@secure_payload(api_name="sample_employee")
def lambda_handler(event, context):
    started_at = time.perf_counter()
    ctx = event.get("context") or {}
    request_id = ctx.get("request-id", "unknown")

    body = event.get("body-json") or {}
    employee_code = str(body.get("employee_code") or "").strip().upper()

    if not employee_code:
        envelope = build_envelope(request_id, response_code=400, error_code="EMP400",
                                  error_message="employee_code is mandatory",
                                  message="Request rejected", started_at=started_at)
        envelope["response_data"] = {}
        return envelope

    # Same fail-closed rule as the real API: no role, no data.
    if not ctx.get("x-Hasura-Role"):
        envelope = build_envelope(request_id, response_code=403, error_code="EMP403",
                                  error_message="Authorization role missing",
                                  message="Request rejected", started_at=started_at)
        envelope["response_data"] = {}
        return envelope

    # Log that a request arrived, never its content.
    log.info(json.dumps({"request_id": request_id, "client_ref": ctx.get("client-ref"),
                         "api": "sample_employee"}))

    record = EMPLOYEES.get(employee_code)
    if record is None:
        envelope = build_envelope(request_id, response_code=200, error_code="EMP404",
                                  error_message="Employee is not available",
                                  started_at=started_at)
        envelope["response_data"] = {}
        return envelope

    envelope = build_envelope(request_id, started_at=started_at)
    envelope["response_data"] = {"employee_information_master": record}
    return envelope
