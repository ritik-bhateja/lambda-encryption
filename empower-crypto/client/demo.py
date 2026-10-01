"""
End to end demo against the local sandbox.

    python local_gateway.py          # terminal 1
    python client/demo.py            # terminal 2

Requests: one request_value, encrypted directly, label as AAD.
Responses: response_key + response_value, unchanged envelope.
"""

import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from empower_client import (  # noqa: E402
    EmpowerApiError, EmpowerClient, b64u, b64u_decode, get_token, seal_request,
)

HOST = os.environ.get("EMPOWER_HOST", "http://localhost:8080")
API = f"{HOST}/prod"
results = []


def check(name, condition, detail=""):
    results.append(condition)
    print(f"  {'PASS' if condition else 'FAIL'}  {name}{'  ' + detail if detail else ''}")


def send(token, body):
    return requests.post(f"{API}/employee",
                         headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                         json=body, timeout=10).json()


def main():
    print("\n1. Keys, fetched once a day")
    token = get_token(HOST, "MERCH_ENCRYPTED")
    client = EmpowerClient(API, token)
    keys = client.ensure_keys()
    check("request encryption key and kek_response issued",
          len(keys["req"]) == 32 and len(keys["res"]) == 32, f"kid={keys['kid']}")
    check("the two keys differ", keys["req"] != keys["res"])

    print("\n2. Encrypted round trip")
    result = client.post("/employee", {"employee_code": "EMP001"})
    name = result.get("response_data", {}).get("employee_information_master", {}).get("employee_full_name")
    check("employee returned, request_value in, response_key + response_value out",
          name == "Asha Menon", f"name={name}")
    check("status fields stayed readable", result.get("response_code") == 200 and "request_id" in result)

    print("\n3. request_value format")
    v1 = client.seal({"employee_code": "EMP001"}, "/employee")
    v2 = client.seal({"employee_code": "EMP001"}, "/employee")
    p1, p2 = v1.split("."), v2.split(".")
    check("four parts: label.iv.ciphertext.tag", len(p1) == 4)
    label = json.loads(b64u_decode(p1[0]))
    check("label carries kid, cid, pth, mtd, iat, jti",
          {"kid", "cid", "pth", "mtd", "iat", "jti"} <= set(label))
    check("same payload twice gives a different iv", p1[1] != p2[1])
    check("same payload twice gives a different jti",
          label["jti"] != json.loads(b64u_decode(p2[0]))["jti"])

    print("\n4. request_value is one time use")
    v = client.seal({"employee_code": "EMP001"}, "/employee")
    first, second = send(token, {"request_value": v}), send(token, {"request_value": v})
    check("first use accepted", first.get("response_code") == 200)
    check("second use rejected", second.get("response_error_code") == "CRY409")

    print("\n5. The label is glued to the data")
    a = client.seal({"employee_code": "EMP001"}, "/employee").split(".")
    b = client.seal({"employee_code": "EMP002"}, "/employee").split(".")
    spliced = ".".join([a[0], b[1], b[2], b[3]])
    check("label from request A on data from request B rejected",
          send(token, {"request_value": spliced}).get("response_error_code") == "CRY422")

    parts = client.seal({"employee_code": "EMP001"}, "/employee").split(".")
    lab = json.loads(b64u_decode(parts[0])); lab["iat"] -= 1
    parts[0] = b64u(json.dumps(lab, sort_keys=True, separators=(",", ":")).encode())
    check("one second edit inside the label rejected",
          send(token, {"request_value": ".".join(parts)}).get("response_error_code") == "CRY422")

    parts = client.seal({"employee_code": "EMP001"}, "/employee").split(".")
    parts[2] = parts[2][:-2] + ("AA" if not parts[2].endswith("AA") else "BB")
    check("flipped ciphertext rejected",
          send(token, {"request_value": ".".join(parts)}).get("response_error_code") == "CRY422")

    print("\n6. Keys and binding")
    wrong = seal_request({"employee_code": "EMP001"}, keys["res"], keys["kid"], "MERCH_ENCRYPTED", "/employee")
    check("encrypted with kek_response instead of the request key rejected",
          send(token, {"request_value": wrong}).get("response_error_code") == "CRY422")
    other = client.seal({"employee_code": "EMP001"}, "/policy")
    check("sealed for /policy, sent to /employee rejected",
          send(token, {"request_value": other}).get("response_error_code") == "CRY412")

    print("\n7. Functional cases still behave as documented")
    missing = client.post("/employee", {"employee_code": "EMP999"})
    check("unknown code is 200 plus EMP404",
          missing.get("response_code") == 200 and missing.get("response_error_code") == "EMP404")
    try:
        client.post("/employee", {})
        check("missing employee_code rejected", False)
    except EmpowerApiError as exc:
        check("missing employee_code rejected", exc.code == "EMP400")

    print("\n8. Shape enforcement")
    check("plain JSON rejected when encryption is required",
          client.post_plaintext("/employee", {"employee_code": "EMP001"}).get("response_error_code") == "CRY426")
    v = client.seal({"employee_code": "EMP001"}, "/employee")
    check("old v2.0 shape with request_key rejected",
          send(token, {"request_key": "x", "request_value": v}).get("response_error_code") == "CRY400")
    v = client.seal({"employee_code": "EMP001"}, "/employee")
    check("plain field smuggled beside request_value rejected",
          send(token, {"request_value": v, "employee_code": "EMP002"}).get("response_error_code") == "CRY400")
    check("request_value with three parts rejected",
          send(token, {"request_value": "a.b.c"}).get("response_error_code") == "CRY400")

    open_client = EmpowerClient(API, get_token(HOST, "MERCH_PLAIN"))
    r = open_client.post_plaintext("/employee", {"employee_code": "EMP002"})
    check("plain JSON accepted when the vendor is not migrated yet",
          r.get("response_code") == 200
          and r.get("response_data", {}).get("employee_information_master", {}).get("employee_id") == "EMP002")

    print(f"\n{sum(results)}/{len(results)} checks passed\n")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
