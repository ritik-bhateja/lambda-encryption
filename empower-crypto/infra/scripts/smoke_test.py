"""
End to end checks against the DEPLOYED stack, through API Gateway.

    python infra/scripts/smoke_test.py --stack empower-care-sample-crypto --region ap-south-1

Proves in the real account: the authorizer, the VTL mapping, the layer, the
key service, the sample Lambda, the nonce table, and that CRY errors come back
as real HTTP statuses. Exits non-zero if any check fails.
"""

import argparse
import json
import os
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "client"))
from empower_client import b64u, b64u_decode, open_response, seal_request  # noqa: E402


class Checks:
    def __init__(self):
        self.results = []

    def check(self, name, ok, detail=""):
        self.results.append(ok)
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{'  ' + detail if detail else ''}")


def run(api_url, token_for, dev_url=None, timeout=15):
    """api_url: base URL including stage. token_for(merchant) returns a bearer token."""
    c = Checks()
    token = token_for("MERCH_ENCRYPTED")
    auth = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def post(path, body, headers=None, raw=None):
        r = requests.post(f"{api_url}{path}", headers=headers or auth,
                          data=raw if raw is not None else json.dumps(body), timeout=timeout)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}

    print("\n1. Gateway and authorizer")
    status, _ = post("/employee", {"employee_code": "EMP001"}, headers={"Content-Type": "application/json"})
    c.check("no Authorization header is 401", status == 401, f"got {status}")
    forged = token.rsplit(".", 1)[0] + "." + b64u(b"x" * 32)
    status, _ = post("/employee", {}, headers={"Authorization": f"Bearer {forged}",
                                               "Content-Type": "application/json"})
    c.check("forged token signature is 403", status == 403, f"got {status}")
    status, _ = post("/employee", None, headers={**auth, "Content-Type": "text/plain"}, raw="hello")
    c.check("non JSON content type is refused", status == 415, f"got {status}")

    print("\n2. Key service")
    status, keys = post("/crypto/session-key", {})
    c.check("keys issued", status == 200 and keys.get("response_code") == 200, f"http {status}")
    if status != 200:
        print("  cannot continue without keys:", keys.get("response_error_code"), keys.get("response_error_message"))
        return 1
    kid = keys["kek_id"]
    req_key, kek_res = b64u_decode(keys["request_encryption_key"]), b64u_decode(keys["kek_response"])
    c.check("request key and kek_response are 32 bytes and differ",
            len(req_key) == 32 and len(kek_res) == 32 and req_key != kek_res, f"kid={kid}")
    c.check("algorithms stated", keys.get("request_alg") == "A256GCM" and keys.get("response_alg") == "A256GCMKW")

    def seal(obj, path="/employee", key=req_key, k=kid, cid="MERCH_ENCRYPTED"):
        return seal_request(obj, key, k, cid, path)

    print("\n3. Encrypted round trip")
    started = time.perf_counter()
    status, body = post("/employee", {"request_value": seal({"employee_code": "EMP001"})})
    elapsed = (time.perf_counter() - started) * 1000
    ok = status == 200 and body.get("encrypted") and "response_key" in body and "response_value" in body
    c.check("reply is response_key + response_value", ok, f"http {status}, {elapsed:.0f} ms end to end")
    if ok:
        opened = open_response(body["response_key"], body["response_value"], kek_res)
        name = opened.get("response_data", {}).get("employee_information_master", {}).get("employee_full_name")
        c.check("response_value opens to the employee", name == "Asha Menon", f"name={name}")
        c.check("no plain data in the raw reply", "Asha" not in json.dumps(body))

    status, body = post("/employee", {"request_value": seal({"employee_code": "EMP999"})})
    c.check("unknown employee is 200 plus EMP404",
            status == 200 and body.get("response_error_code") == "EMP404", f"http {status}")
    status, body = post("/employee", {"request_value": seal({})})
    c.check("missing employee_code is HTTP 400 plus EMP400",
            status == 400 and body.get("response_error_code") == "EMP400", f"http {status}")

    print("\n4. Attacks, each must be HTTP 400 with the right code")

    def expect(name, body, code):
        status, reply = post("/employee", body)
        c.check(f"{name}: {code}", status == 400 and reply.get("response_error_code") == code
                and not reply.get("encrypted"), f"http {status} {reply.get('response_error_code')}")

    value = seal({"employee_code": "EMP001"})
    post("/employee", {"request_value": value})
    expect("replay of the same request_value", {"request_value": value}, "CRY409")

    a, b = seal({"employee_code": "EMP001"}).split("."), seal({"employee_code": "EMP002"}).split(".")
    expect("label from A spliced onto data from B", {"request_value": ".".join([a[0], b[1], b[2], b[3]])}, "CRY422")

    parts = seal({"employee_code": "EMP001"}).split(".")
    label = json.loads(b64u_decode(parts[0])); label["iat"] -= 1
    parts[0] = b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
    expect("one second edited in the label", {"request_value": ".".join(parts)}, "CRY422")

    expect("encrypted with kek_response instead", {"request_value": seal({"employee_code": "EMP001"}, key=kek_res)}, "CRY422")
    expect("sealed for /policy, sent to /employee", {"request_value": seal({"employee_code": "EMP001"}, path="/policy")}, "CRY412")
    expect("label names another vendor", {"request_value": seal({"employee_code": "EMP001"}, cid="MERCH_OTHER")}, "CRY412")
    expect("unknown kid", {"request_value": seal({"employee_code": "EMP001"}, k="A" * 22)}, "CRY410")
    expect("plain JSON while required", {"employee_code": "EMP001"}, "CRY426")
    expect("old v2.0 shape with request_key", {"request_key": "x", "request_value": seal({"employee_code": "EMP001"})}, "CRY400")
    expect("plain field beside request_value", {"request_value": seal({"employee_code": "EMP001"}), "employee_code": "EMP002"}, "CRY400")
    expect("three part request_value", {"request_value": "a.b.c"}, "CRY400")

    print("\n5. A vendor not migrated yet")
    plain_auth = {"Authorization": f"Bearer {token_for('MERCH_PLAIN')}", "Content-Type": "application/json"}
    status, body = post("/employee", {"employee_code": "EMP002"}, headers=plain_auth)
    c.check("plain JSON accepted for crypto_mode off",
            status == 200 and body.get("response_data", {}).get("employee_information_master", {}).get("employee_id") == "EMP002",
            f"http {status}")

    if dev_url:
        print("\n6. Dev helpers, the path Postman uses")
        r = requests.post(f"{dev_url}/dev/seal", headers=auth, timeout=timeout,
                          json={"path": "/employee", "payload": {"employee_code": "EMP003"}})
        sealed = r.json().get("request_value", "")
        c.check("/dev/seal returns a request_value", r.status_code == 200 and sealed.count(".") == 3, f"http {r.status_code}")
        status, body = post("/employee", {"request_value": sealed})
        r = requests.post(f"{dev_url}/dev/open", headers=auth, timeout=timeout,
                          json={"response_key": body.get("response_key"), "response_value": body.get("response_value")})
        name = r.json().get("response_data", {}).get("employee_information_master", {}).get("employee_full_name")
        c.check("/dev/open reads the reply", r.status_code == 200 and name == "Meera Iyer", f"name={name}")

    passed, total = sum(c.results), len(c.results)
    print(f"\n{passed}/{total} checks passed\n")
    return 0 if passed == total else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stack", default="empower-care-sample-crypto")
    ap.add_argument("--region", default="ap-south-1")
    args = ap.parse_args()

    sys.path.insert(0, HERE)
    from _stack import mint_token, outputs

    outs = outputs(args.stack, args.region)
    print(f"API: {outs['ApiUrl']}")
    sys.exit(run(outs["ApiUrl"], lambda m: mint_token(args.stack, args.region, m),
                 dev_url=outs.get("DevApiUrl")))


if __name__ == "__main__":
    main()
