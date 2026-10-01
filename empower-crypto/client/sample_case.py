"""
Sample case: one real request traced end to end, every intermediate captured.

    python local_gateway.py              # terminal 1
    python client/sample_case.py         # terminal 2, writes docs/sample_case.json

Keys printed here come from the LOCAL SANDBOX with a random seed that exists
only while it runs. Never print real keys like this.
"""

import json
import os
import sys
import time
import uuid
import zlib

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from empower_client import b64u, b64u_decode, get_token, seal_request  # noqa: E402

HOST = os.environ.get("EMPOWER_HOST", "http://localhost:8080")
API = f"{HOST}/prod"
MERCHANT, PATH, PAYLOAD = "MERCH_ENCRYPTED", "/employee", {"employee_code": "EMP001"}
out = {"merchant": MERCHANT, "path": PATH, "payload": PAYLOAD}


def post(path, token, body):
    r = requests.post(f"{API}{path}", headers={"Authorization": f"Bearer {token}",
                                               "Content-Type": "application/json"},
                      json=body, timeout=10)
    return r.status_code, r.json()


# ---- steps 1 to 5: today's keys ----------------------------------------------
token = get_token(HOST, MERCHANT)
status, keys = post("/crypto/session-key", token, {})
out["key_service"] = {"status": status, "body": keys}
kid = keys["kek_id"]
request_key = b64u_decode(keys["request_encryption_key"])
kek_response = b64u_decode(keys["kek_response"])

# ---- steps 6 and 7: build request_value by hand, capturing everything -----------
label = {"v": 1, "alg": "A256GCM", "kid": kid, "cid": MERCHANT, "pth": PATH, "mtd": "POST",
         "iat": int(time.time()), "jti": uuid.uuid4().hex}
label_seg = b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
plaintext = json.dumps(PAYLOAD, separators=(",", ":")).encode()
iv = os.urandom(12)
sealed = AESGCM(request_key).encrypt(iv, plaintext, label_seg.encode("ascii"))
ct, tag = sealed[:-16], sealed[-16:]
request_value = ".".join([label_seg, b64u(iv), b64u(ct), b64u(tag)])

out["request"] = {
    "label": label,
    "label_seg": label_seg,
    "plaintext": plaintext.decode(),
    "plaintext_bytes": len(plaintext),
    "iv_hex": iv.hex(), "iv_b64u": b64u(iv),
    "ciphertext_hex": ct.hex(), "ciphertext_b64u": b64u(ct),
    "tag_hex": tag.hex(), "tag_b64u": b64u(tag),
    "request_value": request_value,
    "request_value_chars": len(request_value),
    "label_chars": len(label_seg),
}

# ---- steps 8 to 17: send it ------------------------------------------------------
status, resp = post(PATH, token, {"request_value": request_value})
out["response"] = {"status": status, "body": dict(resp)}

# ---- step 18: open the response -------------------------------------------------
rk, rv = resp["response_key"], resp["response_value"]
r_label = json.loads(b64u_decode(rk))
r_dek = AESGCM(kek_response).decrypt(b64u_decode(r_label["wiv"]),
                                     b64u_decode(r_label["edek"]) + b64u_decode(r_label["wtag"]), None)
blob = b64u_decode(rv)
r_plain = zlib.decompressobj(wbits=-15).decompress(
    AESGCM(r_dek).decrypt(blob[:12], blob[12:], rk.encode("ascii")))
out["open"] = {
    "response_key_label": r_label,
    "response_dek_hex": r_dek.hex(),
    "plaintext": json.loads(r_plain),
    "response_key_chars": len(rk),
    "response_value_chars": len(rv),
}

# ---- negative cases ------------------------------------------------------------------
neg = []


def case(name, body, what):
    s, b = post(PATH, token, body)
    neg.append({"case": name, "what_we_did": what, "http": s,
                "code": b.get("response_error_code"), "message": b.get("response_error_message")})


def fresh(obj=None, path=PATH, key=request_key, k_id=kid, cid=MERCHANT):
    return seal_request(obj or PAYLOAD, key, k_id, cid, path)


case("Replay", {"request_value": request_value}, "Sent the exact same request_value a second time")

a, b = fresh({"employee_code": "EMP001"}).split("."), fresh({"employee_code": "EMP002"}).split(".")
case("Spliced label", {"request_value": ".".join([a[0], b[1], b[2], b[3]])},
     "Label from request A on the iv, data and tag of request B")

p = fresh().split("."); lab = json.loads(b64u_decode(p[0])); lab["iat"] -= 1
p[0] = b64u(json.dumps(lab, sort_keys=True, separators=(",", ":")).encode())
case("Edited label", {"request_value": ".".join(p)}, "Changed iat inside the label by one second")

p = fresh().split("."); p[2] = p[2][:-2] + ("AA" if not p[2].endswith("AA") else "BB")
case("Tampered data", {"request_value": ".".join(p)}, "Changed two characters of the ciphertext")

case("Wrong API", {"request_value": fresh(path="/policy")}, "Built for /policy, sent to /employee")
case("Wrong vendor", {"request_value": fresh(cid="MERCH_OTHER")},
     "Label says another vendor, token is MERCH_ENCRYPTED")
case("Unknown key", {"request_value": fresh(k_id="AAAAAAAAAAAAAAAAAAAAAA")},
     "kid that does not match today's key")
case("Wrong key", {"request_value": fresh(key=kek_response)},
     "Encrypted with kek_response instead of the request key")
case("Plain JSON", PAYLOAD, "Sent the JSON without encryption")
case("Old v2.0 shape", {"request_key": "eyJ...", "request_value": fresh()},
     "Sent request_key beside request_value, as in v2.0")
case("Extra field", {"request_value": fresh(), "employee_code": "EMP002"},
     "Added a plain field beside request_value")
case("Malformed", {"request_value": "only.three.parts"}, "request_value with three parts instead of four")

out["negative"] = neg

path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "sample_case.json")
with open(path, "w") as f:
    json.dump(out, f, indent=2)

print("happy path:", out["response"]["status"], out["open"]["plaintext"]["response_data"])
for n in neg:
    print(f"  {n['case']:<16} {n['http']}  {n['code']}  {n['message']}")
print("request_value chars:", len(request_value), "| written", path)
