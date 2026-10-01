"""Builds vendor/test_vectors.json: fixed inputs -> exact outputs, for vendors to check their code.

Uses a PUBLIC TEST KEY (bytes 00..1f). It is never a real vendor key.
Run: python scripts/make_test_vectors.py
"""
import base64, json, os, sys, zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

KEY = bytes(range(32))
VENDOR, KID, PATH, METHOD = "ACME", "ACME-v1", "/orders", "POST"

# ---- request: vendor -> API
req_payload = {"order_id": "ORD-1001", "amount": 2500, "currency": "INR"}
label = {"alg": "A256GCM", "cid": VENDOR, "iat": 1790412345, "jti": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
         "kid": KID, "mtd": METHOD, "pth": PATH, "v": 1}
label_json = json.dumps(label, sort_keys=True, separators=(",", ":"))
label_seg = b64u(label_json.encode())
req_iv = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaab")
req_plain = json.dumps(req_payload, separators=(",", ":"))
sealed = AESGCM(KEY).encrypt(req_iv, req_plain.encode(), label_seg.encode())
request_key = ".".join([label_seg, b64u(req_iv), b64u(sealed[:-16]), b64u(sealed[-16:])])

# ---- reply: API -> vendor
dek = bytes.fromhex("b0" * 32)
wrap_iv = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacb")
wrapped = AESGCM(KEY).encrypt(wrap_iv, dek, None)
rlabel = {"alg": "A256GCMKW", "cid": VENDOR, "edek": b64u(wrapped[:-16]), "enc": "A256GCM", "iat": 1790412346,
          "jti": "1f2e3d4c5b6a79880796a5b4c3d2e1f0", "kek_id": KID, "mtd": METHOD, "pth": PATH, "v": 1,
          "wiv": b64u(wrap_iv), "wtag": b64u(wrapped[-16:]), "zip": "DEF"}
response_key = b64u(json.dumps(rlabel, sort_keys=True, separators=(",", ":")).encode())
reply_obj = {"order_id": "ORD-1001", "status": "CREATED"}
reply_json = json.dumps(reply_obj, separators=(",", ":"))
co = zlib.compressobj(level=6, wbits=-15)
packed = co.compress(reply_json.encode()) + co.flush()
val_iv = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadb")
response_value = b64u(val_iv + AESGCM(dek).encrypt(val_iv, packed, response_key.encode()))

out = {
    "_note": "PUBLIC TEST KEY. Never use it for real traffic. Use these to check your implementation byte for byte.",
    "key_hex": KEY.hex(), "vendor_id": VENDOR, "key_id": KID,
    "request": {
        "inputs": {"payload_json": req_plain, "label_json": label_json, "iv_hex": req_iv.hex()},
        "expected": {"label_segment": label_seg, "request_key": request_key,
                     "http_body": json.dumps({"request_key": request_key}),
                     "http_headers": {"Content-Type": "application/json", "X-Vendor-Id": VENDOR}},
    },
    "response": {
        "http_body": {"response_key": response_key, "response_value": response_value},
        "expected": {"dek_hex": dek.hex(), "deflated_hex": packed.hex(), "reply_json": reply_json},
    },
}
path = os.path.join(ROOT, "vendor", "test_vectors.json")
json.dump(out, open(path, "w"), indent=2)
print("wrote", path)
