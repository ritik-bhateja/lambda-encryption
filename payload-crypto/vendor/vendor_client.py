"""Vendor reference client for APIs behind payload_crypto. Needs only `cryptography`.

    export VENDOR_ID=ACME
    export VENDOR_KEY_HEX=...          # your 64 hex character key
    export VENDOR_KEY_ID=ACME-v1       # optional, defaults to <VENDOR_ID>-v1
    python vendor_client.py https://api.example.com/hello '{"name": "care"}'
    python vendor_client.py https://api.example.com/items/7 GET

Request: header X-Vendor-Id: <vendor>
         body   {"request_key": "label.iv.ciphertext.tag"}   (GET: no body)
    AES-256-GCM with your key, the base64url label as AAD.
    label = {v, alg, kid, cid, pth, mtd, iat, jti}; a new iv and jti every time.
Reply:   {"response_key": ..., "response_value": ...}
    unwrap the one-time DEK from response_key with your key, decrypt
    response_value with it (response_key as AAD), raw inflate, JSON.
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
import zlib
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VENDOR_HEADER = "X-Vendor-Id"
MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def seal_request(payload, key: bytes, vendor: str, path: str, method: str = "POST", key_id: str = None):
    label = {"v": 1, "alg": "A256GCM", "kid": key_id or f"{vendor}-v1", "cid": vendor, "pth": path,
             "mtd": method, "iat": int(time.time()), "jti": uuid.uuid4().hex}
    label_seg = b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
    iv = os.urandom(12)
    sealed = AESGCM(key).encrypt(iv, json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                                 label_seg.encode("ascii"))
    return {"request_key": ".".join([label_seg, b64u(iv), b64u(sealed[:-16]), b64u(sealed[-16:])])}


def open_reply(response_key: str, response_value: str, key: bytes, vendor: str = None):
    label = json.loads(b64u_decode(response_key))
    if vendor and label.get("cid") != vendor:
        raise ValueError(f"reply is for {label.get('cid')}, not {vendor}")
    dek = AESGCM(key).decrypt(b64u_decode(label["wiv"]),
                              b64u_decode(label["edek"]) + b64u_decode(label["wtag"]), None)
    blob = b64u_decode(response_value)
    packed = AESGCM(dek).decrypt(blob[:12], blob[12:], response_key.encode("ascii"))
    d = zlib.decompressobj(wbits=-15)
    plaintext = d.decompress(packed, MAX_PLAINTEXT_BYTES + 1)
    if len(plaintext) > MAX_PLAINTEXT_BYTES or d.unconsumed_tail:
        raise ValueError("reply over 10 MB")
    return json.loads(plaintext)


def call(url: str, payload, vendor: str, key: bytes, method: str = "POST", key_id: str = None):
    """Seal, send, open. Returns (http_status, decrypted reply or plain error)."""
    path = urlparse(url).path or "/"
    data = None
    if payload is not None and method not in ("GET", "HEAD", "DELETE"):
        data = json.dumps(seal_request(payload, key, vendor, path, method, key_id)).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", VENDOR_HEADER: vendor})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status, reply = resp.status, json.load(resp)
    except urllib.error.HTTPError as exc:
        status, reply = exc.code, json.load(exc)
    if "response_key" in reply:
        return status, open_reply(reply["response_key"], reply["response_value"], key, vendor)
    return status, reply                     # CRY errors come back in the clear


def main():
    vendor = os.environ.get("VENDOR_ID", "").strip()
    key_hex = os.environ.get("VENDOR_KEY_HEX", "").strip()
    if not vendor or len(key_hex) != 64:
        sys.exit("Set VENDOR_ID and VENDOR_KEY_HEX (64 hex characters)")
    if len(sys.argv) != 3:
        sys.exit("usage: python vendor_client.py <url> '<json payload>' | GET")
    method, payload = ("GET", None) if sys.argv[2].upper() == "GET" else ("POST", json.loads(sys.argv[2]))
    status, reply = call(sys.argv[1], payload, vendor, bytes.fromhex(key_hex), method,
                         os.environ.get("VENDOR_KEY_ID") or None)
    print(status)
    print(json.dumps(reply, indent=2))


if __name__ == "__main__":
    main()
