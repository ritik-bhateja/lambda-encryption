"""
Reference client for the Empower Care encrypted APIs.

This is the shape of the small library you hand to a vendor. It does three
things and nothing else:

  1. fetches and caches today's two keys, once a day
  2. encrypts a request into a single request_value
  3. opens a response's response_key + response_value

REQUEST, encrypted directly with the request encryption key:

    label          = {"v","alg","kid","cid","pth","mtd","iat","jti"}
    request_value  = b64u(label) . b64u(iv) . b64u(ciphertext) . b64u(tag)
                     AES-256-GCM, fresh 12 byte iv, the label segment as AAD

RESPONSE, unchanged envelope:

    response_key   the reply's one-time DEK, locked with kek_response
    response_value the reply, locked with that DEK, response_key as AAD

    client = EmpowerClient("http://localhost:8080/prod", token)
    print(client.post("/employee", {"employee_code": "EMP001"}))

Only dependency beyond requests: the `cryptography` package.
"""

import base64
import json
import os
import time
import uuid
import zlib

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class EmpowerApiError(Exception):
    def __init__(self, code, message, body=None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.body = body or {}


# --------------------------------------------------------------------------
# The two primitives a vendor needs. Portable to any language.
# --------------------------------------------------------------------------

def seal_request(obj, request_key: bytes, kid: str, client_ref: str, path: str,
                 method: str = "POST") -> str:
    """Return request_value: label.iv.ciphertext.tag"""
    label = {
        "v": 1, "alg": "A256GCM", "kid": kid,
        "cid": client_ref, "pth": path, "mtd": method,
        "iat": int(time.time()),
        "jti": uuid.uuid4().hex,          # fresh every request, never reused
    }
    label_seg = b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
    iv = os.urandom(12)                   # fresh every request, never reused
    sealed = AESGCM(request_key).encrypt(
        iv, json.dumps(obj, separators=(",", ":")).encode("utf-8"), label_seg.encode("ascii"))
    return ".".join([label_seg, b64u(iv), b64u(sealed[:-16]), b64u(sealed[-16:])])


def open_response(response_key: str, response_value: str, kek_response: bytes):
    """Unlock the reply DEK with kek_response, then the reply. Returns the object."""
    label = json.loads(b64u_decode(response_key))
    dek = AESGCM(kek_response).decrypt(
        b64u_decode(label["wiv"]),
        b64u_decode(label["edek"]) + b64u_decode(label["wtag"]),
        None,
    )
    blob = b64u_decode(response_value)
    packed = AESGCM(dek).decrypt(blob[:12], blob[12:], response_key.encode("ascii"))
    d = zlib.decompressobj(wbits=-15)
    plaintext = d.decompress(packed, MAX_PLAINTEXT_BYTES + 1)
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError("response over 10 MB after decompression")
    return json.loads(plaintext)


# --------------------------------------------------------------------------
# The convenience client
# --------------------------------------------------------------------------

class EmpowerClient:
    def __init__(self, base_url, bearer_token, client_ref=None, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.token = bearer_token
        self.timeout = timeout
        self.client_ref = client_ref or self._merchant_from_token(bearer_token)
        self._keys = None
        self._refresh_at = 0.0

    @staticmethod
    def _merchant_from_token(token):
        claims = json.loads(b64u_decode(token.split(".")[1]))
        return claims.get("merchant_id") or claims.get("client_id")

    def ensure_keys(self, force=False):
        if not force and self._keys and time.time() < self._refresh_at:
            return self._keys

        response = requests.post(
            f"{self.base_url}/crypto/session-key",
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"},
            json={}, timeout=self.timeout,
        )
        body = response.json()
        if body.get("response_code") != 200:
            raise EmpowerApiError(body.get("response_error_code", "KEY_ERROR"),
                                  body.get("response_error_message", "key fetch failed"),
                                  body)

        self._keys = {
            "kid": body["kek_id"],
            "req": b64u_decode(body["request_encryption_key"]),
            "res": b64u_decode(body["kek_response"]),
        }
        # Refresh at 80 percent of the epoch, as the design specifies.
        self._refresh_at = time.time() + body["epoch_seconds"] * 0.8
        return self._keys

    def seal(self, payload, path, method="POST"):
        keys = self.ensure_keys()
        return seal_request(payload, keys["req"], keys["kid"], self.client_ref, path, method)

    def post(self, path, payload, _retried=False):
        request_value = self.seal(payload, path)

        response = requests.post(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"},
            json={"request_value": request_value},
            timeout=self.timeout,
        )
        body = response.json()
        code = body.get("response_error_code", "")

        # The keys rolled underneath us. Refetch once, then give up.
        if code in ("CRY410", "CRY422") and not _retried:
            self.ensure_keys(force=True)
            return self.post(path, payload, _retried=True)

        if body.get("encrypted") and body.get("response_key") and body.get("response_value"):
            opened = open_response(body.pop("response_key"), body.pop("response_value"),
                                   self._keys["res"])
            body.update(opened)

        if body.get("response_code", 200) >= 400:
            raise EmpowerApiError(code or "ERROR", body.get("response_error_message", ""), body)
        return body

    def post_plaintext(self, path, payload):
        """For a vendor still in the optional phase of the rollout."""
        response = requests.post(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"},
            json=payload, timeout=self.timeout,
        )
        return response.json()


def get_token(base_url, merchant_id):
    """Local convenience. In production the vendor gets this from ANZ."""
    response = requests.post(
        f"{base_url}/mock-anz/api/merchants/get_token",
        json={"client_id": merchant_id, "client_secret": "local-dev-secret"},
        timeout=10,
    )
    return response.json()["access_token"]
