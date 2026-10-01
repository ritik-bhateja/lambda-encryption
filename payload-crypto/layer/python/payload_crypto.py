"""payload_crypto: encrypted request in, encrypted reply out, for any Lambda API.

One import and one decorator per API. The handler does not change:

    from payload_crypto import secure_api

    @secure_api()
    def lambda_handler(event, context):
        body = json.loads(event["body"])          # already decrypted
        ...
        return {"statusCode": 200, "body": json.dumps(result)}   # encrypted on exit

Wire format (design v3.0 shapes, one shared AES-256 key per vendor):

    request   header  X-Vendor-Id: <VENDOR>
              body    {"request_key": "<label>.<iv>.<ciphertext>.<tag>"}
                      AES-256-GCM with the vendor key, the base64url label as AAD.
                      label = {v, alg, kid, cid, pth, mtd, iat, jti}
    reply     body    {"response_key": "...", "response_value": "..."}
                      response_key   = a fresh DEK wrapped with the vendor key,
                                       plus the label (cid, pth, mtd, kek_id, iat, jti)
                      response_value = base64url(iv | ciphertext | tag): the
                                       raw-deflated JSON under the DEK,
                                       response_key as AAD

Vendor keys live in Secrets Manager, one secret per vendor, named by
PAYLOAD_KEY_SECRET_TEMPLATE (default "payload-keys/{vendor}"):

    {"key_id": "ACME-v1", "key_hex": "<64 hex chars>"}
    optional while rotating: "previous_key_id", "previous_key_hex"

They are cached per Lambda container. Keys are never put in the event, never
logged and never returned.

Environment:
    PAYLOAD_KEY_SECRET_TEMPLATE   secret name, "{vendor}" is replaced      default payload-keys/{vendor}
    PAYLOAD_NONCE_TABLE           DynamoDB table for replay protection     required
    PAYLOAD_VENDOR_HEADER         header that names the vendor             default X-Vendor-Id
    PAYLOAD_ALLOWED_VENDORS       optional comma list; others are refused before any AWS call
    PAYLOAD_KEY_CACHE_SECONDS     key cache lifetime                       default 300
"""

import base64
import contextvars
import functools
import json
import logging
import os
import re
import time
import uuid
import zlib
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "secure_api", "vendor_keys", "encrypted_payload", "current_vendor_keys",
    "CryptoError", "VendorKeys", "get_vendor_keys", "clear_key_cache",
    "seal_request", "open_reply",
]

log = logging.getLogger("payload_crypto")

REQUEST_FIELD = "request_key"
REQUEST_VERSION = 1
REQUEST_ALG = "A256GCM"
REPLY_VERSION = 1
REPLY_ALG = "A256GCMKW"
REPLY_ENC = "A256GCM"
REPLY_ZIP = "DEF"

MAX_SKEW_SECONDS = 300
NONCE_TTL_SECONDS = 300
MISS_CACHE_SECONDS = 60
MAX_CACHE_ENTRIES = 1000
MAX_BODY_BYTES = 12 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024
BODYLESS_METHODS = {"GET", "HEAD", "DELETE", "OPTIONS"}
VENDOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

CRY_MESSAGES = {
    "CRY400": "Malformed encrypted payload",
    "CRY401": "Algorithm not permitted for this client",
    "CRY409": "request_key already used",
    "CRY410": "Key expired or unknown",
    "CRY412": "Payload binding mismatch",
    "CRY413": "Message timestamp outside the accepted window",
    "CRY422": "Payload could not be decrypted",
    "CRY426": "Encryption required for this client",
    "CRY500": "Platform crypto failure",
}


class CryptoError(Exception):
    """A CRY code for the caller. The detail goes to CloudWatch only."""

    def __init__(self, code, http_status=400, detail="", message=None):
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.detail = detail
        self.message = message              # safe for the caller; defaults to CRY_MESSAGES


@dataclass(frozen=True)
class VendorKeys:
    vendor: str
    key_id: str
    key: bytes = field(repr=False)
    previous: tuple = field(default=(), repr=False)     # ((key_id, key), ...)

    def for_kid(self, kid):
        if kid == self.key_id:
            return self.key
        for old_id, old_key in self.previous:
            if kid == old_id:
                return old_key
        return None


# ---------------------------------------------------------------- AWS clients ----

_clients = {}


def _client(name):
    if name not in _clients:
        _clients[name] = boto3.client(name)
    return _clients[name]


# ------------------------------------------------------------------- helpers ----

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _header(event, name):
    """Case-insensitive header lookup for proxy and mapping-template events."""
    headers = event.get("headers") or (event.get("params") or {}).get("header") or {}
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


# ------------------------------------------------------------- vendor keys ----

_key_cache = {}          # vendor -> (expires_at, VendorKeys or None)
_current = contextvars.ContextVar("payload_crypto_vendor_keys", default=None)


def clear_key_cache():
    _key_cache.clear()


def vendor_from_event(event) -> str:
    header = os.environ.get("PAYLOAD_VENDOR_HEADER", "X-Vendor-Id")
    vendor = (_header(event, header) or "").strip()
    if not vendor:
        raise CryptoError("CRY400", 400, f"{header} header missing",
                          message=f"{header} header is required")
    if not VENDOR_RE.match(vendor):
        raise CryptoError("CRY400", 400, f"{header} header is not a valid vendor name",
                          message=f"{header} header is not a valid vendor name")
    allowed = os.environ.get("PAYLOAD_ALLOWED_VENDORS", "").strip()
    if allowed and vendor not in {v.strip() for v in allowed.split(",")}:
        raise CryptoError("CRY410", 400, f"vendor {vendor} is not allowed")
    return vendor


def _parse_keys(vendor, raw) -> VendorKeys:
    try:
        doc = json.loads(raw)
        key = bytes.fromhex(doc["key_hex"])
        previous = ()
        if doc.get("previous_key_hex"):
            previous = ((doc.get("previous_key_id") or f"{vendor}-previous",
                         bytes.fromhex(doc["previous_key_hex"])),)
    except (ValueError, KeyError, TypeError) as exc:
        raise CryptoError("CRY500", 500, f"secret for {vendor} is malformed: {type(exc).__name__}") from exc
    if len(key) != 32 or any(len(k) != 32 for _, k in previous):
        raise CryptoError("CRY500", 500, f"secret for {vendor} does not hold 32 byte keys")
    return VendorKeys(vendor, doc.get("key_id") or f"{vendor}-v1", key, previous)


def get_vendor_keys(vendor: str) -> VendorKeys:
    """The vendor's keys from Secrets Manager, cached per Lambda container."""
    now = time.time()
    hit = _key_cache.get(vendor)
    if hit and now < hit[0]:
        if hit[1] is None:
            raise CryptoError("CRY410", 400, f"no key for vendor {vendor} (cached)")
        return hit[1]

    if len(_key_cache) >= MAX_CACHE_ENTRIES:
        # Only misses can pile up (random vendor names). Drop them first.
        for name in [n for n, (_, k) in _key_cache.items() if k is None]:
            del _key_cache[name]

    template = os.environ.get("PAYLOAD_KEY_SECRET_TEMPLATE", "payload-keys/{vendor}")
    secret_id = template.format(vendor=vendor)
    try:
        raw = _client("secretsmanager").get_secret_value(SecretId=secret_id)["SecretString"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            _key_cache[vendor] = (now + MISS_CACHE_SECONDS, None)
            raise CryptoError("CRY410", 400, f"no secret {secret_id}") from exc
        # Throttled, denied or unavailable. Fail closed, never fall back to plaintext.
        raise CryptoError("CRY500", 500, f"secret {secret_id} unavailable: {exc.response['Error']['Code']}") from exc

    keys = _parse_keys(vendor, raw)
    ttl = int(os.environ.get("PAYLOAD_KEY_CACHE_SECONDS", "300"))
    _key_cache[vendor] = (now + ttl, keys)
    return keys


def current_vendor_keys() -> VendorKeys:
    keys = _current.get()
    if keys is None:
        raise CryptoError("CRY500", 500, "@vendor_keys is not applied to this handler")
    return keys


# ---------------------------------------------------------------- requests ----

def _consume_nonce(vendor, jti, iat):
    table = os.environ.get("PAYLOAD_NONCE_TABLE")
    if not table:
        raise CryptoError("CRY500", 500, "PAYLOAD_NONCE_TABLE not configured")
    try:
        _client("dynamodb").put_item(
            TableName=table,
            Item={"nonce_id": {"S": f"{vendor}#{jti}"},
                  "ttl_epoch": {"N": str(int(iat) + NONCE_TTL_SECONDS)}},
            ConditionExpression="attribute_not_exists(nonce_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise CryptoError("CRY409", 400, "jti already used") from exc
        raise CryptoError("CRY500", 500, f"nonce store unavailable: {exc.response['Error']['Code']}") from exc


def open_request(body, keys: VendorKeys, path: str, method: str):
    """Verify and decrypt {"request_key": ...}. Returns the vendor's JSON."""
    if not isinstance(body, dict) or REQUEST_FIELD not in body:
        raise CryptoError("CRY426", 400, f"{REQUEST_FIELD} is required")
    extra = set(body) - {REQUEST_FIELD}
    if extra:
        # Anything beside the encrypted field is unauthenticated. Refuse it.
        raise CryptoError("CRY400", 400, f"unexpected fields {sorted(extra)}")

    sealed = body[REQUEST_FIELD]
    if not isinstance(sealed, str) or len(sealed) > MAX_BODY_BYTES:
        raise CryptoError("CRY400", 400, f"{REQUEST_FIELD} missing or oversized")
    parts = sealed.split(".")
    if len(parts) != 4 or not all(parts[:2]) or not parts[3]:
        raise CryptoError("CRY400", 400, f"{REQUEST_FIELD} has {len(parts)} parts, expected 4")
    label_seg, iv_seg, ct_seg, tag_seg = parts
    try:
        label = json.loads(b64u_decode(label_seg))
    except ValueError as exc:
        raise CryptoError("CRY400", 400, "unreadable label") from exc
    if not isinstance(label, dict):
        raise CryptoError("CRY400", 400, "label is not an object")

    if label.get("v") != REQUEST_VERSION:
        raise CryptoError("CRY400", 400, f"unsupported request version {label.get('v')}")
    if label.get("alg") != REQUEST_ALG:
        raise CryptoError("CRY401", 400, f"alg={label.get('alg')}")
    if label.get("cid") != keys.vendor:
        raise CryptoError("CRY412", 400, "label cid does not match the vendor header")
    if label.get("pth") != path or label.get("mtd") != method:
        raise CryptoError("CRY412", 400, f"label is for {label.get('mtd')} {label.get('pth')}, not {method} {path}")
    key = keys.for_kid(label.get("kid"))
    if key is None:
        raise CryptoError("CRY410", 400, f"kid {label.get('kid')} is not a current key")

    iat, jti = label.get("iat"), label.get("jti")
    if not isinstance(iat, int) or not isinstance(jti, str) or not jti:
        raise CryptoError("CRY400", 400, "iat or jti missing")
    if abs(time.time() - iat) > MAX_SKEW_SECONDS:
        raise CryptoError("CRY413", 400, f"skew {int(time.time() - iat)}s")

    _consume_nonce(keys.vendor, jti, iat)

    try:
        iv, ct, tag = b64u_decode(iv_seg), b64u_decode(ct_seg), b64u_decode(tag_seg)
        if len(iv) != 12 or len(tag) != 16:
            raise ValueError("iv must be 12 bytes and tag 16 bytes")
        plaintext = AESGCM(key).decrypt(iv, ct + tag, label_seg.encode("ascii"))
    except (InvalidTag, ValueError) as exc:
        raise CryptoError("CRY422", 400, f"request decrypt failed: {type(exc).__name__}") from exc

    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise CryptoError("CRY400", 400, "request over 10 MB")
    try:
        return json.loads(plaintext)
    except ValueError as exc:
        raise CryptoError("CRY400", 400, "decrypted request is not JSON") from exc


# ------------------------------------------------------------------ replies ----

def seal_reply(obj, keys: VendorKeys, path: str, method: str):
    """Returns {"response_key": ..., "response_value": ...} for obj."""
    dek = os.urandom(32)
    wrap_iv = os.urandom(12)
    wrapped = AESGCM(keys.key).encrypt(wrap_iv, dek, None)
    label = {
        "v": REPLY_VERSION, "alg": REPLY_ALG, "enc": REPLY_ENC, "zip": REPLY_ZIP,
        "kek_id": keys.key_id, "wiv": b64u(wrap_iv), "wtag": b64u(wrapped[-16:]),
        "edek": b64u(wrapped[:-16]), "cid": keys.vendor, "pth": path, "mtd": method,
        "iat": int(time.time()), "jti": uuid.uuid4().hex,
    }
    response_key = b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
    compressor = zlib.compressobj(level=6, wbits=-15)
    packed = compressor.compress(json.dumps(obj, separators=(",", ":")).encode("utf-8")) + compressor.flush()
    iv = os.urandom(12)
    response_value = b64u(iv + AESGCM(dek).encrypt(iv, packed, response_key.encode("ascii")))
    return {"response_key": response_key, "response_value": response_value}


# ----------------------------------------------------- vendor-side helpers ----
# What a vendor does. Used by tests and dev tools; vendors have their own client.

def seal_request(payload, key: bytes, key_id: str, vendor: str, path: str, method: str = "POST"):
    label = {"v": REQUEST_VERSION, "alg": REQUEST_ALG, "kid": key_id, "cid": vendor,
             "pth": path, "mtd": method, "iat": int(time.time()), "jti": uuid.uuid4().hex}
    label_seg = b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
    iv = os.urandom(12)
    sealed = AESGCM(key).encrypt(iv, json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                                 label_seg.encode("ascii"))
    return {REQUEST_FIELD: ".".join([label_seg, b64u(iv), b64u(sealed[:-16]), b64u(sealed[-16:])])}


def open_reply(response_key: str, response_value: str, key: bytes):
    label = json.loads(b64u_decode(response_key))
    try:
        dek = AESGCM(key).decrypt(b64u_decode(label["wiv"]),
                                  b64u_decode(label["edek"]) + b64u_decode(label["wtag"]), None)
        blob = b64u_decode(response_value)
        packed = AESGCM(dek).decrypt(blob[:12], blob[12:], response_key.encode("ascii"))
    except (InvalidTag, KeyError, ValueError) as exc:
        raise CryptoError("CRY422", 400, f"reply decrypt failed: {type(exc).__name__}") from exc
    d = zlib.decompressobj(wbits=-15)
    plaintext = d.decompress(packed, MAX_PLAINTEXT_BYTES + 1)
    if len(plaintext) > MAX_PLAINTEXT_BYTES or d.unconsumed_tail:
        raise CryptoError("CRY400", 400, "reply over 10 MB")
    return json.loads(plaintext)


# ------------------------------------------------------------ event shapes ----
# "proxy":   API Gateway proxy / HTTP API / function URL. Body is event["body"],
#            a string. The handler returns {"statusCode", "headers", "body"}.
# "mapping": REST API with a mapping template (type: aws). Body is
#            event["body-json"], a dict. The handler returns a dict.

def _shape(event):
    return "mapping" if "body-json" in event else "proxy"


def _route(event, shape, path, method):
    if shape == "mapping":
        ctx = event.get("context") or {}
        method = method or ctx.get("http-method")
        path = path or ctx.get("resource-path")
    else:
        rc = event.get("requestContext") or {}
        method = method or event.get("httpMethod") or (rc.get("http") or {}).get("method")
        if not path:
            path = event.get("rawPath") or event.get("path")
            stage = rc.get("stage")
            # HTTP API rawPath carries a named stage; the vendor signs the path without it.
            if event.get("rawPath") and stage and stage != "$default" and path.startswith(f"/{stage}/"):
                path = path[len(stage) + 1:]
    if not path or not method:
        raise CryptoError("CRY500", 500, "cannot work out the API path or method; pass path= and method=")
    return path, method.upper()


def _open_event(event, shape, keys, path, method):
    if shape == "mapping":
        body = event.get("body-json")
        empty = body in (None, "", {})
    else:
        raw = event.get("body")
        if raw and event.get("isBase64Encoded"):
            raw = base64.b64decode(raw).decode("utf-8")
        empty = not raw
        if not empty:
            if len(raw) > MAX_BODY_BYTES:
                raise CryptoError("CRY400", 400, "body over the size limit")
            try:
                body = json.loads(raw)
            except ValueError as exc:
                raise CryptoError("CRY400", 400, "body is not JSON") from exc

    if empty:
        if method in BODYLESS_METHODS:
            return event                     # nothing to decrypt; the reply is still sealed
        raise CryptoError("CRY426", 400, f"{REQUEST_FIELD} is required")

    plain = open_request(body, keys, path, method)
    opened = dict(event)
    if shape == "mapping":
        opened["body-json"] = plain
    else:
        opened["body"] = json.dumps(plain, separators=(",", ":"))
        opened["isBase64Encoded"] = False
    return opened


def _seal_result(result, shape, keys, path, method, plain_fields):
    if shape == "mapping":
        out = {k: result[k] for k in plain_fields if isinstance(result, dict) and k in result}
        out.update(seal_reply(result, keys, path, method))
        return out

    if isinstance(result, dict) and "statusCode" in result:
        out = dict(result)
        raw = result.get("body")
        if raw in (None, ""):
            return out                       # nothing to protect, e.g. 204
        if result.get("isBase64Encoded"):
            raw = base64.b64decode(raw).decode("utf-8")
        try:
            obj = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            obj = raw                        # plain text body: sealed as a JSON string
    else:
        out = {"statusCode": 200}            # HTTP API allows returning the body directly
        obj = result

    out["body"] = json.dumps(seal_reply(obj, keys, path, method))
    out["isBase64Encoded"] = False
    headers = {k: v for k, v in (out.get("headers") or {}).items()
               if k.lower() not in ("content-type", "content-length", "content-encoding")}
    headers["Content-Type"] = "application/json"
    out["headers"] = headers
    return out


def error_response(event, exc: CryptoError):
    """Errors go out in the clear, so a vendor with a broken key can still read why."""
    log.warning("payload_crypto rejected %s: %s", exc.code, exc.detail)
    message = exc.message or CRY_MESSAGES.get(exc.code, "Request rejected")
    if _shape(event) == "mapping":
        return {"response_code": exc.http_status, "response_error_code": exc.code,
                "response_error_message": message}
    return {"statusCode": exc.http_status, "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": exc.code, "message": message})}


# -------------------------------------------------------------- decorators ----

def vendor_keys(handler):
    """Pick the vendor from the header and load its keys (cached).

    The keys are held for the length of the call and read with
    current_vendor_keys(). They are never put into the event.
    """
    @functools.wraps(handler)
    def inner(event, context):
        try:
            keys = get_vendor_keys(vendor_from_event(event))
        except CryptoError as exc:
            return error_response(event, exc)
        token = _current.set(keys)
        try:
            return handler(event, context)
        finally:
            _current.reset(token)
    return inner


def encrypted_payload(path=None, method=None, plain_fields=()):
    """Decrypt the request on the way in, seal the reply on the way out.

    path, method   override what is read from the event (the label must match)
    plain_fields   mapping-template APIs only: top-level reply fields also copied
                   out in the clear, e.g. ("response_code",) for a status mapping
    """
    def outer(handler):
        @functools.wraps(handler)
        def inner(event, context):
            shape = _shape(event)
            try:
                keys = current_vendor_keys()
                api_path, api_method = _route(event, shape, path, method)
                event = _open_event(event, shape, keys, api_path, api_method)
            except CryptoError as exc:
                return error_response(event, exc)

            result = handler(event, context)

            try:
                return _seal_result(result, shape, keys, api_path, api_method, plain_fields)
            except Exception as exc:
                # Never fall back to a plaintext reply.
                return error_response(event, CryptoError("CRY500", 500, f"reply sealing failed: {type(exc).__name__}"))
        return inner
    return outer


def secure_api(path=None, method=None, plain_fields=()):
    """@vendor_keys + @encrypted_payload in one line. Use this on every API."""
    def outer(handler):
        return vendor_keys(encrypted_payload(path, method, plain_fields)(handler))
    return outer
