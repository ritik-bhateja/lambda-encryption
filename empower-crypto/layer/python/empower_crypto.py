"""
empower_crypto - shared payload crypto for the Empower Care API engine.

Ships as a Lambda layer: empower-care-prod-layer-payloadcrypto

Two formats on the wire
-----------------------
REQUEST, one field, encrypted directly with the vendor's request encryption key

    request_value = label . iv . ciphertext . tag      (four base64url parts)

    label       {"v","alg","kid","cid","pth","mtd","iat","jti"} as JSON.
                Readable, not secret, but authenticated: it is the AAD.
    iv          12 random bytes, new for every request
    ciphertext  the vendor JSON, AES-256-GCM with the request encryption key
    tag         16 byte seal over the label AND the ciphertext

RESPONSE, unchanged, envelope encryption

    response_key    a NEW one-time DEK, wrapped with kek_response, plus a label
    response_value  response_data and page_info, encrypted with that DEK,
                    response_key used as the AAD

The one-time rule: every request carries a fresh jti in its label, consumed
in a DynamoDB nonce table. A second use of the same request_value is CRY409.

GCM with random 96 bit ivs is safe up to about 2**32 (4.29 billion) messages
per key. Keys change every epoch, so at 1,000 requests per second a vendor
stays about 50 times under that limit with a 24 hour key.

Environment variables
---------------------
PAYLOAD_SEED_SECRET_ID   Secrets Manager id of the master seed
PAYLOAD_NONCE_TABLE      DynamoDB replay table name
CRYPTO_DEFAULT_MODE      Used only when the authorizer context is missing.
                         Set to "required" on every Gateway facing function.
"""

import base64
import functools
import hashlib
import json
import logging
import os
import time
import uuid
import zlib
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger()
log.setLevel(logging.INFO)

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

ENVELOPE_VERSION = 1
ALG = "A256GCMKW"            # response: how the DEK is wrapped with kek_response
ENC = "A256GCM"              # response: how the reply is encrypted with the DEK
ZIP = "DEF"                  # response: raw deflate before encryption

REQUEST_VERSION = 1
REQUEST_ALG = "A256GCM"      # request: encrypted directly, no DEK, no compression

VALUE_FIELD = "request_value"          # vendor -> platform, the only field
LEGACY_KEY_FIELD = "request_key"       # v2.0 field, refused with CRY400
RESP_KEY_FIELD = "response_key"        # platform -> vendor
RESP_VALUE_FIELD = "response_value"

DEFAULT_EPOCH_SECONDS = 86400
GRACE_SECONDS = 900          # accept the previous KEK for 15 minutes after a roll
MAX_SKEW_SECONDS = 300       # clock skew tolerance on iat
NONCE_TTL_SECONDS = 300      # matches MAX_SKEW_SECONDS
MAX_PLAINTEXT_BYTES = 10 * 1024 * 1024
MAX_FIELD_BYTES = 12 * 1024 * 1024
SEED_CACHE_SECONDS = 300

IST = timezone(timedelta(hours=5, minutes=30))

_sm = boto3.client("secretsmanager")
_ddb = boto3.client("dynamodb")

_seed_cache = {"value": None, "expires_at": 0.0}
_key_cache = {}   # kek_id -> (kek_req, kek_res), warm within a container


class CryptoError(Exception):
    """Carries the CRY code returned to the caller. Detail stays in the log."""

    def __init__(self, code, http_status=400, log_detail=""):
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.log_detail = log_detail


# --------------------------------------------------------------------------
# Base64url helpers
# --------------------------------------------------------------------------

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------
# Seed and KEK derivation
# --------------------------------------------------------------------------

def _get_seed() -> bytes:
    """Master seed from Secrets Manager, cached 300s like API_ENGINE_SECRET_KEY."""
    now = time.time()
    if _seed_cache["value"] is not None and now < _seed_cache["expires_at"]:
        return _seed_cache["value"]

    secret_id = os.environ["PAYLOAD_SEED_SECRET_ID"]
    try:
        raw = _sm.get_secret_value(SecretId=secret_id)["SecretString"]
    except ClientError as exc:
        # Fail closed. Never fall back to plaintext.
        raise CryptoError("CRY500", 500, f"seed fetch failed: {exc}") from exc

    seed = base64.b64decode(json.loads(raw)["seed_b64"])
    if len(seed) < 32:
        raise CryptoError("CRY500", 500, "seed shorter than 32 bytes")

    _seed_cache["value"] = seed
    _seed_cache["expires_at"] = now + SEED_CACHE_SECONDS
    return seed


def _hkdf(ikm: bytes, salt, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def epoch_id_for(ts: float, epoch_seconds: int) -> int:
    return int(ts // epoch_seconds)


def derive_keys(client_ref: str, key_version: int, epoch_id: int):
    """Return (kid, request_key, kek_res) for one client in one epoch.

    These are the two keys shared with the vendor:

        request_key   the request encryption key. The vendor encrypts every
                      request_value directly with it, the platform decrypts
        kek_res       kek_response. The platform wraps each response DEK with
                      it, the vendor unwraps. It never touches data

    kid names the pair. Rotation is automatic at the epoch boundary.
    Revocation is key_version + 1.
    """
    context = f"{client_ref}|{key_version}|{epoch_id}".encode()
    kek_id = b64u(hashlib.sha256(context).digest())[:22]

    cached = _key_cache.get(kek_id)
    if cached:
        return kek_id, cached[0], cached[1]

    seed = _get_seed()
    k_epoch = _hkdf(seed, client_ref.encode(), b"empower-payload-v1|" + context)
    kek_req = _hkdf(k_epoch, None, b"request")
    kek_res = _hkdf(k_epoch, None, b"response")

    _key_cache[kek_id] = (kek_req, kek_res)
    return kek_id, kek_req, kek_res


def candidate_epochs(now: float, epoch_seconds: int):
    """Current epoch, plus the previous one while inside the grace window."""
    current = epoch_id_for(now, epoch_seconds)
    epochs = [current]
    if now % epoch_seconds < GRACE_SECONDS:
        epochs.append(current - 1)
    return epochs


# --------------------------------------------------------------------------
# Seal and open: the two-field envelope
# --------------------------------------------------------------------------

def seal(obj, kek: bytes, kek_id: str, client_ref: str, path: str, method: str):
    """Encrypt obj. Returns (request_key, request_value).

    1. generate a fresh random DEK for this message only
    2. wrap the DEK with the KEK
    3. build request_key: the wrapped DEK plus the binding metadata
    4. encrypt the payload with the DEK, using request_key as the AAD
    """
    dek = os.urandom(32)                       # used once, never sent in the clear

    # --- wrap the DEK with the KEK -------------------------------------
    wrap_iv = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(wrap_iv, dek, None)
    edek, wrap_tag = wrapped[:-16], wrapped[-16:]

    key_obj = {
        "v": ENVELOPE_VERSION,
        "alg": ALG,
        "enc": ENC,
        "zip": ZIP,
        "kek_id": kek_id,
        "wiv": b64u(wrap_iv),
        "wtag": b64u(wrap_tag),
        "edek": b64u(edek),
        # binding: who, where, when, and which one
        "cid": client_ref,
        "pth": path,
        "mtd": method,
        "iat": int(time.time()),
        "jti": uuid.uuid4().hex,
    }
    request_key = b64u(json.dumps(key_obj, sort_keys=True, separators=(",", ":")).encode())

    # --- encrypt the payload with the DEK --------------------------------
    plaintext = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    compressor = zlib.compressobj(level=6, wbits=-15)          # raw deflate
    compressed = compressor.compress(plaintext) + compressor.flush()

    content_iv = os.urandom(12)
    # AAD is request_key itself. This is what makes the key valid for this
    # value and no other.
    ciphertext = AESGCM(dek).encrypt(content_iv, compressed, request_key.encode("ascii"))
    request_value = b64u(content_iv + ciphertext)

    return request_key, request_value


def read_key(request_key: str) -> dict:
    """Parse request_key without unwrapping anything. Safe to call first."""
    if not isinstance(request_key, str) or len(request_key) > 4096:
        raise CryptoError("CRY400", 400, "request_key missing or oversized")
    try:
        key_obj = json.loads(b64u_decode(request_key))
    except Exception as exc:
        raise CryptoError("CRY400", 400, f"unreadable request_key: {exc}") from exc
    if not isinstance(key_obj, dict):
        raise CryptoError("CRY400", 400, "request_key is not an object")
    return key_obj


def open_envelope(request_key: str, request_value: str, client_ref: str,
                  key_version: int, epoch_seconds: int, path: str, method: str,
                  kek_direction: str = "res", check_replay: bool = True):
    """Verify, unwrap, decrypt. Returns the business object.

    Order matters. Every cheap check runs before any crypto, and the nonce is
    consumed only after the request is known to be well formed and fresh.
    """
    if not isinstance(request_value, str) or len(request_value) > MAX_FIELD_BYTES:
        raise CryptoError("CRY400", 400, "request_value missing or oversized")

    key_obj = read_key(request_key)

    if key_obj.get("v") != ENVELOPE_VERSION:
        raise CryptoError("CRY400", 400, f"unsupported envelope version {key_obj.get('v')}")
    if key_obj.get("alg") != ALG or key_obj.get("enc") != ENC:
        raise CryptoError("CRY401", 400, f"alg={key_obj.get('alg')} enc={key_obj.get('enc')}")

    # --- binding -----------------------------------------------------------
    if key_obj.get("cid") != client_ref:
        raise CryptoError("CRY412", 400, "cid does not match the caller")
    if key_obj.get("pth") != path or key_obj.get("mtd") != method:
        raise CryptoError("CRY412", 400, "pth or mtd does not match the endpoint")

    iat, jti = key_obj.get("iat"), key_obj.get("jti")
    if not isinstance(iat, int) or not isinstance(jti, str) or not jti:
        raise CryptoError("CRY400", 400, "iat or jti missing")

    now = time.time()
    if abs(now - iat) > MAX_SKEW_SECONDS:
        raise CryptoError("CRY413", 400, f"skew {int(now - iat)}s")

    # --- resolve the KEK by kek_id -------------------------------------------
    kek_id = key_obj.get("kek_id")
    kek = None
    for epoch_id in candidate_epochs(now, epoch_seconds):
        candidate_id, kek_req, kek_res = derive_keys(client_ref, key_version, epoch_id)
        if candidate_id == kek_id:
            kek = kek_req if kek_direction == "req" else kek_res
            break
    if kek is None:
        raise CryptoError("CRY410", 400, f"kek_id {kek_id} outside the accepted epochs")

    # --- one time use: consume the jti before decrypting ---------------------
    if check_replay:
        _consume_nonce(client_ref, jti, iat)

    # --- unwrap the DEK --------------------------------------------------------
    try:
        dek = AESGCM(kek).decrypt(
            b64u_decode(key_obj["wiv"]),
            b64u_decode(key_obj["edek"]) + b64u_decode(key_obj["wtag"]),
            None,
        )
    except (InvalidTag, KeyError, ValueError) as exc:
        # One code for every failure below this line. Detail to CloudWatch only.
        raise CryptoError("CRY422", 400, f"DEK unwrap failed: {exc!r}") from exc

    # --- decrypt the payload, request_key as AAD -------------------------------
    try:
        blob = b64u_decode(request_value)
        if len(blob) < 12 + 16:
            raise ValueError("request_value too short")
        compressed = AESGCM(dek).decrypt(blob[:12], blob[12:], request_key.encode("ascii"))
    except (InvalidTag, ValueError) as exc:
        raise CryptoError("CRY422", 400, f"payload decrypt failed: {exc!r}") from exc

    # --- decompress with a hard ceiling ----------------------------------------
    decompressor = zlib.decompressobj(wbits=-15)
    plaintext = decompressor.decompress(compressed, MAX_PLAINTEXT_BYTES + 1)
    if len(plaintext) > MAX_PLAINTEXT_BYTES or decompressor.unconsumed_tail:
        raise CryptoError("CRY400", 400, "decompressed payload over 10 MB")

    try:
        return json.loads(plaintext)
    except ValueError as exc:
        raise CryptoError("CRY400", 400, f"plaintext is not JSON: {exc}") from exc


def seal_request(obj, request_key: bytes, kid: str, client_ref: str, path: str,
                 method: str = "POST") -> str:
    """Vendor side, kept here for tests and the sandbox. Returns request_value."""
    label = {
        "v": REQUEST_VERSION, "alg": REQUEST_ALG, "kid": kid,
        "cid": client_ref, "pth": path, "mtd": method,
        "iat": int(time.time()), "jti": uuid.uuid4().hex,
    }
    label_seg = b64u(json.dumps(label, sort_keys=True, separators=(",", ":")).encode())
    iv = os.urandom(12)
    sealed = AESGCM(request_key).encrypt(
        iv, json.dumps(obj, separators=(",", ":")).encode("utf-8"), label_seg.encode("ascii"))
    return ".".join([label_seg, b64u(iv), b64u(sealed[:-16]), b64u(sealed[-16:])])


def read_request_label(request_value: str) -> dict:
    """Split request_value and parse its label. No decryption. Safe to call first."""
    if not isinstance(request_value, str) or len(request_value) > MAX_FIELD_BYTES:
        raise CryptoError("CRY400", 400, "request_value missing or oversized")
    parts = request_value.split(".")
    if len(parts) != 4 or not all(parts[:2]) or not parts[3]:
        raise CryptoError("CRY400", 400, f"request_value has {len(parts)} parts, expected 4")
    try:
        label = json.loads(b64u_decode(parts[0]))
    except Exception as exc:
        raise CryptoError("CRY400", 400, f"unreadable label: {exc}") from exc
    if not isinstance(label, dict):
        raise CryptoError("CRY400", 400, "label is not an object")
    return label


def open_request(request_value: str, client_ref: str, key_version: int,
                 epoch_seconds: int, path: str, method: str, check_replay: bool = True):
    """Verify the label, consume the jti, decrypt. Returns the business object."""
    label = read_request_label(request_value)
    label_seg, iv_seg, ct_seg, tag_seg = request_value.split(".")

    if label.get("v") != REQUEST_VERSION:
        raise CryptoError("CRY400", 400, f"unsupported request version {label.get('v')}")
    if label.get("alg") != REQUEST_ALG:
        raise CryptoError("CRY401", 400, f"alg={label.get('alg')}")

    # --- binding -----------------------------------------------------------
    if label.get("cid") != client_ref:
        raise CryptoError("CRY412", 400, "cid does not match the caller")
    if label.get("pth") != path or label.get("mtd") != method:
        raise CryptoError("CRY412", 400, "pth or mtd does not match the endpoint")

    iat, jti = label.get("iat"), label.get("jti")
    if not isinstance(iat, int) or not isinstance(jti, str) or not jti:
        raise CryptoError("CRY400", 400, "iat or jti missing")

    now = time.time()
    if abs(now - iat) > MAX_SKEW_SECONDS:
        raise CryptoError("CRY413", 400, f"skew {int(now - iat)}s")

    # --- resolve the request key by kid ---------------------------------------
    kid = label.get("kid")
    key = None
    for epoch_id in candidate_epochs(now, epoch_seconds):
        candidate_kid, request_key, _ = derive_keys(client_ref, key_version, epoch_id)
        if candidate_kid == kid:
            key = request_key
            break
    if key is None:
        raise CryptoError("CRY410", 400, f"kid {kid} outside the accepted epochs")

    # --- one time use -----------------------------------------------------------
    if check_replay:
        _consume_nonce(client_ref, jti, iat)

    # --- decrypt, label as AAD --------------------------------------------------
    try:
        iv, ct, tag = b64u_decode(iv_seg), b64u_decode(ct_seg), b64u_decode(tag_seg)
        if len(iv) != 12 or len(tag) != 16:
            raise ValueError("iv must be 12 bytes and tag 16 bytes")
        plaintext = AESGCM(key).decrypt(iv, ct + tag, label_seg.encode("ascii"))
    except (InvalidTag, ValueError) as exc:
        # One code for every failure here. Detail to CloudWatch only.
        raise CryptoError("CRY422", 400, f"request decrypt failed: {exc!r}") from exc

    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise CryptoError("CRY400", 400, "request over 10 MB")
    try:
        return json.loads(plaintext)
    except ValueError as exc:
        raise CryptoError("CRY400", 400, f"plaintext is not JSON: {exc}") from exc


def _consume_nonce(client_ref: str, jti: str, iat: int) -> None:
    table = os.environ.get("PAYLOAD_NONCE_TABLE")
    if not table:
        raise CryptoError("CRY500", 500, "PAYLOAD_NONCE_TABLE not configured")

    try:
        _ddb.put_item(
            TableName=table,
            Item={
                "nonce_id": {"S": f"{client_ref}#{jti}"},
                "ttl_epoch": {"N": str(int(iat) + NONCE_TTL_SECONDS)},
            },
            ConditionExpression="attribute_not_exists(nonce_id)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise CryptoError("CRY409", 400, "duplicate jti, request_value already used") from exc
        # Throttled or unavailable. Fail closed, never skip the check quietly.
        raise CryptoError("CRY500", 500, f"nonce store unavailable: {exc}") from exc


# --------------------------------------------------------------------------
# Response envelope
# --------------------------------------------------------------------------

def _now_ist() -> str:
    return datetime.now(IST).isoformat()


def build_envelope(request_id, response_code=200, error_code="", error_message="",
                   message="Request Successfully processed", started_at=None):
    return {
        "request_id": request_id,
        "response_code": response_code,
        "response_error_code": error_code,
        "response_error_message": error_message,
        # perf_counter, not process_time. This is wall clock latency.
        "time_taken": round((time.perf_counter() - started_at) * 1000, 2) if started_at else 0.0,
        "timestamp": _now_ist(),
        "response_message": message,
    }


# --------------------------------------------------------------------------
# Authorizer context
# --------------------------------------------------------------------------

def _ctx_get(ctx, *names, default=None):
    for name in names:
        if name in ctx and ctx[name] not in (None, ""):
            return ctx[name]
    return default


def read_crypto_profile(event):
    """Pull the crypto profile the authorizer put into the request context."""
    ctx = event.get("context") or {}

    mode = _ctx_get(ctx, "crypto-mode", "crypto_mode")
    if mode is None:
        # No authorizer context at all, for example a direct Lambda invoke.
        # Never read an absent mode as "off".
        mode = os.environ.get("CRYPTO_DEFAULT_MODE", "required")

    return {
        "mode": mode,
        "client_ref": _ctx_get(ctx, "client-ref", "client_ref", default="unknown"),
        "key_version": int(_ctx_get(ctx, "key-version", "key_version", default=1)),
        "epoch_seconds": int(_ctx_get(ctx, "epoch-seconds", "epoch_seconds",
                                      default=DEFAULT_EPOCH_SECONDS)),
        "request_id": _ctx_get(ctx, "request-id", default=str(uuid.uuid4())),
        "path": _ctx_get(ctx, "resource-path", default=""),
        "method": _ctx_get(ctx, "http-method", default="POST"),
    }


# --------------------------------------------------------------------------
# The decorator
# --------------------------------------------------------------------------

def secure_payload(api_name):
    """Decrypt request_value on the way in, seal a response envelope on the way out.

        @secure_payload(api_name="employee")
        def lambda_handler(event, context):
            body = event["body-json"]        # already decrypted, plain dict
            ...
            return build_response(...)       # response_data sealed on exit
    """

    def outer(handler):
        @functools.wraps(handler)
        def inner(event, context):
            started_at = time.perf_counter()
            profile = read_crypto_profile(event)
            mode = profile["mode"]
            body = event.get("body-json") or {}
            encrypted_in = isinstance(body, dict) and (VALUE_FIELD in body or LEGACY_KEY_FIELD in body)

            if mode == "off" and encrypted_in:
                return _error(profile, "CRY426", 400, started_at,
                              "Encrypted payloads are not enabled for this client")
            if mode == "required" and not encrypted_in:
                return _error(profile, "CRY426", 400, started_at,
                              "This client must send request_value")

            # ---- inbound ------------------------------------------------
            if encrypted_in:
                try:
                    if VALUE_FIELD not in body:
                        raise CryptoError("CRY400", 400, "request_value is required")
                    extra = set(body) - {VALUE_FIELD}
                    if extra:
                        # Anything outside request_value is unauthenticated. Refuse
                        # it, including the retired v2.0 request_key field.
                        raise CryptoError("CRY400", 400, f"unexpected fields {sorted(extra)}")

                    event = dict(event)
                    event["_original_body"] = {
                        VALUE_FIELD: body[VALUE_FIELD],
                        "kid": read_request_label(body[VALUE_FIELD]).get("kid"),
                    }
                    event["body-json"] = open_request(
                        body[VALUE_FIELD],
                        client_ref=profile["client_ref"],
                        key_version=profile["key_version"],
                        epoch_seconds=profile["epoch_seconds"],
                        path=profile["path"],
                        method=profile["method"],
                    )
                except CryptoError as exc:
                    log.warning("%s rejected %s: %s", api_name, exc.code, exc.log_detail)
                    _metric("DecryptFailure", api_name, profile["client_ref"], exc.code)
                    return _error(profile, exc.code, exc.http_status, started_at)
            else:
                _metric("PlaintextAccepted", api_name, profile["client_ref"])

            # ---- the real handler ---------------------------------------
            result = handler(event, context)

            # ---- outbound -----------------------------------------------
            if not encrypted_in or not isinstance(result, dict):
                return result

            secret = {}
            for field in ("response_data", "page_info"):
                if field in result:
                    secret[field] = result.pop(field)

            try:
                epoch_id = epoch_id_for(time.time(), profile["epoch_seconds"])
                kek_id, _, kek_res = derive_keys(
                    profile["client_ref"], profile["key_version"], epoch_id
                )
                # A fresh DEK for the response too. Nothing from the request is reused.
                response_key, response_value = seal(
                    secret, kek_res, kek_id, profile["client_ref"],
                    profile["path"], profile["method"],
                )
                result["encrypted"] = True
                result[RESP_KEY_FIELD] = response_key
                result[RESP_VALUE_FIELD] = response_value
            except Exception as exc:
                # Never fall back to a plaintext response_data.
                log.error("%s response sealing failed: %s", api_name, exc)
                return _error(profile, "CRY500", 500, started_at)

            return result

        return inner

    return outer


def _error(profile, code, http_status, started_at, message=None):
    """Errors always go out in the clear. A broken key still has to read why."""
    envelope = build_envelope(
        profile["request_id"],
        response_code=http_status,
        error_code=code,
        error_message=message or CRY_MESSAGES.get(code, "Request rejected"),
        message="Request rejected",
        started_at=started_at,
    )
    envelope["encrypted"] = False
    envelope["response_data"] = {}
    return envelope


CRY_MESSAGES = {
    "CRY400": "Malformed encrypted payload",
    "CRY401": "Algorithm not permitted for this client",
    "CRY409": "request_value already used",
    "CRY410": "Key expired or unknown",
    "CRY412": "Payload binding mismatch",
    "CRY413": "Message timestamp outside the accepted window",
    "CRY422": "Payload could not be decrypted",
    "CRY426": "Encryption required for this client",
    "CRY500": "Platform crypto failure",
}


def _metric(name, api_name, client_ref, code=""):
    """Embedded metric format. CloudWatch turns this into a metric for free."""
    log.info(json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": "EmpowerCare/Crypto",
                # The empty set adds an overall total, which is what the
                # CloudWatch alarms watch. The first set is for drill-down.
                "Dimensions": [["api_name", "client_ref"], []],
                "Metrics": [{"Name": name}],
            }],
        },
        "api_name": api_name,
        "client_ref": client_ref,
        "cry_code": code,
        name: 1,
    }))
