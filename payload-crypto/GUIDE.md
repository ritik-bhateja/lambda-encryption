# Adding payload encryption to an API

`payload_crypto` is a Lambda layer. It decrypts the vendor's request before your
handler runs and encrypts the reply after it returns. **Handler logic does not
change.** Each API needs one import, one decorator line and some config.

```
vendor ──► X-Vendor-Id: ACME
           {"request_key": "label.iv.ciphertext.tag"}
                │
        @secure_api()  ── picks ACME's key from Secrets Manager (cached 5 min)
                │         checks label, blocks replays, decrypts
                ▼
        your handler      sees plain JSON exactly where it always did
                │
        @secure_api()  ── encrypts whatever the handler returned
                ▼
vendor ◄── {"response_key": "...", "response_value": "..."}
```

There are 36 vendors, and each has its own AES-256 key in Secrets Manager at
`payload-keys/<VENDOR>`. The vendor holds a copy of that key.

---

## 1. One-time setup (per AWS account and region)

Done once, not per API.

```bash
cd payload-crypto
./scripts/build_layer.sh                                   # builds .build/layer
sam deploy --template-file infra/shared.yaml --stack-name payload-crypto-dev \
  --region ap-south-1 --capabilities CAPABILITY_NAMED_IAM --resolve-s3 \
  --parameter-overrides Env=dev
```

This creates the **layer**, a **replay table** (DynamoDB, on demand) and an **IAM
policy** that every encrypted API attaches. The outputs are exported as
`payload-crypto-dev-layer`, `-nonce-table`, `-policy` and `-secret-template`.

Create the vendor keys. The script never prints a key:

```bash
python scripts/vendor_key.py create ACME GLOBEX INITECH ...   # all 36 in one go
```

Each secret costs about USD 0.40 a month, so 36 vendors cost about USD 14.40 a month.

---

## 2. Per API: what to change and where (50+ times)

### 2a. Handler file: two lines

```python
import json
from payload_crypto import secure_api          # ← add

@secure_api()                                  # ← add
def lambda_handler(event, context):
    body = json.loads(event["body"])           #   unchanged: already decrypted
    ...                                        #   unchanged
    return {"statusCode": 200, "body": json.dumps(result)}   # unchanged: encrypted on exit
```

That's all the code change. The decorator:

| Your API uses | The handler reads | The handler returns | What the decorator does |
|---|---|---|---|
| HTTP API, REST proxy, function URL | `event["body"]` (string) | `{"statusCode", "headers", "body"}` | Replaces `event["body"]` with the decrypted JSON string. Encrypts `body`, keeping `statusCode` and your headers. |
| REST with a mapping template (`type: aws`, like Empower) | `event["body-json"]` (dict) | a dict | Replaces `event["body-json"]` with the decrypted dict. Encrypts the whole dict. |

It detects which case applies. Use `@secure_api(plain_fields=("response_code",))` on
mapping-template APIs whose response template maps `response_code` to the HTTP
status, so that one field stays readable next to the encrypted pair.

### 2b. Template: layer, environment, policy

```yaml
  OrdersFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.lambda_handler
      Runtime: python3.12                 # layer is built for 3.12 x86_64
      Architectures: [x86_64]
      Layers:
        - !ImportValue payload-crypto-dev-layer                                     # ← add
      Environment:
        Variables:
          PAYLOAD_KEY_SECRET_TEMPLATE: !ImportValue payload-crypto-dev-secret-template   # ← add
          PAYLOAD_NONCE_TABLE: !ImportValue payload-crypto-dev-nonce-table            # ← add
      Policies:
        - !ImportValue payload-crypto-dev-policy                                    # ← add
```

A `Globals: Function:` block can set `Layers` and `Environment` once for every
function in a template.

### 2c. API Gateway: usually nothing

- **HTTP API, REST proxy:** nothing. Headers already reach the Lambda.
- **REST with a mapping template:** nothing if the template already copies
  headers into `params.header`, as `empower-crypto/infra/mapping_template.vtl`
  does. If yours doesn't, add
  `"params": {"header": {"X-Vendor-Id": "$util.escapeJavaScript($input.params('X-Vendor-Id'))"}}`.
- If CORS is enabled, add `X-Vendor-Id` to the allowed headers.

### 2d. Check each API before calling it done

```bash
pytest                                              # your existing tests + a round trip
sam deploy ...
python vendor/vendor_client.py https://<api>/<path> '{"sample": "body"}'   # VENDOR_ID + VENDOR_KEY_HEX set
```

Expected result: `200` plus your normal response. Plain JSON must get `400 CRY426`,
and the same request sent twice must get `400 CRY409`.

**Per-API checklist:** ☐ import + decorator ☐ layer ☐ 2 env vars ☐ policy ☐
(mapping template only) `plain_fields` if status comes from `response_code`
☐ CORS header ☐ vendor client round trip ☐ plain JSON refused

---

## 3. What the vendor does

1. Send the header `X-Vendor-Id: <VENDOR>` on every call.
2. Build the body as `{"request_key": "<label>.<iv>.<ciphertext>.<tag>"}`, all base64url:
   - `label` = JSON `{"v":1,"alg":"A256GCM","kid":"ACME-v1","cid":"ACME","pth":"/orders","mtd":"POST","iat":<unix seconds>,"jti":"<unique>"}`
   - AES-256-GCM with their key, a new 12-byte `iv` each time, and the base64url label string as the AAD.
   - `pth` is the API path without the stage. `iat` must be within 5 minutes of the server clock, and `jti` must never repeat.
   - GET, HEAD and DELETE with no body: send no body.
3. Read the reply:
   - Decode `response_key` (base64url JSON). Unwrap the DEK: AES-256-GCM with their key using `wiv`, `edek` and `wtag`, with no AAD.
   - Decrypt `response_value` = `iv(12) | ciphertext | tag(16)` with the DEK, using the `response_key` string as the AAD.
   - Raw-inflate (deflate with no zlib header), then parse the JSON.

They get this as working code: `vendor/vendor_client.py` (Python), and for
Postman `postman/payload_crypto.postman.js`. Paste it into both the Pre-request
and Post-response tabs, then set the variables `vendor_id` and `vendor_key_hex`.

---

## 4. Errors (always in the clear, never with detail)

| Code | HTTP | Meaning | Usual cause |
|---|---|---|---|
| CRY400 | 400 | Malformed | Missing `X-Vendor-Id`, 3-part value, extra field beside `request_key` |
| CRY401 | 400 | Algorithm not permitted | `alg` isn't `A256GCM` |
| CRY409 | 400 | Already used | Same `jti` sent twice (retry with a new seal) |
| CRY410 | 400 | Key unknown | Unknown vendor, or `kid` isn't the current or previous key |
| CRY412 | 400 | Binding mismatch | Header vendor ≠ label `cid`, or wrong `pth`/`mtd` |
| CRY413 | 400 | Timestamp out of window | Vendor clock off by more than 5 minutes |
| CRY422 | 400 | Could not decrypt | Wrong key, or data changed in transit |
| CRY426 | 400 | Encryption required | Plain JSON sent |
| CRY500 | 500 | Platform crypto failure | Secrets Manager or DynamoDB unavailable, or a malformed secret. Check CloudWatch |

The detail goes to CloudWatch as `payload_crypto rejected <code>: <detail>`.

---

## 5. Rotating a vendor key

```bash
python scripts/vendor_key.py rotate ACME            # ACME-v2 is live, ACME-v1 still accepted
# hand the vendor the new key; they switch kid to ACME-v2
python scripts/vendor_key.py finish-rotation ACME   # ACME-v1 no longer accepted
```

Replies are always encrypted with the newest key. Lambdas pick up a change
within 5 minutes (`PAYLOAD_KEY_CACHE_SECONDS`).

---

## 6. Rules

- **The header picks the key; it is not authentication.** Someone who names another
  vendor can't build a valid request or read the reply, but keep your
  authorizer in front of every API.
- Keys are never put in `event`, never logged and never returned. Never read or
  print a secret value to debug. Use CloudWatch detail and the CRY code.
- Optional: set `PAYLOAD_ALLOWED_VENDORS=ACME,GLOBEX,...` to refuse unknown names
  before any AWS call.
- Don't catch and re-encode the body before the decorator runs. The label is
  authenticated byte for byte.
- Advanced use: `@vendor_keys` and `@encrypted_payload(...)` are the two halves of
  `@secure_api()`. `current_vendor_keys()` returns the active vendor inside a call.
  Most APIs only need `@secure_api()`.

## 7. Settings

| Variable | Default | |
|---|---|---|
| `PAYLOAD_KEY_SECRET_TEMPLATE` | `payload-keys/{vendor}` | Secret name per vendor |
| `PAYLOAD_NONCE_TABLE` | (required) | Replay table |
| `PAYLOAD_VENDOR_HEADER` | `X-Vendor-Id` | Header that names the vendor |
| `PAYLOAD_ALLOWED_VENDORS` | (none) | Optional comma list |
| `PAYLOAD_KEY_CACHE_SECONDS` | `300` | Key cache per Lambda container |

Worked example: `../hello/` (`src/app.py` is a plain handler with `@secure_api()`).
