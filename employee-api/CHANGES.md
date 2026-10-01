# employee_api: adding payload encryption

## 1. Code change (the whole diff)

```diff
 from src import employee_by_employeecode, get_auth_role_by_token, restructure_employee_response
+from payload_crypto import secure_api
 ...
+@secure_api(plain_fields=("response_code",))
 def lambda_handler(event, context):
```

Nothing else in `lambda_function.py` or `src/` changes.

- **In:** the vendor sends `X-Vendor-Id: ACME` + `{"request_key": "..."}`. The decorator decrypts it
  into `event["body-json"]`, so `validate_request` and `get_hasura_response` see
  `{"employee_code": "..."}` exactly as today.
- **Out:** `output` (request_id, codes, messages, time, `response_data`) is encrypted into
  `response_key` + `response_value`. `response_code` is copied out in the clear because the
  API Gateway response template sets the HTTP status from it (`$root.response_code`).

What the vendor receives:

```json
{"response_code": 200, "response_key": "eyJ...", "response_value": "k3F..."}
```

Decrypted, `response_value` is today's `output` object, unchanged.

## 2. Lambda configuration (prod: run these yourself, after dev and UAT)

| Setting | Value |
|---|---|
| Runtime | **python3.12, x86_64**, required by the layer. Check the current runtime first |
| Layers | add `payload-crypto-<env>` (from the shared stack). Lambda allows 5 layers and 250 MB total |
| Env var | `PAYLOAD_KEY_SECRET_TEMPLATE=payload-keys/{vendor}` |
| Env var | `PAYLOAD_NONCE_TABLE=payload-crypto-nonce-<env>` |
| IAM | attach the `payload-crypto-<env>` managed policy to the function role |

```bash
# check
aws lambda get-function-configuration --function-name <employee-fn> \
  --query '[Runtime,Architectures,Layers[].Arn,Environment.Variables]'

# update: pass ALL existing layers and env vars too, these calls replace the lists
aws lambda update-function-configuration --function-name <employee-fn> \
  --layers <existing-layer-arns...> <payload-crypto-layer-arn> \
  --environment 'Variables={<existing vars...>,PAYLOAD_KEY_SECRET_TEMPLATE=payload-keys/{vendor},PAYLOAD_NONCE_TABLE=payload-crypto-nonce-prod}'
aws iam attach-role-policy --role-name <employee-fn-role> --policy-arn <payload-crypto-policy-arn>
```

## 3. API Gateway

- **Request template:** no change. It already copies every header into `params.header`, where the
  decorator reads `X-Vendor-Id`.
- **Response template:** no change. `response_code` is still at the top level.
- **CORS** (if enabled): add `X-Vendor-Id` to the allowed headers.
- Redeploy the stage only if you changed CORS.

## 4. Verified

`tests/test_employee_encrypted.py` runs this exact handler on Python 3.12, with Hasura, the
secret cache, the token helpers and the logging Lambda stubbed. 9 tests pass:

| Case | HTTP (via response_code) | Reply |
|---|---|---|
| Employee found | 200 | encrypted; opens to today's `output` with `employee_information_master` |
| Employee not found | 200 | encrypted; `response_error_code` EMP404 |
| Missing `employee_code` | 400 | encrypted; "Functional error…" |
| Hasura error | 500 | encrypted; "Something went wrong" |
| Plain JSON / no header / unknown vendor | 400 | plain CRY426 / CRY400 / CRY410; Hasura and logging never called |
| Same request twice | 400 | CRY409 |

## 5. Decide before production

1. **The API logging Lambda still gets plaintext.** `log_data` runs inside the handler, so
   `empower_care_prod_lambda_apilogging` receives the decrypted request and the unencrypted
   `output`, as it does today. Options: keep it (internal logs, same as now); mask
   `request_body`/`response_body` in `log_data`; or log only metadata. This is a policy call.
2. **Rejected requests are not sent to the logging Lambda.** CRY4xx rejections stop before the
   handler runs. They are in CloudWatch (`payload_crypto rejected <code>: <detail>`).
3. **Vendors of this API must be onboarded first.** Plain JSON is refused (CRY426) as soon as the
   decorator is live.
4. **Optional hardening:** the token already carries the Cognito `client_id`. A vendor-to-client_id
   map would let the platform reject an `X-Vendor-Id` that does not belong to the token.

## 6. Found while testing, not part of this change

`lambda_handler` calls `asyncio.get_event_loop()` with no running loop. Python 3.12 allows this
with a DeprecationWarning; Python 3.14 raises, and the API logging call would be skipped silently
(the error is caught). Replace the `gather` / `get_event_loop` / `run_until_complete` lines with
`asyncio.run(log_data(...))` before the next runtime upgrade.
