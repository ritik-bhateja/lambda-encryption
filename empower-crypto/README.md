# Empower Care API payload encryption, runnable example

Design v3.0. Requests carry one field, encrypted directly. Responses carry two
fields, a one-time DEK locked with a KEK, unchanged from v2.0.

```json
POST /employee
{ "request_value": "<label>.<iv>.<ciphertext>.<tag>" }

200 OK
{ "request_id": "...", "response_code": 200, "encrypted": true,
  "response_key": "eyJhbGciOi...", "response_value": "Tq8mZ..." }
```

## The terms in plain words

| Term | Plain meaning |
| --- | --- |
| **Request encryption key** | Shared with the vendor, fetched once a day. The vendor locks every request with it directly |
| **request_value** | `label.iv.ciphertext.tag`. A readable label, the locked JSON, and a tamper seal over both |
| **Label** | `kid`, `cid`, `pth`, `mtd`, `iat`, `jti`: which key, who, which API, when, serial number. Readable, not editable |
| **KEK** (`kek_response`) | Shared with the vendor, fetched with the request key. Only ever locks a reply DEK |
| **DEK** | New for every reply. Locks the reply data |
| **response_key** | The reply DEK locked with `kek_response`, plus a label |
| **response_value** | The reply, locked with the DEK |

The label is the AAD of the request, so editing it or splicing it onto other
data breaks the seal. The `jti` is accepted once, so a replayed request is
rejected. Each request uses a fresh random 12 byte iv. AES-GCM is safe up to
about 4.29 billion requests per key, and keys change every day or every hour.

Design: `docs/EmpowerCare_API_Payload_Encryption_Design_v3.docx`.
Worked example with real values: `docs/EmpowerCare_API_Payload_Encryption_Sample_Case_v3.docx`.
Diagrams: `docs/flow.png`, `docs/anatomy.png`.

## Run it

```bash
docker compose up --build                # sandbox on http://localhost:8080
docker compose --profile test up demo    # 22 end to end checks
```

Without Docker:

```bash
pip install -r requirements.txt
python local_gateway.py                  # terminal 1
python client/demo.py                    # terminal 2, 22 end to end checks
python client/sample_case.py             # regenerates docs/sample_case.json
pytest tests/ -v                         # 36 unit tests, no server needed
```

## Postman

Import `postman/EmpowerCare_Payload_Encryption.postman_collection.json` and
`postman/local.postman_environment.json`, then run the collection top to
bottom. 16 requests, 34 assertions.

```bash
newman run postman/EmpowerCare_Payload_Encryption.postman_collection.json \
  -e postman/local.postman_environment.json
```

**Postman cannot do AES-GCM itself.** Its sandbox ships crypto-js, which has no
GCM mode. The pre-request scripts call two sandbox-only helpers,
`POST /dev/seal` (plays the vendor, builds a request_value) and
`POST /dev/open` (plays the vendor, opens response_key and response_value).
Those helpers live in `local_gateway.py` and are never deployed. A real vendor
does the same work locally, see `seal_request()` and `open_response()` in
`client/empower_client.py`.

## Layout

```
layer/python/empower_crypto.py     shared layer: open_request, seal replies, label checks, nonce, decorator
lambdas/cryptokeys/handler.py      POST /crypto/session-key, returns request_encryption_key and kek_response
lambdas/employee_api/handler.py    a business API, the only change is @secure_payload
lambdas/request_validator/         authorizer, adds client_ref, crypto_mode, key_version, epoch_seconds
client/empower_client.py           vendor reference client, about 30 lines of crypto
client/demo.py                     22 end to end checks
client/sample_case.py              traces one request and captures every value
local_gateway.py                   sandbox only: API Gateway, ANZ and Hasura mocks
docs/                              flow and anatomy diagrams, sample_case.json
infra/mapping_template.vtl         production reference: existing VTL plus four context values
infra/template.yaml                the AWS sample stack, complete
infra/scripts/                     build_layer, deploy, seed, issue_token, smoke_test, destroy
lambdas/sample_employee/           sample business Lambda for the AWS stack
lambdas/dev_helpers/               /dev/seal and /dev/open for Postman, off by default
tests/aws_emulator.py              API Gateway emulator driven by infra/template.yaml
CLAUDE.md, .claude/commands/       for Claude Code: rules, /deploy-sample, /test-local, /teardown-sample
postman/                           collection, environment, and the script that builds them
tests/test_roundtrip.py            27 crypto unit tests
tests/test_validator.py            9 authorizer unit tests
```

## Sandbox vendors

| merchant_id | crypto_mode | KEK lifetime |
| --- | --- | --- |
| `MERCH_ENCRYPTED` | `required` | 24 hours |
| `MERCH_OPTIONAL` | `optional` | 24 hours |
| `MERCH_PLAIN` | `off` | 24 hours |
| `MERCH_HOURLY` | `required` | 1 hour |

## Error codes

| Code | Meaning |
| --- | --- |
| `CRY400` | request_value missing or not four parts, an extra field such as the old request_key, or over 10 MB |
| `CRY401` | alg in the label is not A256GCM |
| `CRY409` | request_value already used |
| `CRY410` | kid expired, unknown or revoked. Fetch today's keys |
| `CRY412` | Label does not match the vendor, API or method |
| `CRY413` | Message time more than 5 minutes from platform time |
| `CRY422` | Could not unlock. One code for every unlock failure, on purpose |
| `CRY426` | Plain JSON sent while encryption is required |
| `CRY500` | Platform side failure. Never falls back to plain JSON |

## The one line that changes in a business Lambda

```python
@secure_payload(api_name="employee")
def lambda_handler(event, context):
    body = event["body-json"]      # request_value already unlocked, same shape as today
    ...
    return build_response(...)     # response_data locked on the way out
```

## Deploy to AWS

A complete sample stack in `infra/template.yaml`: API Gateway REST API with the
request validator as a REQUEST authorizer, the crypto layer, the key service,
a sample Employee Lambda, the nonce store, the master seed under its own KMS
key, and two alarms. Use a **non-production** account.

```bash
python3 -m pip install -r infra/requirements-deploy.txt   # plus AWS CLI v2 and SAM CLI
./infra/scripts/deploy.sh                                  # region ap-south-1 by default
```

`deploy.sh` shows the account it is about to change and asks you to type the
account id. Then it builds the layer, deploys, seeds four sample vendors, and
runs `infra/scripts/smoke_test.py` against the live API: 23 checks, 25 with
dev helpers on. Tear down with `./infra/scripts/destroy.sh`.

**With Claude Code.** Open this folder in Claude Code and run
`/deploy-sample`, `/test-local` or `/teardown-sample`. `CLAUDE.md` gives it
the layout, the commands and the safety rules: non-production only, never
`ENV=prod`, confirm the account, never print key material.

**Tokens.** The sample stack runs the authorizer in `AUTH_MODE=sample`: HS256
tokens signed with a secret in Secrets Manager, so only someone with access to
the account can mint one.

```bash
TOKEN=$(python3 infra/scripts/issue_token.py --merchant MERCH_ENCRYPTED)
```

For real vendors, deploy with `AuthMode=anz` and `AnzValidateUrl` set. With
`anz` and no URL, every call is denied on purpose.

**Postman against AWS.** Deploy with `DEV_HELPERS=true`, which adds a separate
API with `/dev/seal` and `/dev/open`. Import
`postman/EmpowerCare_AWS_Sample.postman_collection.json` and
`postman/aws.postman_environment.json`, then fill in `api_url`, `dev_url`,
`token` and `plain_token`. 15 requests, 38 assertions.

**Test before you deploy a change.** `tests/run_aws_emulation.py` runs the same
smoke test against an emulator built from `infra/template.yaml`: the real VTL
templates, the real handlers and the real Linux layer under Python 3.12. It
catches a broken mapping template or a misnamed environment variable without
spending a deploy.

**Moving this into the existing 22 APIs** is a different job from the sample
stack: attach the layer pinned to an exact version, add the decorator, add the
four context values to each mapping template (`infra/mapping_template.vtl`),
backfill keyrolemapping with `crypto_mode: off`, then switch vendors one at a
time.

## Note on KEK change time

Epochs count from UTC midnight, so a 24 hour KEK changes at 05:30 IST. To move
it, add a fixed offset in `epoch_id_for()` in the layer and in the key service.
