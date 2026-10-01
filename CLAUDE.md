# Empower Care payload encryption

Implementation of the payload encryption design v3.0 for the Empower Care API
engine, plus a self-contained AWS sample stack.

- Requests carry one field, `request_value = label.iv.ciphertext.tag`, encrypted
  directly with the vendor's request encryption key (AES-256-GCM, label as AAD).
- Responses carry `response_key` + `response_value`: a new DEK per reply, locked
  with `kek_response`.
- Keys are derived per vendor per epoch from one master seed. Nothing is stored.
- Design and worked example: `docs/*.docx`. Diagrams: `docs/flow.png`, `docs/anatomy.png`.

## Layout

```
layer/python/empower_crypto.py      the shared layer: open_request, seal replies, labels, nonce, @secure_payload
lambdas/request_validator/          REQUEST authorizer. AUTH_MODE=anz (real) or sample (HS256 tokens)
lambdas/cryptokeys/                 POST /crypto/session-key
lambdas/sample_employee/            sample business Lambda, fixture data, one decorator line
lambdas/dev_helpers/                /dev/seal and /dev/open for Postman. Sample stacks only, off by default
lambdas/employee_api/               production-shaped Employee API (Hasura). Reference, not deployed by the sample stack
infra/template.yaml                 the SAM stack
infra/scripts/                      build_layer, deploy, seed, issue_token, smoke_test, destroy
client/                             vendor reference client, sandbox demo, sample case generator
local_gateway.py                    local sandbox (moto + mocks), no AWS needed
tests/                              unit tests, and an API Gateway emulator driven by infra/template.yaml
postman/                            sandbox collection, and the AWS sample stack collection
```

## Commands

```bash
# local, no AWS
pip install -r requirements.txt
pytest tests/ -q                                  # 36 unit tests
python local_gateway.py &  python client/demo.py  # sandbox, 22 end to end checks

# before any deploy of a template or handler change
./infra/scripts/build_layer.sh
python3 tests/run_aws_emulation.py                # smoke test against the template, needs python3.12 with flask, moto, airspeed

# AWS, non-production account only
python3 -m pip install -r infra/requirements-deploy.txt
./infra/scripts/deploy.sh                         # asks for the account id before it changes anything
ENV=sample DEV_HELPERS=true ./infra/scripts/deploy.sh   # with Postman helpers
python3 infra/scripts/issue_token.py --merchant MERCH_ENCRYPTED
python3 infra/scripts/smoke_test.py --stack empower-care-sample-crypto --region ap-south-1
./infra/scripts/destroy.sh                        # asks for the stack name before deleting
```

## Rules for working in AWS. Follow all of them.

1. **Non-production accounts only.** Before any deploy or delete, run
   `aws sts get-caller-identity` and show the account id and caller ARN to the
   human. Get an explicit yes for that account. Do not assume.
2. **Never `ENV=prod`.** Never remove the `NeverProd` rule in the template or
   the prod checks in the scripts. This stack uses sample tokens and must never
   carry real vendor traffic.
3. **Do not pass `AUTO_YES=true`** unless the human asks for it in this session.
   The typed confirmation is the safety net.
4. **Never print, log or commit key material**: `request_encryption_key`,
   `kek_response`, the seed secret, the sample token secret. Do not read
   secret values with the AWS CLI. Tokens from `issue_token.py` are sample
   tokens that expire in an hour and may be shown.
5. **Keep `DEV_HELPERS` off** unless the human wants to run Postman. It is a
   seal and open oracle for the caller's own keys.
6. **Test before deploying changes**: `pytest tests/ -q`, then
   `./infra/scripts/build_layer.sh`, then `python3 tests/run_aws_emulation.py`.
   If the emulator fails, the deploy would too.
7. Default region `ap-south-1` unless the human says otherwise.
8. Say what a deploy creates and costs before running it: API Gateway, 4 Lambda
   functions, a layer, 4 DynamoDB tables on demand, a KMS key (about USD 1 a
   month), 2 secrets (about USD 0.40 each a month), 2 alarms.

## Adding encryption to another API

1. Copy `lambdas/sample_employee/` as the pattern. The handler only needs
   `@secure_payload(api_name="...")` and reads `event["body-json"]` as a dict.
2. In `infra/template.yaml`, copy the `/employee` path block (keep its
   request and response templates exactly), add the function with the same
   policies as `SampleEmployeeFunction`, and add a `AWS::Lambda::Permission`.
3. Vendors put the API path, without the stage, in the label's `pth`.
4. Run the three test steps in rule 6.

## Behaviour worth knowing

- Integrations are non-proxy (`type: aws`) with VTL, like the existing gateway.
  The response template copies `response_code` into the HTTP status, so CRY
  errors are real 400s and EMP404 stays a 200.
- Headers are not copied into the Lambda event, so the bearer token never
  reaches business code or its logs.
- Authorizer caching is off (TTL 0), like production.
- 24 hour keys change at 05:30 IST, because epochs count from UTC midnight.
- `sam deploy` packages source folders directly. There is no `sam build` step:
  the functions have no dependencies and the layer is prebuilt by
  `build_layer.sh`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| 403 on every call | Run `seed.py`. Or the token expired, mint a new one |
| 500 on every call | `sam logs -n RequestValidatorFunction --stack-name <stack> --region <region> --tail` |
| CRY410 | Keys rolled or `key_version` changed. Fetch keys again |
| CRY422 on every request | Wrong key, or the label was re-encoded after sealing |
| `sam deploy` complains about `.build/layer` | Run `./infra/scripts/build_layer.sh` first |
| 415 | The request is not `Content-Type: application/json` |
