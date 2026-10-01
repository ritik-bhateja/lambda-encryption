---
description: Run every local check for the payload encryption project, no AWS needed
---
Run, in order, and report a one line result for each:

1. `pytest tests/ -q`
2. Start `python local_gateway.py` in the background, wait for `curl -s localhost:8080/health`, then `python client/demo.py`.
3. If `newman` is installed: `newman run postman/EmpowerCare_Payload_Encryption.postman_collection.json -e postman/local.postman_environment.json`.
4. `./infra/scripts/build_layer.sh`, then `python3 tests/run_aws_emulation.py` if python3.12 with flask, moto and airspeed is available.
5. `cfn-lint infra/template.yaml` if cfn-lint is installed.

Stop the sandbox afterwards. If anything fails, show the failing check and the relevant log lines, then propose a fix. Do not change the tests to make them pass.
