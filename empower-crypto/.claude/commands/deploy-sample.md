---
description: Deploy the payload encryption sample stack to a non-production AWS account and smoke test it
argument-hint: "[env name, default sample] [dev-helpers: true|false]"
---
Deploy the Empower Care payload encryption sample stack. Follow every rule in CLAUDE.md under "Rules for working in AWS".

Environment name: $1 (use "sample" if empty). Dev helpers: $2 (use "false" if empty).

1. Refuse if the environment name is "prod".
2. Run `aws sts get-caller-identity`. Show the account id, caller ARN and region (ap-south-1 unless the user said otherwise). State what the stack creates and roughly costs. Ask the user to confirm this account. Stop if they do not.
3. Run `pytest tests/ -q`. Stop on any failure.
4. Run `./infra/scripts/build_layer.sh`.
5. If python3.12 with flask, moto and airspeed is available, run `python3 tests/run_aws_emulation.py` and stop on failure. If not, say it was skipped.
6. Run `ENV=<env> DEV_HELPERS=<dev-helpers> ./infra/scripts/deploy.sh`. The script asks for the account id. Let the user type it. Do not pass AUTO_YES.
7. Report the API URL, the smoke test result, and the commands for a token and for teardown. Never print key material.
