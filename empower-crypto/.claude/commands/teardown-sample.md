---
description: Delete the payload encryption sample stack from AWS
argument-hint: "[env name, default sample]"
---
Delete the sample stack for environment $1 ("sample" if empty). Follow CLAUDE.md "Rules for working in AWS".

1. Refuse if the environment name is "prod".
2. Run `aws sts get-caller-identity` and `aws cloudformation describe-stacks --stack-name empower-care-<env>-crypto --region ap-south-1 --query "Stacks[0].StackStatus"`. Show the account, the stack and its status. Ask the user to confirm deletion.
3. Run `ENV=<env> ./infra/scripts/destroy.sh`. The script asks for the stack name. Let the user type it. Do not pass AUTO_YES.
4. Confirm it is gone, and mention the KMS key has a 7 day pending deletion window.
