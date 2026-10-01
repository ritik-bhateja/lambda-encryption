#!/usr/bin/env bash
# Deletes the SAMPLE stack and everything in it.
#
#   ./infra/scripts/destroy.sh
#
# The KMS key enters a 7 day pending deletion window, which is AWS's minimum.
# The secrets enter their recovery window. Neither blocks a redeploy, because
# the template never gives them fixed names.
set -euo pipefail

ENV="${ENV:-sample}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-south-1}}"
STACK="empower-care-${ENV}-crypto"

if [ "$ENV" = "prod" ]; then
  echo "Refusing: ENV=prod is never a sample stack." >&2
  exit 1
fi

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
echo "About to DELETE stack $STACK in account $ACCOUNT, region $REGION."

if [ "${AUTO_YES:-false}" != "true" ]; then
  read -r -p "Type the stack name to delete it: " CONFIRM
  [ "$CONFIRM" = "$STACK" ] || { echo "Stack name did not match. Nothing deleted."; exit 1; }
fi

sam delete --stack-name "$STACK" --region "$REGION" --no-prompts
echo "Deleted $STACK. The KMS key is scheduled for deletion in 7 days."
