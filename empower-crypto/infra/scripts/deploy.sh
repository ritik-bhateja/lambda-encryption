#!/usr/bin/env bash
# Deploys the SAMPLE stack, seeds four vendors, then runs the smoke test.
#
#   ./infra/scripts/deploy.sh
#   ENV=dev2 DEV_HELPERS=true ./infra/scripts/deploy.sh      # second copy, Postman helpers on
#
# Needs: AWS CLI v2, SAM CLI, Python 3.10+ with infra/requirements-deploy.txt,
# and AWS credentials for a NON-PRODUCTION account.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ENV="${ENV:-sample}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-ap-south-1}}"
STACK="empower-care-${ENV}-crypto"
DEV_HELPERS="${DEV_HELPERS:-false}"
PYTHON="${PYTHON:-python3}"

if [ "$ENV" = "prod" ]; then
  echo "Refusing: this is the sample stack. It must never be deployed with ENV=prod." >&2
  exit 1
fi

for tool in aws sam "$PYTHON"; do
  command -v "$tool" >/dev/null || { echo "Missing: $tool" >&2; exit 1; }
done

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
CALLER="$(aws sts get-caller-identity --query Arn --output text)"

cat <<EOF

  Stack        $STACK
  Account      $ACCOUNT
  Caller       $CALLER
  Region       $REGION
  Dev helpers  $DEV_HELPERS

  Creates: API Gateway, 4 Lambda functions, 1 layer, 4 DynamoDB tables,
  1 KMS key (about USD 1 a month), 2 secrets, 2 CloudWatch alarms.

EOF

if [ "${AUTO_YES:-false}" != "true" ]; then
  read -r -p "Type the account id to deploy into it: " CONFIRM
  [ "$CONFIRM" = "$ACCOUNT" ] || { echo "Account id did not match. Nothing deployed."; exit 1; }
fi

echo "== building layer"
"$ROOT/infra/scripts/build_layer.sh"

echo "== deploying"
sam deploy \
  --template-file infra/template.yaml \
  --stack-name "$STACK" \
  --region "$REGION" \
  --capabilities CAPABILITY_IAM \
  --resolve-s3 \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  --parameter-overrides "Env=$ENV" "AuthMode=sample" "EnableDevHelpers=$DEV_HELPERS" \
  --tags "project=empower-care" "purpose=payload-encryption-sample"

echo "== seeding sample vendors"
"$PYTHON" infra/scripts/seed.py --stack "$STACK" --region "$REGION"

echo "== smoke test"
"$PYTHON" infra/scripts/smoke_test.py --stack "$STACK" --region "$REGION"

API_URL="$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text)"
echo
echo "Deployed. API: $API_URL"
echo "Token:        python3 infra/scripts/issue_token.py --stack $STACK --region $REGION"
echo "Tear down:    ENV=$ENV ./infra/scripts/destroy.sh"
