"""Create or rotate a vendor's payload key in Secrets Manager. Never prints a key.

    python scripts/vendor_key.py create ACME
    python scripts/vendor_key.py create ACME GLOBEX INITECH          # several at once
    python scripts/vendor_key.py rotate ACME                         # new key, old one kept as previous
    python scripts/vendor_key.py finish-rotation ACME                # drop the previous key

Options: --template payload-keys/{vendor}  --region ap-south-1  --tag Owner=team

Secret value: {"key_id": "ACME-v1", "key_hex": "<64 hex>"} and, during a
rotation, "previous_key_id" / "previous_key_hex". Hand the vendor its key over
a secure channel. Lambdas pick up a change within PAYLOAD_KEY_CACHE_SECONDS.
"""

import argparse
import json
import os
import re
import sys

import boto3

VENDOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _next_id(vendor, key_id):
    m = re.match(rf"^{re.escape(vendor)}-v(\d+)$", key_id or "")
    return f"{vendor}-v{int(m.group(1)) + 1 if m else 2}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["create", "rotate", "finish-rotation"])
    ap.add_argument("vendors", nargs="+")
    ap.add_argument("--template", default=os.environ.get("PAYLOAD_KEY_SECRET_TEMPLATE", "payload-keys/{vendor}"))
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "ap-south-1"))
    ap.add_argument("--tag", action="append", default=[], help="Key=Value, repeatable")
    args = ap.parse_args()

    sm = boto3.client("secretsmanager", region_name=args.region)
    tags = [{"Key": k, "Value": v} for k, v in (t.split("=", 1) for t in args.tag)]

    for vendor in args.vendors:
        if not VENDOR_RE.match(vendor):
            sys.exit(f"bad vendor name {vendor!r}: letters, digits, _ and - only")
        name = args.template.format(vendor=vendor)

        if args.action == "create":
            value = {"key_id": f"{vendor}-v1", "key_hex": os.urandom(32).hex()}
            arn = sm.create_secret(Name=name, SecretString=json.dumps(value),
                                   Description=f"payload_crypto key for {vendor}", Tags=tags)["ARN"]
            print(f"created {name}  key_id={value['key_id']}  {arn}")
            continue

        current = json.loads(sm.get_secret_value(SecretId=name)["SecretString"])
        current_id = current.get("key_id") or f"{vendor}-v1"
        if args.action == "rotate":
            value = {"key_id": _next_id(vendor, current_id), "key_hex": os.urandom(32).hex(),
                     "previous_key_id": current_id, "previous_key_hex": current["key_hex"]}
        else:
            value = {"key_id": current_id, "key_hex": current["key_hex"]}
        sm.put_secret_value(SecretId=name, SecretString=json.dumps(value))
        print(f"{args.action} {name}  key_id={value['key_id']}"
              + (f"  previous={value['previous_key_id']}" if "previous_key_id" in value else ""))


if __name__ == "__main__":
    main()
