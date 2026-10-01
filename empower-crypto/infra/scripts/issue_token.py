"""
Mints a SAMPLE bearer token for a seeded vendor. Prints only the token, so it
can be captured straight into a variable or pasted into Postman.

    TOKEN=$(python infra/scripts/issue_token.py --merchant MERCH_ENCRYPTED)

Sample stacks only. Real vendors get their tokens from ANZ.
"""

import argparse
import sys

from _stack import mint_token


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stack", default="empower-care-sample-crypto")
    ap.add_argument("--region", default="ap-south-1")
    ap.add_argument("--merchant", default="MERCH_ENCRYPTED")
    ap.add_argument("--ttl", type=int, default=3600, help="seconds, max 86400")
    args = ap.parse_args()

    if not 60 <= args.ttl <= 86400:
        sys.exit("--ttl must be between 60 and 86400 seconds")
    print(mint_token(args.stack, args.region, args.merchant, args.ttl))
    print(f"sample token for {args.merchant}, valid {args.ttl}s", file=sys.stderr)


if __name__ == "__main__":
    main()
