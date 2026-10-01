"""
Writes the four sample vendors into the stack's keyrolemapping table.

    python infra/scripts/seed.py --stack empower-care-sample-crypto --region ap-south-1

Safe to run again. It overwrites the same four records.
"""

import argparse

import boto3

from _stack import client_key, outputs

VENDORS = [
    # merchant_id        crypto_mode  epoch_seconds  what it shows
    ("MERCH_ENCRYPTED", "required", 86400, "the end state"),
    ("MERCH_OPTIONAL", "optional", 86400, "mid migration, both accepted"),
    ("MERCH_PLAIN", "off", 86400, "a vendor not migrated yet"),
    ("MERCH_HOURLY", "required", 3600, "high sensitivity, 1 hour keys"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stack", default="empower-care-sample-crypto")
    ap.add_argument("--region", default="ap-south-1")
    args = ap.parse_args()

    table = outputs(args.stack, args.region)["KeyRoleTableName"]
    ddb = boto3.client("dynamodb", region_name=args.region)

    for merchant, mode, epoch_seconds, note in VENDORS:
        ddb.put_item(TableName=table, Item={
            "client_id": {"S": client_key(merchant)},
            "role_id": {"S": "empower_role_sample"},
            "allowed_ids": {"S": ""},
            "limit": {"N": "100000"},
            "source_ips": {"S": ""},
            "crypto_mode": {"S": mode},
            "key_version": {"N": "1"},
            "epoch_seconds": {"N": str(epoch_seconds)},
        })
        print(f"  seeded {merchant:<16} crypto_mode={mode:<9} keys={epoch_seconds // 3600}h  ({note})")
    print(f"seeded {len(VENDORS)} vendors into {table}")


if __name__ == "__main__":
    main()
