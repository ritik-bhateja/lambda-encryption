"""Shared helpers for the infra scripts: stack outputs and sample tokens."""

import base64
import hashlib
import hmac
import json
import sys
import time


def outputs(stack, region):
    import boto3
    cfn = boto3.client("cloudformation", region_name=region)
    stack_desc = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack_desc.get("Outputs", [])}


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def mint_token(stack, region, merchant, ttl_seconds=3600, _secret_cache={}):
    """A SAMPLE HS256 token. Only someone who can read the secret can mint one."""
    if stack not in _secret_cache:
        arn = outputs(stack, region).get("SampleTokenSecretArn")
        if not arn:
            sys.exit("This stack is not in AuthMode=sample, so there is no sample token secret.")
        import boto3
        raw = boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=arn)
        _secret_cache[stack] = json.loads(raw["SecretString"])["secret"].encode()
    return sign_token(_secret_cache[stack], merchant, ttl_seconds)


def sign_token(secret: bytes, merchant, ttl_seconds=3600):
    """HS256 over header.payload. Must match _verify_sample_token in the validator."""
    now = int(time.time())
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64u(json.dumps({"merchant_id": merchant, "iat": now, "exp": now + ttl_seconds},
                               separators=(",", ":")).encode())
    signature = _b64u(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def client_key(value):
    """Must match CLIENT_KEY_HASH=sha256 in the request validator."""
    return hashlib.sha256(value.encode()).hexdigest()
