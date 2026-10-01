"""scripts/vendor_key.py: create, rotate, finish; never prints key material."""

import importlib.util
import json
import os
import sys

import boto3
from moto import mock_aws

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "layer", "python"))
import payload_crypto as pc  # noqa: E402

spec = importlib.util.spec_from_file_location("vendor_key", os.path.join(ROOT, "scripts", "vendor_key.py"))
vk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vk)


def run(monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["vendor_key.py", *argv, "--region", "ap-south-1"])
    vk.main()
    return capsys.readouterr().out


def secret(name):
    return json.loads(boto3.client("secretsmanager", region_name="ap-south-1")
                      .get_secret_value(SecretId=name)["SecretString"])


def test_create_rotate_finish(monkeypatch, capsys):
    with mock_aws():
        monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-south-1")
        out = run(monkeypatch, capsys, "create", "ACME", "GLOBEX")
        a1 = secret("payload-keys/ACME")
        assert a1["key_id"] == "ACME-v1" and len(bytes.fromhex(a1["key_hex"])) == 32
        assert a1["key_hex"] not in out and secret("payload-keys/GLOBEX")["key_hex"] != a1["key_hex"]

        out = run(monkeypatch, capsys, "rotate", "ACME")
        a2 = secret("payload-keys/ACME")
        assert (a2["key_id"], a2["previous_key_id"], a2["previous_key_hex"]) == ("ACME-v2", "ACME-v1", a1["key_hex"])
        assert a2["key_hex"] not in out and a1["key_hex"] not in out

        # the decorator module reads the rotated secret: both keys usable
        pc._clients.clear(); pc.clear_key_cache()
        keys = pc.get_vendor_keys("ACME")
        assert keys.for_kid("ACME-v2") == bytes.fromhex(a2["key_hex"])
        assert keys.for_kid("ACME-v1") == bytes.fromhex(a1["key_hex"])

        run(monkeypatch, capsys, "finish-rotation", "ACME")
        assert secret("payload-keys/ACME") == {"key_id": "ACME-v2", "key_hex": a2["key_hex"]}
