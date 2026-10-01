"""Checks vendor_client.py against test_vectors.json. Port this check to your own language.

    python verify_test_vectors.py
"""
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import vendor_client as vc

HERE = os.path.dirname(os.path.abspath(__file__))
tv = json.load(open(os.path.join(HERE, "test_vectors.json")))
key = bytes.fromhex(tv["key_hex"])

# Request: same inputs must give the same request_key, byte for byte.
inp = tv["request"]["inputs"]
label_seg = vc.b64u(inp["label_json"].encode())
assert label_seg == tv["request"]["expected"]["label_segment"], "label segment differs"
iv = bytes.fromhex(inp["iv_hex"])
sealed = AESGCM(key).encrypt(iv, inp["payload_json"].encode(), label_seg.encode())
request_key = ".".join([label_seg, vc.b64u(iv), vc.b64u(sealed[:-16]), vc.b64u(sealed[-16:])])
assert request_key == tv["request"]["expected"]["request_key"], "request_key differs"
print("request   OK  request_key matches")

# Response: the reply must open to the expected JSON.
body = tv["response"]["http_body"]
reply = vc.open_reply(body["response_key"], body["response_value"], key, tv["vendor_id"])
assert json.dumps(reply, separators=(",", ":")) == tv["response"]["expected"]["reply_json"], "reply differs"
print("response  OK ", reply)
