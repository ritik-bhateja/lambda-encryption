"""End-to-end example for a vendor: encrypt a request, send it, decrypt the reply.

    pip install cryptography
    export VENDOR_ID=ACME
    export VENDOR_KEY_HEX=<the 64 hex character key you were given>
    python example_call.py https://<api-host>/orders
"""
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

from vendor_client import open_reply, seal_request

vendor = os.environ["VENDOR_ID"]
key = bytes.fromhex(os.environ["VENDOR_KEY_HEX"])       # keep it in a secret store, never in code
url = sys.argv[1]
path = urlparse(url).path                                # the label's pth: the path, no host, no stage

# 1. Encrypt: plain JSON in, one field out.
payload = {"order_id": "ORD-1001", "amount": 2500, "currency": "INR"}
body = seal_request(payload, key, vendor, path, "POST")  # {"request_key": "label.iv.ciphertext.tag"}

# 2. Send, with your vendor id in the header.
req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                             headers={"Content-Type": "application/json", "X-Vendor-Id": vendor})
try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        status, reply = resp.status, json.load(resp)
except urllib.error.HTTPError as exc:
    status, reply = exc.code, json.load(exc)

# 3. Decrypt: the reply is {"response_key", "response_value"}; errors come back in the clear.
if "response_key" in reply:
    print(status, json.dumps(open_reply(reply["response_key"], reply["response_value"], key, vendor), indent=2))
else:
    print(status, reply)                                 # e.g. {"error": "CRY413", ...}
