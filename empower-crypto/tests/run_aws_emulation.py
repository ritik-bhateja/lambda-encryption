"""
Runs infra/scripts/smoke_test.py against tests/aws_emulator.py.

This is the same smoke test deploy.sh runs against the real stack, pointed at
an emulator driven by infra/template.yaml. Use it to check a template or
handler change before spending a deploy on it.

    ./infra/scripts/build_layer.sh
    python3 tests/run_aws_emulation.py

Needs a Python 3.12 interpreter (PY312, default python3.12) that can import
flask, moto, airspeed and pyyaml. Set PY312_DEPS to a --target folder holding
them if they are not installed for that interpreter.
"""

import os
import random
import string
import subprocess
import sys
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "infra", "scripts"))
from _stack import sign_token  # noqa: E402
from smoke_test import run  # noqa: E402

PORT = 9090
BASE = f"http://127.0.0.1:{PORT}"


def main():
    layer = os.path.join(ROOT, ".build", "layer", "python")
    if not os.path.isdir(layer):
        sys.exit("Build the layer first: ./infra/scripts/build_layer.sh")

    secret = "".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(48))
    paths = [layer] + ([os.environ["PY312_DEPS"]] if os.environ.get("PY312_DEPS") else [])
    env = {**os.environ, "EMULATOR_SAMPLE_SECRET": secret, "EMULATOR_PORT": str(PORT),
           "PYTHONPATH": os.pathsep.join(paths)}
    proc = subprocess.Popen([os.environ.get("PY312", "python3.12"), os.path.join(ROOT, "tests", "aws_emulator.py")],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(60):
            try:
                if requests.post(f"{BASE}/sample/employee", timeout=1).status_code == 401:
                    break
            except requests.ConnectionError:
                time.sleep(0.5)
        else:
            print(proc.stdout.read() if proc.poll() is not None else "emulator did not start")
            return 1

        print("emulator up: API Gateway behaviour from infra/template.yaml, real handlers, real layer")
        code = run(f"{BASE}/sample", lambda m: sign_token(secret.encode(), m),
                   dev_url=f"{BASE}/devapi/sample")
        return code
    finally:
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out = ""
        banner = [ln for ln in (out or "").splitlines() if ln.startswith(("python", "routes"))]
        errors = [ln for ln in (out or "").splitlines() if "Traceback" in ln or "Error" in ln]
        print("\n".join(banner))
        if errors:
            print("emulator reported errors:\n  " + "\n  ".join(errors[:10]))


if __name__ == "__main__":
    sys.exit(main())
