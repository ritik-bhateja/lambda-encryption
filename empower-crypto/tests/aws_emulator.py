"""
API Gateway emulator driven by infra/template.yaml. Test harness only.

The point is to exercise the DEPLOYABLE artifacts, not a re-implementation:

  - reads the paths, VTL request and response templates, authorizer settings
    and every function's environment variables from infra/template.yaml
  - runs the real handler files, importing the real layer from .build/layer
  - renders the real VTL with a Velocity engine, and parses the result as the
    Lambda event, so a broken template fails here as it would in AWS
  - reproduces API Gateway behaviour around them: 401 with no header, 403 on
    Deny, 415 for non JSON bodies with passthroughBehavior never, 500 on a
    Lambda exception, and response_code copied into the HTTP status
  - fakes only AWS itself (DynamoDB, Secrets Manager) with moto, seeded the
    way CloudFormation and infra/scripts/seed.py would seed them

Run under Python 3.12 with the layer first on sys.path, as Lambda does:
    tests/run_aws_emulation.sh
"""

import importlib.util
import json
import os
import random
import string
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_NAME, REGION, ACCOUNT = "sample", "ap-south-1", "111122223333"

os.environ.update({"AWS_DEFAULT_REGION": REGION, "AWS_ACCESS_KEY_ID": "test",
                   "AWS_SECRET_ACCESS_KEY": "test"})

import yaml  # noqa: E402
from moto import mock_aws  # noqa: E402

_mock = mock_aws()
_mock.start()

import airspeed  # noqa: E402
import boto3  # noqa: E402
from flask import Flask, Response, request  # noqa: E402

sys.path.insert(0, os.path.join(ROOT, "infra", "scripts"))
from seed import VENDORS  # noqa: E402
from _stack import client_key  # noqa: E402


# --------------------------------------------------------------------------
# Load the template, keeping CloudFormation tags as their long form
# --------------------------------------------------------------------------

class CfnLoader(yaml.SafeLoader):
    pass


def _tag(name):
    def construct(loader, node):
        if isinstance(node, yaml.ScalarNode):
            value = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            value = loader.construct_sequence(node, deep=True)
        else:
            value = loader.construct_mapping(node, deep=True)
        if name == "GetAtt" and isinstance(value, str):
            value = value.split(".")
        return {("Ref" if name == "Ref" else f"Fn::{name}"): value}
    return construct


for tag in ["Ref", "Sub", "GetAtt", "If", "Not", "Equals", "And", "Or", "Join", "Select", "Split"]:
    CfnLoader.add_constructor(f"!{tag}", _tag(tag))

TEMPLATE = yaml.load(open(os.environ.get("EMULATOR_TEMPLATE", os.path.join(ROOT, "infra", "template.yaml"))), Loader=CfnLoader)
RES = TEMPLATE["Resources"]
PARAMS = {"Env": ENV_NAME, "AuthMode": "sample", "AnzValidateUrl": "",
          "EnableDevHelpers": "true", "MaxKeyIssuesPerEpoch": "50"}
CONDITIONS = {"IsSampleAuth": True, "CreateDevHelpers": True}
PHYSICAL = {}   # logical id -> physical name or ARN


def resolve(value):
    """Enough of the CloudFormation intrinsics for this template."""
    if isinstance(value, (str, int, float)):
        return str(value)
    if "Ref" in value:
        ref = value["Ref"]
        if ref in PARAMS:
            return PARAMS[ref]
        if ref in PHYSICAL:
            return PHYSICAL[ref]
        raise KeyError(f"template refers to {ref}, which the emulator cannot resolve")
    if "Fn::Sub" in value:
        out = value["Fn::Sub"]
        for k, v in {**PARAMS, "AWS::Region": REGION, "AWS::AccountId": ACCOUNT,
                     "AWS::Partition": "aws"}.items():
            out = out.replace("${" + k + "}", v)
        return out
    if "Fn::If" in value:
        cond, yes, no = value["Fn::If"]
        return resolve(yes if CONDITIONS[cond] else no)
    raise ValueError(f"unsupported intrinsic {value}")


# --------------------------------------------------------------------------
# Create the AWS resources the way CloudFormation would
# --------------------------------------------------------------------------

ddb = boto3.client("dynamodb")
sm = boto3.client("secretsmanager")

for logical, res in RES.items():
    if res["Type"] != "AWS::DynamoDB::Table":
        continue
    props = res["Properties"]
    name = resolve(props["TableName"])
    ddb.create_table(TableName=name, KeySchema=props["KeySchema"],
                     AttributeDefinitions=props["AttributeDefinitions"], BillingMode="PAY_PER_REQUEST")
    PHYSICAL[logical] = name


def generated(length):
    """What GenerateSecretString with ExcludePunctuation produces: letters and digits."""
    return "".join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(length))


SAMPLE_TOKEN_SECRET = os.environ.get("EMULATOR_SAMPLE_SECRET") or generated(48)
for logical, res in RES.items():
    if res["Type"] != "AWS::SecretsManager::Secret":
        continue
    gen = res["Properties"]["GenerateSecretString"]
    value = SAMPLE_TOKEN_SECRET if gen["GenerateStringKey"] == "secret" else generated(gen["PasswordLength"])
    arn = sm.create_secret(Name=f"{logical}-{uuid.uuid4().hex[:6]}",
                           SecretString=json.dumps({gen["GenerateStringKey"]: value}))["ARN"]
    PHYSICAL[logical] = arn

# seed.py's vendors, written exactly as seed.py writes them
for merchant, mode, epoch_seconds, _ in VENDORS:
    ddb.put_item(TableName=PHYSICAL["KeyRoleTable"], Item={
        "client_id": {"S": client_key(merchant)}, "role_id": {"S": "empower_role_sample"},
        "allowed_ids": {"S": ""}, "limit": {"N": "100000"}, "source_ips": {"S": ""},
        "crypto_mode": {"S": mode}, "key_version": {"N": "1"},
        "epoch_seconds": {"N": str(epoch_seconds)},
    })

# every function's environment, straight from the template
for logical, res in RES.items():
    if res["Type"] != "AWS::Serverless::Function":
        continue
    for k, v in (res["Properties"].get("Environment", {}).get("Variables") or {}).items():
        value = resolve(v)
        if k in os.environ and os.environ[k] != value and k not in ("AWS_DEFAULT_REGION",):
            raise SystemExit(f"env var {k} differs between functions, the emulator cannot share it")
        os.environ[k] = value


# --------------------------------------------------------------------------
# Load the real handlers, each from its CodeUri, the layer from .build
# --------------------------------------------------------------------------

sys.path.insert(0, os.path.join(ROOT, ".build", "layer", "python"))


def load_handler(logical):
    props = RES[logical]["Properties"]
    code_dir = os.path.normpath(os.path.join(ROOT, "infra", props["CodeUri"]))
    module_file, func = props["Handler"].split(".")
    spec = importlib.util.spec_from_file_location(f"{logical}_mod", os.path.join(code_dir, module_file + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, func)


HANDLERS = {logical: load_handler(logical) for logical, r in RES.items()
            if r["Type"] == "AWS::Serverless::Function"}


def function_for(uri):
    """Integration or authorizer URI -> logical function id."""
    sub = uri["Fn::Sub"]
    return sub.split("${")[-1].split(".Arn}")[0]


# --------------------------------------------------------------------------
# API Gateway
# --------------------------------------------------------------------------

class VtlInput:
    def __init__(self, raw):
        self._raw = raw
        self._obj = json.loads(raw) if raw else {}

    def json(self, path):
        return json.dumps(self._obj) if path == "$" else "null"

    def path(self, path):
        return self._obj


APIS = {"CryptoApi": f"/{ENV_NAME}", "DevApi": f"/devapi/{ENV_NAME}"}
app = Flask(__name__)
LOG = []


def gateway(api_logical, resource_path):
    body = RES[api_logical]["Properties"]["DefinitionBody"]
    op = body["paths"][resource_path]["post"]
    integ = op["x-amazon-apigateway-integration"]
    auth_cfg = body["securityDefinitions"]["RequestValidator"]["x-amazon-apigateway-authorizer"]
    assert auth_cfg["authorizerResultTtlInSeconds"] == 0, "authorizer caching must stay off"

    def reply(status, payload):
        LOG.append((resource_path, status))
        return Response(json.dumps(payload), status=status, mimetype="application/json")

    # 1. identity source
    header = auth_cfg["identitySource"].split(".")[-1]
    if not request.headers.get(header):
        return reply(401, {"message": "Unauthorized"})

    # 2. REQUEST authorizer
    method_arn = f"arn:aws:execute-api:{REGION}:{ACCOUNT}:{api_logical}/{ENV_NAME}/POST{resource_path}"
    auth_event = {"type": "REQUEST", "methodArn": method_arn, "resource": resource_path,
                  "path": resource_path, "httpMethod": "POST", "headers": dict(request.headers),
                  "requestContext": {"resourcePath": resource_path, "httpMethod": "POST",
                                     "stage": ENV_NAME, "identity": {"sourceIp": request.remote_addr}}}
    try:
        policy = HANDLERS[function_for(auth_cfg["authorizerUri"])](auth_event, None)
    except Exception as exc:
        if str(exc) == "Unauthorized":
            return reply(401, {"message": "Unauthorized"})
        return reply(500, {"message": None})
    stmt = policy["policyDocument"]["Statement"][0]
    if stmt["Effect"] != "Allow" or method_arn not in stmt["Resource"]:
        return reply(403, {"Message": "User is not authorized to access this resource with an explicit deny"})
    auth_ctx = policy.get("context", {})
    if not all(isinstance(v, (str, int, float, bool)) for v in auth_ctx.values()):
        return reply(500, {"message": None})     # AuthorizerConfigurationException in real AWS

    # 3. integration request, passthroughBehavior never
    ctype = (request.content_type or "").split(";")[0].strip()
    templates = integ["requestTemplates"]
    if ctype not in templates:
        return reply(415, {"message": "Unsupported Media Type"})
    context = {"requestId": str(uuid.uuid4()), "resourcePath": resource_path, "stage": ENV_NAME,
               "httpMethod": "POST", "identity": {"sourceIp": request.remote_addr},
               "authorizer": {k: str(v) for k, v in auth_ctx.items()}, "responseOverride": {}}
    rendered = airspeed.Template(templates[ctype]).merge(
        {"input": VtlInput(request.get_data(as_text=True)), "context": context})
    try:
        event = json.loads(rendered)
    except ValueError:
        return reply(500, {"message": "Internal server error"})   # the Lambda would get broken JSON

    # 4. Lambda
    try:
        result = json.loads(json.dumps(HANDLERS[function_for(integ["uri"])](event, None)))
    except Exception:
        err = integ["responses"].get(".+")
        if not err:
            return reply(502, {"message": "Internal server error"})
        return reply(int(err["statusCode"]), json.loads(err["responseTemplates"]["application/json"]))

    # 5. integration response
    default = integ["responses"]["default"]
    context["responseOverride"] = {}
    out = airspeed.Template(default["responseTemplates"]["application/json"]).merge(
        {"input": VtlInput(json.dumps(result)), "context": context})
    status = int(context["responseOverride"].get("status") or default["statusCode"])
    LOG.append((resource_path, status))
    return Response(out.strip(), status=status, mimetype="application/json")


for api, prefix in APIS.items():
    for path in RES[api]["Properties"]["DefinitionBody"]["paths"]:
        app.add_url_rule(f"{prefix}{path}", endpoint=f"{api}{path}", methods=["POST"],
                         view_func=(lambda a=api, p=path: gateway(a, p)))


@app.errorhandler(404)
@app.errorhandler(405)
def missing_route(_):
    return Response(json.dumps({"message": "Missing Authentication Token"}), status=403,
                    mimetype="application/json")


if __name__ == "__main__":
    port = int(os.environ.get("EMULATOR_PORT", "9090"))
    print(f"python {sys.version.split()[0]} | layer cryptography from "
          f"{sys.modules['cryptography'].__file__.split(ROOT)[-1] if 'cryptography' in sys.modules else 'not loaded yet'}")
    print("routes:", sorted(str(r) for r in app.url_map.iter_rules() if "static" not in str(r)))
    app.run(host="127.0.0.1", port=port, threaded=True)
