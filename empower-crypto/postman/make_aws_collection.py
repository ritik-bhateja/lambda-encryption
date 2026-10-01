"""
Builds the Postman collection for the DEPLOYED sample stack.

Needs the stack deployed with DEV_HELPERS=true, because Postman cannot do
AES-GCM and uses the stack's /dev/seal and /dev/open to play the vendor.

Fill the environment from your deploy:
    api_url      ApiUrl output, for example https://abc123.execute-api.ap-south-1.amazonaws.com/sample
    dev_url      DevApiUrl output
    token        python3 infra/scripts/issue_token.py --merchant MERCH_ENCRYPTED
    plain_token  python3 infra/scripts/issue_token.py --merchant MERCH_PLAIN
"""
import json
import pathlib

AUTH = [{"key": "Authorization", "value": "Bearer {{token}}"},
        {"key": "Content-Type", "value": "application/json"}]
JSON_ONLY = [{"key": "Content-Type", "value": "application/json"}]


def url(var, path):
    return {"raw": "{{" + var + "}}" + path, "host": ["{{" + var + "}}"], "path": path.strip("/").split("/")}


def seal_js(var, payload, path="/employee", then=None):
    """Pre-request: the stack's /dev/seal plays the vendor and returns a request_value."""
    return [
        "pm.sendRequest({",
        "  url: pm.variables.get('dev_url') + '/dev/seal', method: 'POST',",
        "  header: { 'Content-Type': 'application/json',",
        "            'Authorization': 'Bearer ' + pm.variables.get('token') },",
        f"  body: {{ mode: 'raw', raw: JSON.stringify({{ path: '{path}', method: 'POST', payload: {json.dumps(payload)} }}) }}",
        "}, (err, res) => {",
        "  if (err || res.code !== 200) { console.error('dev/seal failed', err || res.code); return; }",
        "  const v = res.json().request_value;",
        f"  pm.collectionVariables.set('{var}', v);",
    ] + (then or []) + ["});"]


def value_body(var, extra=""):
    return {"mode": "raw", "raw": "{\n  \"request_value\": \"{{" + var + "}}\"" + extra + "\n}"}


def item(name, body, path="/employee", pre=None, tests=None, headers=AUTH, base="api_url"):
    it = {"name": name, "request": {"method": "POST", "header": headers, "url": url(base, path)}}
    if body is not None:
        it["request"]["body"] = body
    ev = []
    if pre:
        ev.append({"listen": "prerequest", "script": {"type": "text/javascript", "exec": pre}})
    if tests:
        ev.append({"listen": "test", "script": {"type": "text/javascript", "exec": tests}})
    if ev:
        it["event"] = ev
    return it


def rejected(code, status=400):
    return ["const b = pm.response.json();",
            f"pm.test('HTTP {status}', () => pm.response.to.have.status({status}));",
            f"pm.test('rejected with {code}', () => pm.expect(b.response_error_code).to.eql('{code}'));",
            "pm.test('error readable, nothing leaked', () => {",
            "  pm.expect(b.encrypted).to.be.false;",
            "  pm.expect(b).to.not.have.property('response_key');",
            "});"]


LABEL_EDIT = [
    "  const p = v.split('.');",
    "  const s = p[0].replace(/-/g, '+').replace(/_/g, '/');",
    "  const label = JSON.parse(atob(s + '='.repeat((4 - s.length % 4) % 4)));",
    "  label.iat = label.iat - 1;",
    "  p[0] = btoa(JSON.stringify(label)).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');",
    "  pm.collectionVariables.set('edited_value', p.join('.'));",
]

items = [
    item("01. Get today's keys", {"mode": "raw", "raw": "{}"}, "/crypto/session-key", tests=[
        "const b = pm.response.json();",
        "pm.test('200', () => pm.response.to.have.status(200));",
        "pm.test('two 32 byte keys that differ', () => {",
        "  pm.expect(b.request_encryption_key).to.have.lengthOf(43);",
        "  pm.expect(b.kek_response).to.have.lengthOf(43);",
        "  pm.expect(b.request_encryption_key).to.not.eql(b.kek_response);",
        "});",
        "pm.test('algorithms stated', () => {",
        "  pm.expect(b.request_alg).to.eql('A256GCM');",
        "  pm.expect(b.response_alg).to.eql('A256GCMKW');",
        "});",
    ]),
    item("02. Employee, encrypted (happy path)", value_body("happy_value"),
         pre=seal_js("happy_value", {"employee_code": "EMP001"}), tests=[
        "const b = pm.response.json();",
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        "pm.test('reply is response_key + response_value', () => {",
        "  pm.expect(b.encrypted).to.be.true;",
        "  pm.expect(b.response_key).to.be.a('string');",
        "  pm.expect(b.response_value).to.be.a('string');",
        "});",
        "pm.test('no plain data in the reply', () => pm.expect(pm.response.text()).to.not.include('Asha'));",
        "pm.sendRequest({",
        "  url: pm.variables.get('dev_url') + '/dev/open', method: 'POST',",
        "  header: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + pm.variables.get('token') },",
        "  body: { mode: 'raw', raw: JSON.stringify({ response_key: b.response_key, response_value: b.response_value }) }",
        "}, (err, res) => {",
        "  const clear = res.json();",
        "  console.log('opened response_value:', JSON.stringify(clear.response_data));",
        "  pm.test('response_value opens to the employee', () => {",
        "    pm.expect(clear.response_data.employee_information_master.employee_full_name).to.eql('Asha Menon');",
        "  });",
        "});",
    ]),
    item("03. Replay the same request_value (CRY409)", value_body("happy_value"), tests=rejected("CRY409")),
    item("04. Label from A on data from B (CRY422)", value_body("spliced_value"),
         pre=seal_js("a_value", {"employee_code": "EMP001"}, then=[
             *["  " + line for line in seal_js("b_value", {"employee_code": "EMP002"}, then=[
                 "  const a = pm.collectionVariables.get('a_value').split('.');",
                 "  const b = v.split('.');",
                 "  pm.collectionVariables.set('spliced_value', [a[0], b[1], b[2], b[3]].join('.'));",
             ])],
         ]), tests=rejected("CRY422")),
    item("05. Edit one second in the label (CRY422)", value_body("edited_value"),
         pre=seal_js("e_value", {"employee_code": "EMP001"}, then=LABEL_EDIT), tests=rejected("CRY422")),
    item("06. Tampered ciphertext (CRY422)", value_body("tampered_value"),
         pre=seal_js("t_value", {"employee_code": "EMP001"}, then=[
             "  const p = v.split('.');",
             "  p[2] = p[2].slice(0, -2) + (p[2].endsWith('AA') ? 'BB' : 'AA');",
             "  pm.collectionVariables.set('tampered_value', p.join('.'));",
         ]), tests=rejected("CRY422")),
    item("07. Sealed for /policy, sent to /employee (CRY412)", value_body("policy_value"),
         pre=seal_js("policy_value", {"employee_code": "EMP001"}, path="/policy"), tests=rejected("CRY412")),
    item("08. Plain JSON while encryption is required (CRY426)",
         {"mode": "raw", "raw": "{\n  \"employee_code\": \"EMP001\"\n}"}, tests=rejected("CRY426")),
    item("09. Old v2.0 shape with request_key (CRY400)",
         {"mode": "raw", "raw": "{\n  \"request_key\": \"eyJ...\",\n  \"request_value\": \"{{old_value}}\"\n}"},
         pre=seal_js("old_value", {"employee_code": "EMP001"}), tests=rejected("CRY400")),
    item("10. Extra plain field beside request_value (CRY400)",
         value_body("x_value", ",\n  \"employee_code\": \"EMP002\""),
         pre=seal_js("x_value", {"employee_code": "EMP001"}), tests=rejected("CRY400")),
    item("11. Malformed request_value (CRY400)",
         {"mode": "raw", "raw": "{\n  \"request_value\": \"only.three.parts\"\n}"}, tests=rejected("CRY400")),
    item("12. Unknown employee (200 plus EMP404)", value_body("m_value"),
         pre=seal_js("m_value", {"employee_code": "EMP999"}), tests=[
        "const b = pm.response.json();",
        "pm.test('functional miss still on a 200', () => {",
        "  pm.response.to.have.status(200);",
        "  pm.expect(b.response_error_code).to.eql('EMP404');",
        "});",
    ]),
    item("13. Vendor not migrated yet (crypto_mode off)",
         {"mode": "raw", "raw": "{\n  \"employee_code\": \"EMP002\"\n}"},
         headers=[{"key": "Authorization", "value": "Bearer {{plain_token}}"}] + JSON_ONLY, tests=[
        "const b = pm.response.json();",
        "pm.test('unmigrated vendor unaffected', () => {",
        "  pm.response.to.have.status(200);",
        "  pm.expect(b.response_data.employee_information_master.employee_id).to.eql('EMP002');",
        "});",
    ]),
    item("14. No Authorization header (401)", {"mode": "raw", "raw": "{}"}, headers=JSON_ONLY, tests=[
        "pm.test('stopped at the gateway', () => pm.response.to.have.status(401));",
    ]),
    item("15. Forged token signature (403)", {"mode": "raw", "raw": "{}"},
         headers=[{"key": "Authorization", "value": "Bearer {{forged_token}}"}] + JSON_ONLY,
         pre=["const t = pm.variables.get('token');",
              "pm.collectionVariables.set('forged_token', t.slice(0, t.lastIndexOf('.') + 1) + 'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg');"],
         tests=["pm.test('authorizer denies', () => pm.response.to.have.status(403));"]),
]

variables = ["happy_value", "a_value", "b_value", "spliced_value", "e_value", "edited_value", "t_value",
             "tampered_value", "policy_value", "old_value", "x_value", "m_value", "forged_token"]

collection = {
    "info": {
        "name": "Empower Care - AWS sample stack",
        "description": (
            "Drives the DEPLOYED sample stack through API Gateway. Deploy with DEV_HELPERS=true.\n\n"
            "Set api_url, dev_url, token and plain_token in the environment first, see the header "
            "of postman/make_aws_collection.py. Tokens last one hour.\n\n"
            "Requests carry request_value. Replies carry response_key and response_value. Errors come "
            "back as real HTTP 400s with the CRY code in response_error_code."),
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "item": items,
    "variable": [{"key": k, "value": ""} for k in variables],
}

here = pathlib.Path(__file__).parent
(here / "EmpowerCare_AWS_Sample.postman_collection.json").write_text(json.dumps(collection, indent=2))
(here / "aws.postman_environment.json").write_text(json.dumps({
    "id": "empower-aws-sample",
    "name": "Empower Care - AWS sample stack",
    "values": [
        {"key": "api_url", "value": "https://REPLACE.execute-api.ap-south-1.amazonaws.com/sample", "type": "default", "enabled": True},
        {"key": "dev_url", "value": "https://REPLACE.execute-api.ap-south-1.amazonaws.com/sample", "type": "default", "enabled": True},
        {"key": "token", "value": "", "type": "secret", "enabled": True},
        {"key": "plain_token", "value": "", "type": "secret", "enabled": True},
    ],
    "_postman_variable_scope": "environment",
}, indent=2))
print("AWS collection written with", len(items), "requests")
