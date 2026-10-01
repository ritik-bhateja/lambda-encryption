"""Builds the Postman collection: request_value in, response_key + response_value out."""
import json
import pathlib

HOST = "{{host}}"
AUTH = [{"key": "Authorization", "value": "Bearer {{token}}"},
        {"key": "Content-Type", "value": "application/json"}]
JSON_ONLY = [{"key": "Content-Type", "value": "application/json"}]


def url(path):
    return {"raw": HOST + path, "host": [HOST], "path": path.strip("/").split("/")}


def seal_js(var, payload, path="/employee", then=None):
    """Pre-request: ask the sandbox to play the vendor and build a request_value."""
    body = [
        "pm.sendRequest({",
        "  url: pm.variables.get('host') + '/dev/seal', method: 'POST',",
        "  header: { 'Content-Type': 'application/json',",
        "            'Authorization': 'Bearer ' + pm.collectionVariables.get('token') },",
        f"  body: {{ mode: 'raw', raw: JSON.stringify({{ path: '{path}', method: 'POST', payload: {json.dumps(payload)} }}) }}",
        "}, (err, res) => {",
        "  const v = res.json().request_value;",
        f"  pm.collectionVariables.set('{var}', v);",
    ]
    return body + (then or []) + ["});"]


def value_body(var, extra=""):
    return {"mode": "raw", "raw": "{\n  \"request_value\": \"{{" + var + "}}\"" + extra + "\n}"}


def item(name, body, path="/prod/employee", pre=None, tests=None, headers=AUTH, method="POST"):
    it = {"name": name, "request": {"method": method, "header": headers, "url": url(path)}}
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


def rejected(code):
    return ["const b = pm.response.json();",
            f"pm.test('rejected with {code}', () => pm.expect(b.response_error_code).to.eql('{code}'));",
            "pm.test('error readable, nothing leaked', () => {",
            "  pm.expect(b.encrypted).to.be.false;",
            "  pm.expect(b).to.not.have.property('response_key');",
            "  pm.expect(b.response_data).to.eql({});",
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
    item("00. Health", None, "/health", method="GET", headers=[], tests=[
        "pm.test('sandbox is up', () => pm.response.to.have.status(200));",
        "pm.test('vendors seeded', () => pm.expect(pm.response.json().clients.MERCH_ENCRYPTED).to.eql('required'));",
    ]),
    item("01. Get ANZ token", {"mode": "raw", "raw": "{\n  \"client_id\": \"{{merchant}}\",\n  \"client_secret\": \"local-dev-secret\"\n}"},
         "/mock-anz/api/merchants/get_token", headers=JSON_ONLY, tests=[
        "const b = pm.response.json();",
        "pm.test('token issued', () => pm.expect(b.status).to.be.true);",
        "pm.collectionVariables.set('token', b.access_token);",
    ]),
    item("02. Get today's keys (once a day)", {"mode": "raw", "raw": "{}"}, "/prod/crypto/session-key", tests=[
        "const b = pm.response.json();",
        "pm.test('200', () => pm.expect(b.response_code).to.eql(200));",
        "pm.test('kek_id returned', () => pm.expect(b.kek_id).to.have.lengthOf(22));",
        "pm.test('request encryption key and kek_response, 32 bytes each', () => {",
        "  pm.expect(b.request_encryption_key).to.have.lengthOf(43);",
        "  pm.expect(b.kek_response).to.have.lengthOf(43);",
        "  pm.expect(b.request_encryption_key).to.not.eql(b.kek_response);",
        "});",
        "pm.test('algorithms stated', () => {",
        "  pm.expect(b.request_alg).to.eql('A256GCM');",
        "  pm.expect(b.response_alg).to.eql('A256GCMKW');",
        "});",
        "pm.test('old v2.0 field gone', () => pm.expect(b).to.not.have.property('kek_request'));",
        "pm.collectionVariables.set('kek_id', b.kek_id);",
    ]),
    item("03. Employee, encrypted (happy path)", value_body("happy_value"),
         pre=seal_js("happy_value", {"employee_code": "EMP001"}), tests=[
        "const b = pm.response.json();",
        "pm.test('200 OK', () => pm.response.to.have.status(200));",
        "pm.test('status fields readable', () => pm.expect(b.response_code).to.eql(200));",
        "pm.test('reply is response_key + response_value, unchanged', () => {",
        "  pm.expect(b.encrypted).to.be.true;",
        "  pm.expect(b.response_key).to.be.a('string');",
        "  pm.expect(b.response_value).to.be.a('string');",
        "});",
        "pm.test('no plain data in the reply', () => {",
        "  pm.expect(b).to.not.have.property('response_data');",
        "  pm.expect(pm.response.text()).to.not.include('Asha');",
        "});",
        "pm.sendRequest({",
        "  url: pm.variables.get('host') + '/dev/open', method: 'POST',",
        "  header: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + pm.collectionVariables.get('token') },",
        "  body: { mode: 'raw', raw: JSON.stringify({ response_key: b.response_key, response_value: b.response_value }) }",
        "}, (err, res) => {",
        "  const clear = res.json();",
        "  console.log('opened response_value:', JSON.stringify(clear));",
        "  pm.test('response_value opens to the employee', () => {",
        "    pm.expect(clear.response_data.employee_information_master.employee_full_name).to.eql('Asha Menon');",
        "  });",
        "});",
    ]),
    item("04. Replay the same request_value (CRY409)", value_body("happy_value"), tests=rejected("CRY409")),
    item("05. Label from A on data from B (CRY422)", value_body("spliced_value"),
         pre=seal_js("a_value", {"employee_code": "EMP001"}, then=[
             "  // only after A exists, build B, then splice A's label onto B's data",
             *["  " + line for line in seal_js("b_value", {"employee_code": "EMP002"}, then=[
                 "  const a = pm.collectionVariables.get('a_value').split('.');",
                 "  const b = v.split('.');",
                 "  pm.collectionVariables.set('spliced_value', [a[0], b[1], b[2], b[3]].join('.'));",
             ])],
         ]),
         tests=rejected("CRY422")),
    item("06. Edit one second in the label (CRY422)", value_body("edited_value"),
         pre=seal_js("e_value", {"employee_code": "EMP001"}, then=LABEL_EDIT), tests=rejected("CRY422")),
    item("07. Tampered ciphertext (CRY422)", value_body("tampered_value"),
         pre=seal_js("t_value", {"employee_code": "EMP001"}, then=[
             "  const p = v.split('.');",
             "  p[2] = p[2].slice(0, -2) + (p[2].endsWith('AA') ? 'BB' : 'AA');",
             "  pm.collectionVariables.set('tampered_value', p.join('.'));",
         ]),
         tests=rejected("CRY422")),
    item("08. Sealed for /policy, sent to /employee (CRY412)", value_body("policy_value"),
         pre=seal_js("policy_value", {"employee_code": "EMP001"}, path="/policy"), tests=rejected("CRY412")),
    item("09. Plain JSON while encryption is required (CRY426)",
         {"mode": "raw", "raw": "{\n  \"employee_code\": \"EMP001\"\n}"}, tests=rejected("CRY426")),
    item("10. Old v2.0 shape with request_key (CRY400)",
         {"mode": "raw", "raw": "{\n  \"request_key\": \"eyJ...\",\n  \"request_value\": \"{{old_value}}\"\n}"},
         pre=seal_js("old_value", {"employee_code": "EMP001"}), tests=rejected("CRY400")),
    item("11. Extra plain field beside request_value (CRY400)",
         value_body("x_value", ",\n  \"employee_code\": \"EMP002\""),
         pre=seal_js("x_value", {"employee_code": "EMP001"}), tests=rejected("CRY400")),
    item("12. Malformed request_value (CRY400)",
         {"mode": "raw", "raw": "{\n  \"request_value\": \"only.three.parts\"\n}"}, tests=rejected("CRY400")),
    item("13. Unknown employee (200 plus EMP404)", value_body("m_value"),
         pre=seal_js("m_value", {"employee_code": "EMP999"}), tests=[
        "const b = pm.response.json();",
        "pm.test('functional miss still on a 200', () => {",
        "  pm.expect(b.response_code).to.eql(200);",
        "  pm.expect(b.response_error_code).to.eql('EMP404');",
        "});",
    ]),
    item("14. Vendor not migrated yet (crypto_mode off)",
         {"mode": "raw", "raw": "{\n  \"employee_code\": \"EMP002\"\n}"},
         headers=[{"key": "Authorization", "value": "Bearer {{plain_token}}"}] + JSON_ONLY,
         pre=[
             "pm.sendRequest({",
             "  url: pm.variables.get('host') + '/mock-anz/api/merchants/get_token', method: 'POST',",
             "  header: { 'Content-Type': 'application/json' },",
             "  body: { mode: 'raw', raw: JSON.stringify({ client_id: 'MERCH_PLAIN' }) }",
             "}, (err, res) => pm.collectionVariables.set('plain_token', res.json().access_token));",
         ],
         tests=[
             "const b = pm.response.json();",
             "pm.test('unmigrated vendor unaffected', () => {",
             "  pm.expect(b.response_code).to.eql(200);",
             "  pm.expect(b.response_data.employee_information_master.employee_id).to.eql('EMP002');",
             "});",
         ]),
    item("15. No Authorization header (401)", {"mode": "raw", "raw": "{}"}, headers=JSON_ONLY, tests=[
        "pm.test('stopped at the gateway', () => pm.response.to.have.status(401));",
    ]),
]

variables = ["token", "kek_id", "plain_token", "happy_value", "a_value", "b_value", "spliced_value",
             "e_value", "edited_value", "t_value", "tampered_value", "policy_value", "old_value",
             "x_value", "m_value"]

collection = {
    "info": {
        "name": "Empower Care - request_value in, response_key + response_value out",
        "description": (
            "Runs against the local sandbox. Run the collection top to bottom, or use the Collection Runner.\n\n"
            "Requests carry one field, request_value = label.iv.ciphertext.tag, encrypted directly with the "
            "request encryption key. Responses carry response_key and response_value, unchanged.\n\n"
            "Postman cannot do AES-GCM itself (its sandbox ships crypto-js, which has no GCM mode). "
            "Pre-request scripts call the sandbox helper POST /dev/seal, which plays the vendor, and "
            "request 03 reads the reply through POST /dev/open. A real vendor does this locally, see "
            "seal_request() and open_response() in client/empower_client.py."),
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "item": items,
    "variable": [{"key": "host", "value": "http://localhost:8080"},
                 {"key": "merchant", "value": "MERCH_ENCRYPTED"}] +
                [{"key": k, "value": ""} for k in variables],
}

out = pathlib.Path(__file__).parent / "EmpowerCare_Payload_Encryption.postman_collection.json"
out.write_text(json.dumps(collection, indent=2))
print("collection written with", len(items), "requests")
