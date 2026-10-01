"""Generates the request_key / request_value flow diagram as SVG, then PNG."""
import html
import pathlib

W = 1600
ORANGE, CHAR, INK, GREY, MUTED = "#F36B1D", "#352F3D", "#222227", "#6B6B72", "#9A9AA2"
RULE, TINT, OUTLINE, BLUE, GREEN, RED = "#BDBDC4", "#F4F5F6", "#C9C9CE", "#0F4761", "#2E9E5B", "#D64545"
FONT = "Aptos, 'Segoe UI', 'DejaVu Sans', Arial, sans-serif"
MONO = "Consolas, 'DejaVu Sans Mono', monospace"

LANES = [
    ("vendor", "Vendor", "internal or external", 215),
    ("gw", "API Gateway", "+ request validator", 520),
    ("keys", "Key service", "/crypto/session-key", 820),
    ("lambda", "Business Lambda", "+ shared crypto layer", 1120),
    ("nonce", "Nonce store", "DynamoDB, TTL on", 1430),
]
X = {k: x for k, _, _, x in LANES}

# rows: (kind, ...)
ROWS = [
    ("phase", "A", "Key provisioning", "once per epoch: 24 hours by default, 1 hour for high sensitivity clients"),
    ("msg", "vendor", "gw", ["POST /crypto/session-key", "Authorization: Bearer <ANZ token>"]),
    ("self", "gw", ["Validate token with ANZ", "Separate crypto quota bucket"]),
    ("msg", "gw", "keys", ["Allow + client_ref, key_version"]),
    ("self", "keys", ["Derive today's key pair", "HKDF(seed, client, version, epoch)", "Nothing stored"]),
    ("ret", "keys", "vendor", ["kek_id, request_encryption_key,", "kek_response, next_rotation_at"]),

    ("phase", "B", "Vendor encrypts every request", "directly with the request encryption key"),
    ("self", "vendor", ["label = kid, cid, pth, mtd,", "iat, jti  (new jti every time)"]),
    ("self", "vendor", ["AES-GCM(request key, JSON)", "fresh random iv, AAD = label"]),
    ("msg", "vendor", "gw", ["POST /employee", "{ request_value: label.iv.ct.tag }"]),
    ("msg", "gw", "lambda", ["Allow + role, crypto_mode,", "key_version, epoch_seconds"]),

    ("phase", "C", "Platform opens and processes", "cheap checks first, crypto last"),
    ("self", "lambda", ["Check label: cid, pth, mtd", "Check clock skew under 300 s"]),
    ("self", "lambda", ["Resolve request key by kid", "re-derive, no lookup"]),
    ("msg", "lambda", "nonce", ["put jti", "if not exists"]),
    ("ret", "nonce", "lambda", ["ok, or duplicate = CRY409"]),
    ("self", "lambda", ["Decrypt request_value", "label must match, AAD"]),
    ("self", "lambda", ["Handler runs unchanged", "Hasura, same role as today"]),

    ("phase", "D", "Platform seals the response", "unchanged: fresh DEK, locked with the KEK"),
    ("self", "lambda", ["New DEK, wrap with kek_response", "response_key + response_value"]),
    ("ret", "lambda", "vendor", ["{ request_id, response_code, ...,", "response_key, response_value }"]),
    ("self", "vendor", ["Unwrap DEK with kek_response", "Decrypt response_value"]),
]

TOP = 190
PH_H, MSG_H, SELF_LINE = 74, 22, 21
parts, y, step = [], TOP, 0
LINE_H = 20


def text(x, y, s, size=17, color=INK, weight=400, anchor="middle", font=FONT, italic=False):
    st = ' font-style="italic"' if italic else ""
    return (f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" fill="{color}" '
            f'font-weight="{weight}" text-anchor="{anchor}"{st}>{html.escape(s)}</text>')


def badge(x, y, n):
    return (f'<circle cx="{x}" cy="{y}" r="14" fill="{ORANGE}"/>'
            + text(x, y + 5.5, str(n), 14, "#FFFFFF", 700))


body = []
for row in ROWS:
    kind = row[0]
    if kind == "phase":
        _, letter, title, sub = row
        y += 18
        body.append(f'<rect x="30" y="{y}" width="{W-60}" height="52" rx="10" fill="{TINT}"/>')
        body.append(f'<rect x="30" y="{y}" width="8" height="52" rx="3" fill="{ORANGE}"/>')
        body.append(text(62, y + 33, f"{letter}", 22, ORANGE, 700, "start"))
        body.append(text(92, y + 33, title, 20, INK, 700, "start"))
        body.append(text(W - 56, y + 33, sub, 16, GREY, 400, "end", italic=True))
        y += 52 + 24
        continue

    step += 1
    if kind == "self":
        _, lane, lines = row
        h = 22 + len(lines) * LINE_H
        bw = 340
        x0 = X[lane] - bw / 2
        body.append(f'<rect x="{x0}" y="{y}" width="{bw}" height="{h}" rx="9" fill="#FFFFFF" '
                    f'stroke="{OUTLINE}" stroke-width="1.5"/>')
        for i, ln in enumerate(lines):
            mono = ("=" in ln or "(" in ln or "{" in ln) and i == 0
            body.append(text(X[lane] + 10, y + 26 + i * LINE_H, ln, 15.5 if not mono else 14,
                             INK if i == 0 else GREY, 600 if i == 0 else 400,
                             font=MONO if mono else FONT))
        body.append(badge(x0 + 2, y + 2, step))
        y += h + 16
        continue

    _, a, b, lines = row
    dashed = kind == "ret"
    xa, xb = X[a], X[b]
    label_h = len(lines) * LINE_H
    ly = y + label_h + 14
    direction = 1 if xb > xa else -1
    xs, xe = xa + direction * 6, xb - direction * 10
    color = BLUE if dashed else INK
    dash = ' stroke-dasharray="8 6"' if dashed else ""
    body.append(f'<line x1="{xs}" y1="{ly}" x2="{xe}" y2="{ly}" stroke="{color}" stroke-width="2.2"{dash}/>')
    ah = 11
    body.append(f'<path d="M {xb - direction*2} {ly} L {xb - direction*(2+ah)} {ly-6.5} '
                f'L {xb - direction*(2+ah)} {ly+6.5} Z" fill="{color}"/>')
    mid = (xa + xb) / 2
    for i, ln in enumerate(lines):
        body.append(text(mid, y + 14 + i * LINE_H, ln, 15.5, color if dashed else INK,
                         600 if i == 0 else 400,
                         font=MONO if ("{" in ln or "_" in ln and i > 0) else FONT))
    body.append(badge(min(xa, xb) + 26 if direction == 1 else max(xa, xb) - 26, ly, step))
    y += label_h + 42

bottom = y + 20

# lifelines and headers
head = []
for key, name, sub, x in LANES:
    head.append(f'<line x1="{x}" y1="{TOP - 30}" x2="{x}" y2="{bottom}" stroke="{RULE}" '
                f'stroke-width="1.6" stroke-dasharray="3 6"/>')
for key, name, sub, x in LANES:
    fill = "#FEF1E9" if key == "lambda" else "#FFFFFF"
    head.append(f'<rect x="{x-128}" y="96" width="256" height="66" rx="11" fill="{fill}" '
                f'stroke="{ORANGE if key == "lambda" else OUTLINE}" stroke-width="1.6"/>')
    head.append(text(x, 125, name, 19, INK, 700))
    head.append(text(x, 149, sub, 14.5, GREY, 400))

# legend + properties box
ly0 = bottom + 24
legend = [
    f'<rect x="30" y="{ly0}" width="{W-60}" height="248" rx="12" fill="#FFFFFF" stroke="{OUTLINE}" stroke-width="1.5"/>',
    text(58, ly0 + 40, "What each piece guarantees", 20, INK, 700, "start"),
]
props = [
    ("One time use", "Every request carries a new jti, consumed in the nonce store. Replay = CRY409"),
    ("Label bound to data", "The label is the AAD. Edit it, or splice it onto other data, and decrypt fails"),
    ("Fresh iv per request", "A new random 12 byte iv every time. Safe up to about 4 billion requests per key"),
    ("Easy rotation", "Both keys change every epoch on their own. key_version + 1 revokes them instantly"),
    ("Directional keys", "The request key cannot read responses. kek_response cannot forge requests"),
]
for i, (k, v) in enumerate(props):
    yy = ly0 + 80 + i * 34
    legend.append(f'<circle cx="66" cy="{yy - 6}" r="6" fill="{ORANGE}"/>')
    legend.append(text(84, yy, k, 16.5, INK, 700, "start"))
    legend.append(text(330, yy, v, 16, GREY, 400, "start"))

key_y = ly0 + 248 + 26
legend += [
    f'<line x1="40" y1="{key_y}" x2="100" y2="{key_y}" stroke="{INK}" stroke-width="2.2"/>',
    text(112, key_y + 5, "request", 15, GREY, 400, "start"),
    f'<line x1="200" y1="{key_y}" x2="260" y2="{key_y}" stroke="{BLUE}" stroke-width="2.2" stroke-dasharray="8 6"/>',
    text(272, key_y + 5, "response", 15, GREY, 400, "start"),
    f'<rect x="370" y="{key_y-12}" width="36" height="24" rx="5" fill="#FFFFFF" stroke="{OUTLINE}" stroke-width="1.5"/>',
    text(418, key_y + 5, "local action, no network", 15, GREY, 400, "start"),
    badge(640, key_y, 1), text(662, key_y + 5, "step number, referenced in the design document", 15, GREY, 400, "start"),
]
H = key_y + 40

title = [
    text(40, 50, "Empower Care API payload encryption: request and response flow", 27, INK, 700, "start"),
    f'<rect x="40" y="64" width="120" height="4" fill="{ORANGE}"/>',
]

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">'
       f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>'
       + "".join(title + head + body + legend) + "</svg>")

out = pathlib.Path(__file__).parent
(out / "flow.svg").write_text(svg)
(out / "flow.html").write_text(f"<html><body style='margin:0'>{svg}</body></html>")
print("svg written", W, H)
