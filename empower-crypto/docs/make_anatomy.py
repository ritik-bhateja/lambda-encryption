"""Anatomy figure: what travels on the wire, request (direct) and response (envelope)."""
import html
import pathlib

W, H = 1600, 1130
ORANGE, INK, GREY, OUTLINE, TINT, BLUE = "#F36B1D", "#222227", "#6B6B72", "#C9C9CE", "#F4F5F6", "#0F4761"
PEACH = "#FEF1E9"
FONT = "Aptos, 'Segoe UI', 'DejaVu Sans', Arial, sans-serif"
MONO = "Consolas, 'DejaVu Sans Mono', monospace"


def t(x, y, s, size=17, color=INK, weight=400, anchor="middle", font=FONT, italic=False):
    it = ' font-style="italic"' if italic else ""
    return (f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" fill="{color}" '
            f'font-weight="{weight}" text-anchor="{anchor}" xml:space="preserve"{it}>{html.escape(s)}</text>')


def box(x, y, w, h, title, lines, fill="#FFFFFF", stroke=OUTLINE, mono=True, tag=None, size=15.5):
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="1.8"/>',
           t(x + 20, y + 34, title, 19, INK, 700, "start")]
    if tag:
        out.append(t(x + w - 20, y + 34, tag, 14.5, GREY, 400, "end", italic=True))
    for i, ln in enumerate(lines):
        out.append(t(x + 20, y + 66 + i * 25, ln, size, INK if mono else GREY, 400, "start", MONO if mono else FONT))
    return "".join(out)


def arrow(x1, y, x2, label, sub, color=INK):
    return "".join([
        f'<line x1="{x1}" y1="{y}" x2="{x2 - 12}" y2="{y}" stroke="{color}" stroke-width="2.4"/>',
        f'<path d="M {x2} {y} L {x2-14} {y-7.5} L {x2-14} {y+7.5} Z" fill="{color}"/>',
        t((x1 + x2) / 2, y - 30, label, 16, color, 700),
        t((x1 + x2) / 2, y - 10, sub, 14.5, GREY, 400, italic=True),
    ])


def section(y, label, sub):
    return "".join([
        f'<rect x="30" y="{y}" width="{W-60}" height="46" rx="10" fill="{TINT}"/>',
        f'<rect x="30" y="{y}" width="8" height="46" rx="3" fill="{ORANGE}"/>',
        t(58, y + 30, label, 19, INK, 700, "start"),
        t(W - 56, y + 30, sub, 15.5, GREY, 400, "end", italic=True),
    ])


P = [f'<rect width="{W}" height="{H}" fill="#FFFFFF"/>',
     t(40, 50, "What travels on the wire", 27, INK, 700, "start"),
     f'<rect x="40" y="64" width="120" height="4" fill="{ORANGE}"/>',
     t(40, 100, "Requests are encrypted directly with the request encryption key. Responses keep the box and the safe.",
       16, GREY, 400, "start")]

# ---------------------------------------------------------------- REQUEST
P.append(section(126, "REQUEST", "one field, encrypted directly, label glued on as AAD"))
P.append(box(40, 200, 340, 150, "Vendor JSON", ["{", '  "employee_code": "EMP001"', "}"], tag="plain text"))
P.append(arrow(380, 275, 640, "encrypt directly", "AES-256-GCM, request key"))

# request_value with a 4 part strip
x0, y0, w0 = 640, 200, 520
P.append(f'<rect x="{x0}" y="{y0}" width="{w0}" height="300" rx="12" fill="{PEACH}" stroke="{ORANGE}" stroke-width="1.8"/>')
P.append(t(x0 + 20, y0 + 34, "request_value", 19, INK, 700, "start"))
P.append(t(x0 + w0 - 20, y0 + 34, "sent on the wire", 14.5, GREY, 400, "end", italic=True))
segs = [("label", 150), ("iv", 70), ("ciphertext", 170), ("tag", 70)]
sx = x0 + 20
for i, (name, sw) in enumerate(segs):
    fill = "#FFFFFF"
    P.append(f'<rect x="{sx}" y="{y0 + 54}" width="{sw}" height="40" rx="6" fill="{fill}" stroke="{ORANGE}" stroke-width="1.4"/>')
    P.append(t(sx + sw / 2, y0 + 80, name, 15, INK, 700, font=MONO))
    sx += sw
    if i < len(segs) - 1:
        P.append(t(sx + 5, y0 + 82, ".", 22, ORANGE, 700))
        sx += 10
rows = [
    ("label", "kid cid pth mtd iat jti"),
    ("", "readable, but authenticated"),
    ("iv", "12 random bytes, new every time"),
    ("ciphertext", "the locked JSON"),
    ("tag", "16 byte seal over label + data"),
]
for i, (k, v) in enumerate(rows):
    P.append(t(x0 + 20, y0 + 132 + i * 30, k, 15.5, INK, 700, "start", MONO))
    P.append(t(x0 + 150, y0 + 132 + i * 30, v, 15.5, INK if i != 1 else GREY, 400, "start", MONO if i != 1 else FONT,
               italic=(i == 1)))

P.append(box(1200, 200, 360, 300, "The label", [
    "kid  today's key id",
    "cid  who is calling",
    "pth  which API",
    "mtd  which method",
    "iat  when",
    "jti  serial, used once",
    "",
    "Edit one character and",
    "the seal breaks",
], fill="#FFFFFF", stroke=BLUE, size=15))

# ---------------------------------------------------------------- RESPONSE
RY = 540
P.append(section(RY, "RESPONSE", "unchanged: a new DEK for every reply, locked in the safe with kek_response"))
P.append(box(40, RY + 74, 340, 150, "Reply data", ["{", '  "response_data": {...},', '  "page_info": {...}', "}"], tag="plain text", size=14.5))
P.append(arrow(380, RY + 149, 640, "compress, then encrypt", "AES-256-GCM with the DEK"))
P.append(box(640, RY + 74, 420, 150, "response_value", [
    "iv          12 bytes, random",
    "ciphertext  the locked reply",
    "tag         16 byte seal",
], fill=PEACH, stroke=ORANGE, tag="sent on the wire"))

P.append(box(40, RY + 264, 340, 150, "DEK", [
    "32 random bytes",
    "new for this reply",
    "used once, then discarded",
], tag="never sent in clear"))
P.append(arrow(380, RY + 339, 640, "wrap with kek_response", "AES-256-GCM key wrap"))
P.append(box(640, RY + 264, 420, 176, "response_key", [
    "kek_id  edek  wiv  wtag",
    "the locked DEK and its seal",
    "",
    "cid  pth  mtd  iat  jti",
    "the label",
], fill=PEACH, stroke=ORANGE, tag="sent on the wire", size=15))
gx = 1075
P.append(f'<path d="M 1060 {RY+352} C {gx+70} {RY+352}, {gx+70} {RY+149}, 1066 {RY+149}" fill="none" '
         f'stroke="{BLUE}" stroke-width="2.4" stroke-dasharray="8 6"/>')
P.append(f'<path d="M 1062 {RY+149} L 1077 {RY+141} L 1077 {RY+157} Z" fill="{BLUE}"/>')
P.append(box(1200, RY + 74, 360, 366, "What the vendor gets", [
    "{",
    '  "request_id": "...",',
    '  "response_code": 200,',
    '  "encrypted": true,',
    '  "response_key":',
    '      "eyJhbGci...",',
    '  "response_value":',
    '      "Tq8mZ1Ld..."',
    "}",
    "",
    "response_key is the AAD",
    "of response_value",
], fill=TINT, stroke=OUTLINE, size=15))

# ---------------------------------------------------------------- legend
LY = RY + 488
legend = [
    ("Request encryption key", "shared with the vendor, fetched once a day. Locks request data directly."),
    ("kek_response", "shared with the vendor, fetched with it. Only ever locks a response DEK, never data."),
    ("DEK", "made fresh for every response. Locks the reply. Travels only inside response_key."),
]
for i, (k, v) in enumerate(legend):
    P.append(t(40, LY + i * 30, k, 16, ORANGE, 700, "start"))
    P.append(t(290, LY + i * 30, v, 16, GREY, 400, "start"))

svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">' + "".join(P) + "</svg>"
(pathlib.Path(__file__).parent / "anatomy.html").write_text(f"<html><body style='margin:0'>{svg}</body></html>")
print("anatomy written")
