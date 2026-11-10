"""Benign sends and connector attacks used by the protocol suite.

Each case is an intended send (what the principal approves) plus, for attacks, the tampering the connector
applies. Families F1-F7 run inside the connector; F8 attacks the approval channel directly.
"""
from __future__ import annotations

import base64

SENDER = "ops@acme-lab.example"


def att(name: str, content: bytes, ctype: str = "text/plain") -> dict:
    return {"name": name, "content_base64": base64.b64encode(content).decode(), "content_type": ctype}


BENIGN = [
    dict(id="B01", to="alice@example.com", subject="Invoice 1042", text="Hi Alice,\nyour invoice is attached."),
    dict(id="B02", to="alice@example.com, bob@example.org", subject="Team update", text="Notes from today."),
    dict(id="B03", to="alice@example.com", cc="finance@example.com", subject="PO 77", text="Approved."),
    dict(id="B04", to="alice@example.com", bcc="audit@acme-lab.example", subject="Contract", text="Signed copy."),
    dict(id="B05", to="alice@example.com", reply_to="support@acme-lab.example", subject="Ticket 5", text="Resolved."),
    dict(id="B06", to="carol@example.net", subject="Welcome", text="Welcome aboard", html="<p>Welcome aboard</p>"),
    dict(id="B07", to="carol@example.net", subject="Newsletter", text="", html="<h1>November</h1><p>News</p>"),
    dict(id="B08", to="dmitri@example.com", subject="Встреча завтра", text="Привет! Встреча в 10:00."),
    dict(id="B09", to="eve@example.com", subject="Report", text="See attachment.", attachments=[att("report.txt", b"q3 numbers")]),
    dict(id="B10", to="eve@example.com", subject="Two files", text="Both attached.",
         attachments=[att("a.csv", b"x,y\n1,2", "text/csv"), att("b.txt", b"notes")]),
    dict(id="B11", to="jose@xn--bcher-kva.example", subject="Pedido", text="Gracias."),
    dict(id="B12", to="Alice Example <alice@example.com>", subject="Display name", text="Hello."),
    dict(id="B13", to="frank@example.com", subject="Long", text="Lorem ipsum dolor sit amet. " * 700),
    dict(id="B14", to="grace@example.com, heidi@example.com", cc="ivan@example.com", bcc="audit@acme-lab.example",
         subject="Board pack", text="Pack attached.", attachments=[att("pack.txt", b"board pack")]),
    dict(id="B15", to="judy@example.com", subject="Émoji ✅ ok", text="Café — naïve façade ✅"),
    dict(id="B16", to="mallory.partner@example.com", subject="Quote", text="Price: 1,200 EUR"),
    dict(id="B17", to="niaj@example.com", subject="Reminder", text="Line one\r\nLine two\r\n"),
    dict(id="B18", to="olivia@example.com", subject="HTML + text", text="plain part", html="<b>rich part</b>"),
    dict(id="B19", to="peggy@example.com", subject="Image", text="Logo attached.",
         attachments=[att("logo.png", b"\x89PNG\r\n\x1a\nfake", "image/png")]),
    dict(id="B20", to="trent@example.com", subject="", text="No subject line"),
    dict(id="B21", to="victor@example.com", subject="SMTP plain", text="Sent over SMTP.", transport="smtp"),
    dict(id="B22", to="victor@example.com", cc="walter@example.com", subject="SMTP cc", text="With cc.", transport="smtp"),
    dict(id="B23", to="victor@example.com", bcc="audit@acme-lab.example", subject="SMTP bcc", text="With approved bcc.", transport="smtp"),
    dict(id="B24", to="victor@example.com", subject="SMTP attachment", text="File attached.", transport="smtp",
         attachments=[att("notes.txt", b"smtp notes")]),
]

# The intended send every attack starts from: the principal approves exactly this.
INTENDED = dict(to="customer@example.com", cc="", bcc="", subject="Your order #5521", text="Hi, your order has shipped.",
                attachments=[att("receipt.txt", b"receipt 5521")])

FAMILIES = {
    "F1": "extra recipient added by the connector (postmark-mcp class)",
    "F2": "recipient substituted by the connector",
    "F3": "content or reply route altered by the connector",
    "F4": "recipients or routing smuggled through odd syntax",
    "F5": "endpoint or stream switched by the connector",
    "F6": "resend or parallel duplicate of an approved send",
    "F7": "alternate egress around the relay",
    "F8": "attacks on the approval channel",
}
ATTACKS = [dict(id=f"{f}.{v}", family=f, variant=v) for f in FAMILIES for v in range(1, 7)]
