"""The relay: the only holder of provider credentials, and the last point where a send can still be stopped.

HTTPS: a Postmark-compatible API (served under the provider hostname inside the lab).
SMTP:  a submission listener.
In `enforce` mode a message is delivered only if its effect digest equals an authorized, unexpired, unconsumed
approval; the relay then forwards a message re-serialized from what it parsed (never the connector's raw bytes),
so what was checked is exactly what is sent. An ambiguous provider result is recorded as UNKNOWN and the
consumed approval cannot release a second dispatch.
In `passthrough` mode (baselines) the relay behaves like a permissive provider and forwards whatever it is asked.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import smtplib
import uuid
from email.message import EmailMessage
from email.utils import format_datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .model import Attachment, Effect, Rejected, diff, effect_from_postmark, effect_from_smtp, strict_json
from .store import Ledger

UNSUPPORTED_TEMPLATE = "template sends are not supported: the rendered content cannot be compared with an approval"


class Relay:
    def __init__(self, ledger: Ledger, mailpit_smtp: tuple[str, int], mode: str = "enforce"):
        assert mode in ("enforce", "passthrough")
        self.ledger, self.mailpit, self.mode = ledger, mailpit_smtp, mode
        self.fault: str | None = None  # "ack-timeout-once": deliver, then report a timeout to the connector

    # --- forwarding ---
    def _deliver(self, sender: str, to, cc, bcc, reply_to, subject: str, text: str, html: str,
                 attachments: list[tuple[str, str, bytes]], extra_headers: list[tuple[str, str]] | None = None) -> str:
        msg = EmailMessage()
        message_id = f"<{uuid.uuid4().hex}@wirebound.lab>"
        msg["Message-ID"] = message_id
        msg["Date"] = format_datetime(dt.datetime.now(dt.timezone.utc))
        msg["From"] = sender
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)
        if reply_to:
            msg["Reply-To"] = ", ".join(reply_to)
        msg["Subject"] = subject
        for name, value in extra_headers or []:
            msg[name] = value
        if text or not html:
            msg.set_content(text or "")
            if html:
                msg.add_alternative(html, subtype="html")
        else:
            msg.set_content(html, subtype="html")
        for name, ctype, data in attachments:
            maintype, _, subtype = ctype.partition("/")
            msg.add_attachment(data, maintype=maintype or "application", subtype=subtype or "octet-stream", filename=name)
        envelope = list(dict.fromkeys([*to, *cc, *bcc]))
        with smtplib.SMTP(*self.mailpit, timeout=10) as s:
            s.send_message(msg, from_addr=sender, to_addrs=envelope)
        return message_id

    @staticmethod
    def _postmark_attachments(msg: dict) -> list[tuple[str, str, bytes]]:
        return [(a["Name"], str(a["ContentType"]).strip().lower(), base64.b64decode(a["Content"]))
                for a in (msg.get("Attachments") or [])]

    def _deliver_effect(self, e: Effect, attachments) -> str:
        return self._deliver(e.sender, e.to, e.cc, e.bcc, e.reply_to, e.subject, e.text, e.html, attachments)

    # --- enforcement ---
    def _closest(self, effect: Effect, session: str):
        """The approved artefact most similar to `effect` in this session, for the rejection diff."""
        best, best_score = None, -1
        for art in self.ledger.session_artifacts(session):
            c = json.loads(art["effect_json"])
            score = (c["subject"] == effect.subject) * 4 + len(set(c["to"]) & set(effect.to)) * 2 + (c["text"] == effect.text)
            if score > best_score:
                best, best_score = c, score
        if best is None:
            return None
        return Effect(sender=best["sender"], to=tuple(best["to"]), cc=tuple(best["cc"]), bcc=tuple(best["bcc"]),
                      reply_to=tuple(best["reply_to"]), subject=best["subject"], text=best["text"], html=best["html"],
                      attachments=tuple(Attachment(a["name"], a["content_type"], a["sha256"]) for a in best["attachments"]),
                      stream=best["stream"])

    def enforce(self, channel: str, endpoint: str, effect: Effect, attachments, session: str, meta=None) -> dict:
        digest = effect.digest()
        send_id = self.ledger.consume(digest, session)
        if send_id is None:
            reasons = diff(self._closest(effect, session), effect)
            self.ledger.record_send(channel, endpoint, digest, None, "REJECTED", reasons, effect=effect.canonical(), meta=meta)
            return {"ok": False, "reasons": reasons, "digest": digest}
        row = self.ledger.record_send(channel, endpoint, digest, send_id, "DISPATCHING", effect=effect.canonical(), meta=meta)
        try:
            provider_id = self._deliver_effect(effect, attachments)
        except (OSError, smtplib.SMTPException) as exc:
            self.ledger.update_send(row, "UNKNOWN")
            return {"ok": False, "unknown": True, "reasons": [f"provider result unknown: {exc}"], "send_id": send_id}
        if self.fault == "ack-timeout-once":
            self.fault = None
            self.ledger.update_send(row, "UNKNOWN", provider_id)
            return {"ok": False, "unknown": True, "reasons": ["provider acknowledgement lost (injected fault)"],
                    "send_id": send_id}
        self.ledger.update_send(row, "DELIVERED", provider_id)
        return {"ok": True, "send_id": send_id, "provider_id": provider_id, "digest": digest}

    # --- permissive provider model (baselines only) ---
    def passthrough_postmark(self, endpoint: str, msg: dict) -> dict:
        low = {k.lower(): v for k, v in msg.items()}  # case-insensitive keys, last duplicate wins (json default)
        def addrs(v):
            return [a.strip() for a in (",".join(v) if isinstance(v, list) else str(v or "")).split(",") if a.strip()]
        extra, extra_bcc = [], []
        for h in low.get("headers") or []:
            if str(h.get("Name", "")).lower() == "bcc":
                extra_bcc += addrs(h.get("Value"))
            else:
                extra.append((h.get("Name"), h.get("Value")))
        atts = [(a.get("Name"), a.get("ContentType", "application/octet-stream"), base64.b64decode(a.get("Content", "")))
                for a in (low.get("attachments") or [])]
        pid = self._deliver(low.get("from"), addrs(low.get("to")), addrs(low.get("cc")), addrs(low.get("bcc")) + extra_bcc,
                            addrs(low.get("replyto")), low.get("subject") or "", low.get("textbody") or "",
                            low.get("htmlbody") or "", atts, extra)
        self.ledger.record_send("https", endpoint, None, None, "DELIVERED", ["passthrough"], pid)
        return {"ok": True, "provider_id": pid}

    def handle_postmark_message(self, endpoint: str, msg, session: str = "default") -> dict:
        if self.mode == "passthrough":
            return self.passthrough_postmark(endpoint, msg)
        try:
            effect, meta = effect_from_postmark(msg)
        except Rejected as exc:
            self.ledger.record_send("https", endpoint, None, None, "REJECTED", [str(exc)])
            return {"ok": False, "reasons": [str(exc)]}
        return self.enforce("https", endpoint, effect, self._postmark_attachments(msg), session, meta)

    # --- SMTP ---
    def handle_smtp(self, mail_from: str, rcpt_tos: list[str], data: bytes, session: str = "default") -> dict:
        if self.mode == "passthrough":
            with smtplib.SMTP(*self.mailpit, timeout=10) as s:
                s.sendmail(mail_from, rcpt_tos, data)
            self.ledger.record_send("smtp", "DATA", None, None, "DELIVERED", ["passthrough"])
            return {"ok": True}
        try:
            effect = effect_from_smtp(mail_from, rcpt_tos, data)
        except Rejected as exc:
            self.ledger.record_send("smtp", "DATA", None, None, "REJECTED", [str(exc)])
            return {"ok": False, "reasons": [str(exc)]}
        from email import policy
        from email.parser import BytesParser
        parsed = BytesParser(policy=policy.default).parsebytes(data)
        atts = [(p.get_filename() or "", p.get_content_type(), p.get_payload(decode=True) or b"")
                for p in parsed.walk() if not p.is_multipart() and p.get_content_disposition() == "attachment"]
        return self.enforce("smtp", "DATA", effect, atts, session)


def postmark_app(relay: Relay) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def response(result: dict, to: str = ""):
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        if result.get("ok"):
            return {"To": to, "SubmittedAt": now, "MessageID": result.get("provider_id", "").strip("<>"),
                    "ErrorCode": 0, "Message": "OK"}
        code = 1001 if result.get("unknown") else 1000
        return {"To": to, "SubmittedAt": now, "ErrorCode": code,
                "Message": "Wirebound: " + "; ".join(result.get("reasons", []))}

    @app.get("/server")
    async def server():
        return {"ID": 1, "Name": "Wirebound lab relay", "ApiTokens": ["redacted"], "Color": "blue"}

    @app.post("/email")
    async def email(request: Request):
        raw = await request.body()
        try:
            msg = strict_json(raw) if relay.mode == "enforce" else json.loads(raw)
        except Rejected as exc:
            relay.ledger.record_send("https", "/email", None, None, "REJECTED", [str(exc)])
            return JSONResponse(response({"ok": False, "reasons": [str(exc)]}), status_code=422)
        result = relay.handle_postmark_message("/email", msg, request.headers.get("x-postmark-server-token", "default"))
        status = 200 if result.get("ok") else (504 if result.get("unknown") else 422)
        return JSONResponse(response(result, str(msg.get("To", "")) if isinstance(msg, dict) else ""), status_code=status)

    @app.post("/email/batch")
    async def batch(request: Request):
        raw = await request.body()
        try:
            msgs = strict_json(raw) if relay.mode == "enforce" else json.loads(raw)
        except Rejected as exc:
            return JSONResponse([response({"ok": False, "reasons": [str(exc)]})], status_code=422)
        if not isinstance(msgs, list) or not 1 <= len(msgs) <= 500:
            return JSONResponse([response({"ok": False, "reasons": ["batch must be a list of 1-500 messages"]})], 422)
        session = request.headers.get("x-postmark-server-token", "default")
        return [response(relay.handle_postmark_message("/email/batch", m, session), str(m.get("To", "")) if isinstance(m, dict) else "")
                for m in msgs]

    @app.post("/email/withTemplate")
    @app.post("/email/batchWithTemplates")
    async def templates(request: Request):
        relay.ledger.record_send("https", request.url.path, None, None, "REJECTED", [UNSUPPORTED_TEMPLATE])
        return JSONResponse(response({"ok": False, "reasons": [UNSUPPORTED_TEMPLATE]}), status_code=422)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def other(path: str, request: Request):
        relay.ledger.record_send("https", "/" + path, None, None, "REJECTED", ["endpoint not supported by the relay"])
        return JSONResponse({"ErrorCode": 1002, "Message": "Wirebound: endpoint not supported"}, status_code=404)

    return app
