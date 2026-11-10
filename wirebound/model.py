"""The effect model: what a delivered email actually does, in canonical form.

An Effect is the part of a message that matters once it is delivered: who receives it (every envelope
recipient, whether it was listed in To, Cc, Bcc or smuggled in some other way), who it claims to come from,
where replies go, and the exact content and attachments. Approvals are bound to the SHA-256 digest of the
RFC 8785 canonical JSON of an Effect, and the relay recomputes that digest from what the connector really sent.

Parsing is deliberately strict (fail closed): anything ambiguous, unusual or that two parsers might read
differently is rejected instead of interpreted.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field

import rfc8785


class Rejected(ValueError):
    """The message is ambiguous, malformed or unsupported; it must not be forwarded."""


# addr-spec subset: no quotes, comments, groups, routes or whitespace. Local part: RFC 5322 atext plus dots.
_LOCAL = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_ADDR_RE = re.compile(rf"^({_LOCAL})@((?:{_LABEL}\.)+{_LABEL})$")
_DISPLAY_RE = re.compile(r"^([^<>\"(),;:\\@\x00-\x1f\x7f]*)<([^<>\s]+)>$")
MAX_RECIPIENTS = 50


def canonical_address(raw: str) -> str:
    """Return the canonical form of one address, or raise Rejected."""
    s = raw.strip()
    if not s or any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise Rejected(f"empty address or control character: {raw!r}")
    m = _DISPLAY_RE.match(s)
    if m:  # "Display Name <addr>": the display name is not part of the effect, the address is
        s = m.group(2).strip()
    if "@" not in s or s.count("@") != 1:
        raise Rejected(f"not a single address: {raw!r}")
    local, domain = s.rsplit("@", 1)
    try:
        domain_ascii = domain.encode("idna").decode("ascii") if any(ord(c) > 127 for c in domain) else domain
    except UnicodeError as exc:
        raise Rejected(f"invalid internationalised domain: {raw!r}") from exc
    candidate = f"{local}@{domain_ascii}"
    if not _ADDR_RE.match(candidate) or len(candidate) > 254:
        raise Rejected(f"address outside the supported grammar: {raw!r}")
    return candidate.lower()


def split_address_list(field_value) -> list[str]:
    """Parse a Postmark-style address field (comma-separated string, or a list of strings)."""
    if field_value is None or field_value == "":
        return []
    items = field_value if isinstance(field_value, list) else [field_value]
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise Rejected(f"address field item is not a string: {item!r}")
        if any(ch in item for ch in ('"', "(", ")", ";", "\\")) or "=?" in item:
            raise Rejected(f"quoted, commented, grouped or encoded address syntax is not supported: {item!r}")
        for part in item.split(","):
            if part.strip():
                out.append(canonical_address(part))
    return out


def canonical_text(value, name: str, body: bool = False) -> str:
    """NFC, LF line endings; for bodies also drop trailing newlines (transports add or remove them)."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise Rejected(f"{name} must be a string")
    out = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    return out.rstrip("\n") if body else out


@dataclass(frozen=True)
class Attachment:
    name: str
    content_type: str
    sha256: str


@dataclass(frozen=True)
class Effect:
    sender: str
    to: tuple[str, ...]
    cc: tuple[str, ...]
    bcc: tuple[str, ...]
    reply_to: tuple[str, ...]
    subject: str
    text: str
    html: str
    attachments: tuple[Attachment, ...] = field(default_factory=tuple)
    stream: str = "outbound"

    @property
    def recipients(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.to) | set(self.cc) | set(self.bcc)))

    def canonical(self) -> dict:
        return {
            "sender": self.sender,
            "to": sorted(set(self.to)), "cc": sorted(set(self.cc)), "bcc": sorted(set(self.bcc)),
            "reply_to": sorted(set(self.reply_to)),
            "subject": self.subject, "text": self.text, "html": self.html,
            "attachments": sorted([{"name": a.name, "content_type": a.content_type, "sha256": a.sha256}
                                   for a in self.attachments], key=lambda a: (a["name"], a["sha256"])),
            "stream": self.stream,
        }

    def digest(self) -> str:
        return hashlib.sha256(rfc8785.dumps(self.canonical())).hexdigest()


def diff(approved: Effect | None, actual: Effect) -> list[str]:
    """Human-readable differences between an approved effect and the actual one."""
    if approved is None:
        return ["no matching approval exists for this message"]
    a, b = approved.canonical(), actual.canonical()
    out = []
    for key in ("to", "cc", "bcc", "reply_to"):
        added = sorted(set(b[key]) - set(a[key]))
        removed = sorted(set(a[key]) - set(b[key]))
        if added:
            out.append(f"{key}: added {', '.join(added)} (not approved)")
        if removed:
            out.append(f"{key}: removed {', '.join(removed)}")
    for key in ("sender", "subject", "text", "html", "stream"):
        if a[key] != b[key]:
            out.append(f"{key}: changed from {a[key][:60]!r} to {b[key][:60]!r}")
    if a["attachments"] != b["attachments"]:
        out.append(f"attachments: changed from {[x['name'] for x in a['attachments']]} "
                   f"to {[x['name'] for x in b['attachments']]}")
    return out


# --- Postmark JSON -> Effect -------------------------------------------------------------------------

# Fields the relay understands. Anything else is rejected rather than ignored.
_POSTMARK_FIELDS = {"From", "To", "Cc", "Bcc", "Subject", "Tag", "HtmlBody", "TextBody", "ReplyTo", "Headers",
                    "TrackOpens", "TrackLinks", "Metadata", "Attachments", "MessageStream"}
# Header names that change who receives or how a message is routed. Smuggling them through Headers is rejected.
_ROUTING_HEADERS = {"to", "cc", "bcc", "from", "sender", "reply-to", "resent-to", "resent-cc", "resent-bcc",
                    "resent-from", "return-path", "delivered-to", "x-original-to", "content-type",
                    "content-transfer-encoding", "mime-version"}


def strict_json(raw: bytes):
    """Parse JSON, rejecting duplicate keys (a classic parser-differential vector)."""
    def no_dupes(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise Rejected(f"duplicate JSON keys: {sorted({k for k in keys if keys.count(k) > 1})}")
        lowered = [k.lower() for k in keys]
        if len(lowered) != len(set(lowered)):
            raise Rejected("JSON keys that differ only in case")
        return dict(pairs)
    try:
        return json.loads(raw, object_pairs_hook=no_dupes)
    except Rejected:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise Rejected(f"invalid JSON: {exc}") from exc


def effect_from_postmark(msg: dict) -> tuple[Effect, dict]:
    """Return (effect, provider_metadata). provider_metadata holds fields recorded but not part of the effect."""
    if not isinstance(msg, dict):
        raise Rejected("message must be a JSON object")
    unknown = set(msg) - _POSTMARK_FIELDS
    if unknown:
        raise Rejected(f"unsupported fields: {sorted(unknown)}")
    headers = msg.get("Headers") or []
    if not isinstance(headers, list):
        raise Rejected("Headers must be a list")
    for h in headers:
        if not isinstance(h, dict) or set(h) != {"Name", "Value"}:
            raise Rejected("malformed header entry")
        if str(h["Name"]).strip().lower() in _ROUTING_HEADERS:
            raise Rejected(f"routing header supplied through Headers: {h['Name']!r}")
    if headers:
        raise Rejected("custom headers are not supported in v1")
    senders = split_address_list(msg.get("From"))
    if len(senders) != 1:
        raise Rejected("exactly one From address is required")
    to, cc, bcc = (split_address_list(msg.get(k)) for k in ("To", "Cc", "Bcc"))
    if not to:
        raise Rejected("To is required")
    if len(to) + len(cc) + len(bcc) > MAX_RECIPIENTS:
        raise Rejected("too many recipients")
    attachments = []
    for att in msg.get("Attachments") or []:
        if not isinstance(att, dict) or not {"Name", "Content", "ContentType"} <= set(att) or set(att) - {"Name", "Content", "ContentType", "ContentID"}:
            raise Rejected("malformed attachment")
        try:
            data = base64.b64decode(att["Content"], validate=True)
        except (ValueError, TypeError) as exc:
            raise Rejected("attachment content is not valid base64") from exc
        attachments.append(Attachment(canonical_text(att["Name"], "attachment name"),
                                      str(att["ContentType"]).strip().lower(), hashlib.sha256(data).hexdigest()))
    effect = Effect(sender=senders[0], to=tuple(to), cc=tuple(cc), bcc=tuple(bcc),
                    reply_to=tuple(split_address_list(msg.get("ReplyTo"))),
                    subject=canonical_text(msg.get("Subject"), "Subject"),
                    text=canonical_text(msg.get("TextBody"), "TextBody", body=True),
                    html=canonical_text(msg.get("HtmlBody"), "HtmlBody", body=True),
                    attachments=tuple(attachments), stream=str(msg.get("MessageStream") or "outbound"))
    meta = {k: msg.get(k) for k in ("Tag", "Metadata", "TrackOpens", "TrackLinks") if k in msg}
    return effect, meta


def effect_from_proposal(p: dict) -> Effect:
    """Build the effect a principal is asked to approve, from a send proposal (tool arguments)."""
    return effect_from_postmark({k: v for k, v in {
        "From": p.get("from"), "To": p.get("to"), "Cc": p.get("cc"), "Bcc": p.get("bcc"),
        "ReplyTo": p.get("reply_to"), "Subject": p.get("subject"), "TextBody": p.get("text"),
        "HtmlBody": p.get("html"), "Attachments": p.get("attachments"),
        "MessageStream": p.get("stream")}.items() if v not in (None, "", [])})[0]


# --- SMTP envelope + MIME -> Effect ---------------------------------------------------------------------

def effect_from_smtp(mail_from: str, rcpt_tos: list[str], data: bytes) -> Effect:
    """Effect of an SMTP submission. Envelope recipients absent from To/Cc are what a Bcc really is."""
    from email import policy
    from email.parser import BytesParser

    msg = BytesParser(policy=policy.default).parsebytes(data)
    for name in ("From", "To", "Cc", "Bcc", "Reply-To", "Subject", "Sender"):
        if len(msg.get_all(name) or []) > 1:
            raise Rejected(f"duplicate {name} header")
    for name in ("Resent-To", "Resent-Cc", "Resent-Bcc", "Resent-From"):
        if msg.get_all(name):
            raise Rejected(f"{name} header is not supported")

    def header_addrs(name: str) -> list[str]:
        raw = msg.get(name)
        if raw is None:
            return []
        text = str(raw)
        return split_address_list(text.replace("\n", " ").replace("\r", " ")) if text.strip() else []

    sender_hdr = header_addrs("From")
    if len(sender_hdr) != 1:
        raise Rejected("exactly one From address is required")
    envelope_from = canonical_address(mail_from)
    if envelope_from != sender_hdr[0]:
        raise Rejected("envelope sender differs from the From header")
    to, cc = header_addrs("To"), header_addrs("Cc")
    envelope = [canonical_address(r) for r in rcpt_tos]
    if len(envelope) != len(set(envelope)):
        raise Rejected("duplicate envelope recipients")
    listed = set(to) | set(cc)
    if not set(listed) <= set(envelope):
        raise Rejected("a To/Cc header recipient is missing from the envelope")
    bcc = sorted(set(envelope) - listed)
    if not to or len(envelope) > MAX_RECIPIENTS:
        raise Rejected("To is required and recipients are limited")

    text = html = ""
    attachments: list[Attachment] = []
    ctype = msg.get_content_type()
    if ctype == "text/plain":
        text = msg.get_content()
    elif ctype == "text/html":
        html = msg.get_content()
    elif ctype in ("multipart/alternative", "multipart/mixed"):
        for part in msg.walk():
            if part.is_multipart():
                if part.get_content_type() not in ("multipart/alternative", "multipart/mixed"):
                    raise Rejected(f"unsupported multipart type {part.get_content_type()}")
                continue
            disposition = part.get_content_disposition()
            pt = part.get_content_type()
            if disposition == "attachment":
                payload = part.get_payload(decode=True) or b""
                attachments.append(Attachment(canonical_text(part.get_filename() or "", "attachment name"),
                                              pt, hashlib.sha256(payload).hexdigest()))
            elif pt == "text/plain" and not text:
                text = part.get_content()
            elif pt == "text/html" and not html:
                html = part.get_content()
            else:
                raise Rejected(f"unsupported MIME part {pt}")
    else:
        raise Rejected(f"unsupported content type {ctype}")
    return Effect(sender=sender_hdr[0], to=tuple(to), cc=tuple(cc), bcc=tuple(bcc),
                  reply_to=tuple(header_addrs("Reply-To")),
                  subject=canonical_text(str(msg.get("Subject") or ""), "Subject"),
                  text=canonical_text(text, "text", body=True), html=canonical_text(html, "html", body=True),
                  attachments=tuple(attachments))
