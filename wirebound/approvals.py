"""Composer and approver: turn a send proposal into a frozen artefact and record a principal's approval.

The approval card is rendered from the artefact itself (the exact recipients, content digest and attachment
hashes the relay will enforce), never from the agent's description of the send. Approving requires the
principal key, which lives outside the connector's sandbox (file reads of run/secrets are denied there and the
approver port is unreachable from it).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

from .model import Effect, Rejected, effect_from_proposal
from .store import Ledger

DEFAULT_TTL = 120.0


def render_card(send_id: str, effect: Effect, ttl: float) -> str:
    c = effect.canonical()
    lines = [f"Send {send_id}  (expires in {int(ttl)} s)",
             f"From:     {c['sender']}",
             f"To:       {', '.join(c['to'])}"]
    if c["cc"]:
        lines.append(f"Cc:       {', '.join(c['cc'])}")
    lines.append(f"Bcc:      {', '.join(c['bcc']) if c['bcc'] else '(none)'}")
    if c["reply_to"]:
        lines.append(f"Reply-To: {', '.join(c['reply_to'])}")
    lines.append(f"Subject:  {c['subject']}")
    body = c["text"] or c["html"]
    lines.append("Body:     " + (body[:300] + ("…" if len(body) > 300 else "")).replace("\n", "\n          "))
    for a in c["attachments"]:
        lines.append(f"Attach:   {a['name']} ({a['content_type']}, sha256 {a['sha256'][:12]})")
    lines.append(f"Digest:   {effect.digest()}")
    return "\n".join(lines)


class Approvals:
    def __init__(self, ledger: Ledger, principal_key: bytes):
        self.ledger = ledger
        self.key = principal_key

    def propose(self, session: str, proposal: dict) -> dict:
        try:
            effect = effect_from_proposal(proposal)
        except Rejected as exc:
            return {"ok": False, "error": f"proposal rejected: {exc}"}
        send_id = "snd_" + secrets.token_hex(8)
        digest = effect.digest()
        self.ledger.prepare(send_id, session, digest, effect.canonical())
        return {"ok": True, "send_id": send_id, "digest": digest, "card": render_card(send_id, effect, DEFAULT_TTL)}

    def token(self, send_id: str, digest: str, expiry: float, nonce: str) -> str:
        payload = json.dumps({"send_id": send_id, "digest": digest, "exp": expiry, "nonce": nonce}, sort_keys=True)
        mac = hmac.new(self.key, payload.encode(), hashlib.sha256).hexdigest()
        return payload + "." + mac

    def approve(self, send_id: str, digest: str, principal_key: bytes, ttl: float = DEFAULT_TTL,
                approver: str = "principal") -> dict:
        if not hmac.compare_digest(principal_key, self.key):
            return {"ok": False, "error": "approval refused: principal authentication failed"}
        art = self.ledger.artifact(send_id)
        if art is None:
            return {"ok": False, "error": "approval refused: unknown send_id"}
        if art["digest"] != digest:
            return {"ok": False, "error": "approval refused: digest does not match the prepared artefact"}
        if art["state"] != "PREPARED":
            return {"ok": False, "error": f"approval refused: artefact is {art['state']}"}
        expiry, nonce = time.time() + ttl, secrets.token_hex(8)
        if not self.ledger.authorize(send_id, digest, expiry, approver, nonce):
            return {"ok": False, "error": "approval refused: concurrent state change"}
        return {"ok": True, "token": self.token(send_id, digest, expiry, nonce), "expiry": expiry}

    def deny(self, send_id: str) -> None:
        self.ledger.deny(send_id)
