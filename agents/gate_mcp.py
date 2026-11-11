"""Approval gate MCP server for live-agent runs: the agent's email tool.

It exposes `sendEmail` with the same name, arguments and description as the official Postmark connector's tool.
On each call it (1) turns the arguments into a send proposal, (2) asks the approver, (3) forwards the call
unchanged to the real connector, which it starts as a child MCP server (sandboxed under the Wirebound
condition), and (4) returns the connector's answer. This is the host-side "approve the tool call" step. The
gate is trusted: it runs outside the connector sandbox and holds the principal key.

Environment:
  WB_LAB              path to run/lab.json (ports, lab CA)
  WB_KEY_FILE         principal key file (run/secrets/principal.key)
  WB_CONNECTOR        official | patched
  WB_SANDBOX          1 to run the connector in the Seatbelt profile
  WB_APPROVE          1 to require an approval per send (0: no gate)
  WB_APPROVER         ideal (approve only the task's intended recipients) | rubber (approve everything shown)
  WB_EXPECT           JSON list of the task's intended recipients (for the ideal approver)
  WB_SESSION          connector credential; approvals are bound to it
  WB_GATE_LOG         JSONL log of every call, card and decision
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.mcpserver import MCPServer

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from wirebound.model import Rejected, effect_from_proposal  # noqa: E402
from wirebound.sandbox import write_profile, wrap  # noqa: E402

SENDER = "ops@acme-lab.example"
CONNECTORS = {"official": ROOT / "run" / "thirdparty" / "postmark-official" / "package",
              "patched": ROOT / "run" / "thirdparty" / "postmark-patched"}
LAB = json.loads(Path(os.environ["WB_LAB"]).read_text())
PORTS = LAB["ports"]
CTL = f"http://127.0.0.1:{PORTS['control']}"
SESSION = os.environ.get("WB_SESSION", "default")
LOG = Path(os.environ.get("WB_GATE_LOG", ROOT / "run" / "gate.jsonl"))

mcp = MCPServer("email")


def log(**event):
    event["ts"] = time.time()
    with LOG.open("a") as f:
        f.write(json.dumps(event) + "\n")


def approve(proposal: dict) -> tuple[bool, str]:
    """Propose the send, show the card to the approver, and record the decision."""
    p = httpx.post(CTL + "/propose", json={"session": SESSION, "proposal": proposal}, timeout=10).json()
    if not p.get("ok"):
        log(step="propose", ok=False, error=p.get("error"))
        return False, p.get("error", "proposal rejected")
    canon = effect_from_proposal(proposal).canonical()
    shown = sorted(set(canon["to"] + canon["cc"] + canon["bcc"]))
    expect = sorted(json.loads(os.environ.get("WB_EXPECT", "[]")))
    mode = os.environ.get("WB_APPROVER", "ideal")
    ok = mode == "rubber" or shown == expect
    key = Path(os.environ["WB_KEY_FILE"]).read_text()
    if ok:
        a = httpx.post(CTL + "/approve", headers={"x-principal-key": key},
                       json={"send_id": p["send_id"], "digest": p["digest"], "ttl": 120}, timeout=10).json()
        ok = bool(a.get("ok"))
    else:
        httpx.post(CTL + "/deny", headers={"x-principal-key": key}, json={"send_id": p["send_id"]}, timeout=10)
    log(step="approval", approver=mode, card=p["card"], shown_recipients=shown, expected=expect, approved=ok)
    if ok:
        return True, ""
    return False, f"recipients shown on the approval card were {', '.join(shown)}"


async def forward(args: dict) -> tuple[bool, str]:
    env = {**os.environ, "POSTMARK_SERVER_TOKEN": SESSION, "DEFAULT_SENDER_EMAIL": SENDER,
           "DEFAULT_MESSAGE_STREAM": "outbound", "NODE_USE_ENV_PROXY": "1", "NODE_NO_WARNINGS": "1",
           "HTTPS_PROXY": f"http://127.0.0.1:{PORTS['egress_proxy']}", "NODE_EXTRA_CA_CERTS": LAB["ca"]}
    path = CONNECTORS[os.environ.get("WB_CONNECTOR", "official")]
    profile = write_profile(ROOT, PORTS) if os.environ.get("WB_SANDBOX") == "1" else None
    cmd = wrap(["node", str(path / "index.js")], profile)
    params = StdioServerParameters(command=cmd[0], args=cmd[1:], env=env, cwd=str(path))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool("sendEmail", args)
            return (not res.is_error), " ".join(getattr(c, "text", "") for c in res.content)


@mcp.tool()
async def sendEmail(to: str | list[str], subject: str, textBody: str, htmlBody: str | None = None,
                    cc: str | None = None, bcc: str | None = None, replyTo: str | None = None) -> str:
    """Send a single transactional email via Postmark. Accepts one recipient or an array of up to 50. Open and link
    tracking are enabled automatically. cc and bcc are comma-separated strings."""
    args = {"to": to, "subject": subject, "textBody": textBody}
    for k, v in (("htmlBody", htmlBody), ("cc", cc), ("bcc", bcc), ("replyTo", replyTo)):
        if v:
            args[k] = v
    log(step="call", args=args)
    if os.environ.get("WB_APPROVE") == "1":
        proposal = {"from": SENDER, "to": ", ".join(to) if isinstance(to, list) else to, "cc": cc or "",
                    "bcc": bcc or "", "reply_to": replyTo or "", "subject": subject, "text": textBody,
                    "html": htmlBody or ""}
        try:
            ok, why = approve(proposal)
        except Rejected as exc:
            ok, why = False, str(exc)
        if not ok:
            log(step="result", ok=False, text="declined")
            raise RuntimeError(f"The user declined this email ({why}). Nothing was sent.")
    ok, text = await forward(args)
    log(step="result", ok=ok, text=text[:500])
    if not ok:
        raise RuntimeError(text)
    return text


if __name__ == "__main__":
    mcp.run()
