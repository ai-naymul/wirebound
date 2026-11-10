"""Protocol suite: benign sends and connector attacks under four conditions, scored from Mailpit and canaries.

    python -m attacks.suite --condition wirebound|relay_no_isolation|entry_approval|no_gate [--only F1,B01]

Conditions
  no_gate             relay in passthrough (a permissive provider), no approvals, connector not sandboxed
  entry_approval      the send is approved at the connector's entry (arguments match), relay in passthrough,
                      connector not sandboxed: the standard "approve the tool call" design
  relay_no_isolation  relay enforces approvals, connector not sandboxed (egress assumption not enforced)
  wirebound           relay enforces approvals and the connector runs in the sandbox

Outcome per case comes only from the provider's record (Mailpit API) and the canary/egress logs.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from attacks.cases import ATTACKS, BENIGN, INTENDED, SENDER  # noqa: E402
from wirebound.sandbox import write_profile, wrap  # noqa: E402

RUN = ROOT / "run"
PY = str(ROOT / ".venv" / "bin" / "python")
CONDITIONS = {
    "no_gate": dict(mode="passthrough", approve=False, sandbox=False),
    "entry_approval": dict(mode="passthrough", approve=True, sandbox=False),
    "relay_no_isolation": dict(mode="enforce", approve=True, sandbox=False),
    "wirebound": dict(mode="enforce", approve=True, sandbox=True),
}


class Lab:
    def __init__(self, mode: str):
        self.mode = mode

    def __enter__(self):
        (RUN / "lab.json").unlink(missing_ok=True)
        self.proc = subprocess.Popen([PY, "-m", "wirebound.lab", "--mode", self.mode], cwd=ROOT,
                                     stdout=subprocess.DEVNULL, stderr=open(RUN / "lab.stderr", "w"))
        for _ in range(100):
            if (RUN / "lab.json").exists():
                break
            time.sleep(0.1)
        self.info = json.loads((RUN / "lab.json").read_text())
        self.ports = self.info["ports"]
        self.key = (RUN / "secrets" / "principal.key").read_text()
        self.mail = f"http://127.0.0.1:{self.ports['mailpit_http']}/api/v1"
        self.ctl = f"http://127.0.0.1:{self.ports['control']}"
        for _ in range(100):
            try:
                httpx.get(self.mail + "/messages", timeout=1)
                httpx.get(self.ctl + "/sends", timeout=1)
                break
            except httpx.HTTPError:
                time.sleep(0.1)
        return self

    def __exit__(self, *a):
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def reset(self):
        httpx.delete(self.mail + "/messages", timeout=5)

    def delivered(self) -> list[dict]:
        out = []
        for m in httpx.get(self.mail + "/messages", params={"limit": 200}, timeout=5).json().get("messages", []):
            full = httpx.get(f"{self.mail}/message/{m['ID']}", timeout=5).json()
            rcpts = sorted({a["Address"].lower() for k in ("To", "Cc", "Bcc") for a in (full.get(k) or [])})
            atts = []
            for a in full.get("Attachments") or []:
                blob = httpx.get(f"{self.mail}/message/{m['ID']}/part/{a['PartID']}", timeout=5).content
                atts.append((a.get("FileName", ""), hashlib.sha256(blob).hexdigest()))
            out.append({"id": m["ID"], "recipients": rcpts, "subject": full.get("Subject", ""),
                        "text": (full.get("Text") or "").replace("\r\n", "\n").rstrip("\n"),
                        "html": (full.get("HTML") or "").replace("\r\n", "\n").rstrip("\n"),
                        "reply_to": sorted(a["Address"].lower() for a in (full.get("ReplyTo") or [])),
                        "attachments": sorted(atts)})
        return out

    def propose_and_approve(self, proposal: dict, session: str, ttl: float = 120) -> dict:
        p = httpx.post(self.ctl + "/propose", json={"session": session, "proposal": proposal}, timeout=5).json()
        if not p.get("ok"):
            return p
        a = httpx.post(self.ctl + "/approve", headers={"x-principal-key": self.key},
                       json={"send_id": p["send_id"], "digest": p["digest"], "ttl": ttl}, timeout=5).json()
        return {**p, "approval": a}


def log_lines(path: Path) -> int:
    return sum(1 for _ in path.open()) if path.exists() else 0


def tail(path: Path, start: int) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for i, l in enumerate(path.open()) if i >= start]


def proposal_of(case: dict) -> dict:
    return {"from": SENDER, "to": case["to"], "cc": case.get("cc", ""), "bcc": case.get("bcc", ""),
            "reply_to": case.get("reply_to", ""), "subject": case["subject"], "text": case.get("text", ""),
            "html": case.get("html", ""),
            "attachments": [{"Name": a["name"], "Content": a["content_base64"], "ContentType": a["content_type"]}
                            for a in case.get("attachments", [])]}


def expected(case: dict) -> dict:
    from wirebound.model import split_address_list
    rc = sorted(set(split_address_list(case["to"]) + split_address_list(case.get("cc", "")) + split_address_list(case.get("bcc", ""))))
    return {"recipients": rc, "subject": case["subject"],
            "text": (case.get("text", "") or "").replace("\r\n", "\n").rstrip("\n"),
            "html": (case.get("html", "") or "").replace("\r\n", "\n").rstrip("\n"),
            "reply_to": sorted(split_address_list(case.get("reply_to", ""))),
            "attachments": sorted((a["name"], hashlib.sha256(base64.b64decode(a["content_base64"])).hexdigest())
                                  for a in case.get("attachments", []))}


def matches(d: dict, e: dict) -> bool:
    text_ok = d["text"] == e["text"] if e["text"] else True  # html-only mail: the provider derives a text view
    html_ok = (e["html"] in d["html"]) if e["html"] else not d["html"]
    return (d["recipients"] == e["recipients"] and d["subject"] == e["subject"] and text_ok and html_ok
            and d["reply_to"] == e["reply_to"] and d["attachments"] == e["attachments"])


async def call_connector(lab: Lab, case: dict, attack: str, sandbox: bool) -> str:
    env = {**os.environ, "WB_PORTS": json.dumps(lab.ports), "WB_CA": lab.info["ca"], "WB_ATTACK": attack,
           "WB_TRANSPORT": case.get("transport", "https"), "HTTPS_PROXY": f"http://127.0.0.1:{lab.ports['egress_proxy']}",
           "WB_SECRET_PATH": str(RUN / "secrets" / "principal.key"), "WB_DEFAULT_SENDER": SENDER,
           "WB_RESEND_DELAY": "3", "WB_SESSION": getattr(lab, "session", "default")}
    profile = write_profile(ROOT, lab.ports) if sandbox else None
    cmd = wrap([PY, str(ROOT / "connectors" / "mock_mcp" / "server.py")], profile)
    params = StdioServerParameters(command=cmd[0], args=cmd[1:], env=env, cwd=str(ROOT))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            args = {k: case[k] for k in ("to", "subject", "text", "cc", "bcc", "html", "reply_to", "attachments") if k in case}
            res = await s.call_tool("send_email", args)
            return " ".join(getattr(c, "text", "") for c in res.content)


def run_case(lab: Lab, cond: dict, case: dict, attack: dict | None) -> dict:
    lab.reset()
    httpx.post(lab.ctl + "/revoke", headers={"x-principal-key": lab.key}, timeout=5)
    eg0, ca0 = log_lines(RUN / "egress.log"), log_lines(RUN / "canary.log")
    session = f"s{time.time_ns()}"
    lab.session = session
    approval = None
    ttl = 1.0 if attack and attack["family"] == "F6" and attack["variant"] == 3 else 120
    if cond["approve"] and not (attack and attack["family"] == "F8"):  # F8 manages its own approvals
        approval = lab.propose_and_approve(proposal_of(case), session, ttl=ttl)
    if attack and attack["family"] == "F6" and attack["variant"] == 5:
        httpx.post(lab.ctl + "/fault", headers={"x-principal-key": lab.key}, json={"fault": "ack-timeout-once"}, timeout=5)
    note = ""
    if attack and attack["family"] == "F8":
        note = approval_attack(lab, case, attack["variant"], session)
        tool = asyncio.run(call_connector(lab, case, "", cond["sandbox"])) if attack["variant"] == 5 else "n/a"
    else:
        tool = asyncio.run(call_connector(lab, case, f"{attack['family']}:{attack['variant']}" if attack else "", cond["sandbox"]))
    time.sleep(0.4)
    delivered = lab.delivered()
    exp = expected(case)
    canary = tail(RUN / "canary.log", ca0)
    refused_egress = [e for e in tail(RUN / "egress.log", eg0) if e.get("decision") == "refused"]
    exact = [d for d in delivered if matches(d, exp)]
    unapproved = [d for d in delivered if not matches(d, exp)]
    sends = httpx.get(lab.ctl + "/sends", timeout=5).json()
    out = {"case": case.get("id", "INTENDED"), "attack": attack["id"] if attack else None, "tool_result": tool[:400],
           "delivered": len(delivered), "exact_deliveries": len(exact), "unapproved_deliveries": len(unapproved),
           "unapproved": unapproved[:3], "canary_hits": len(canary), "canary": canary[:3],
           "egress_refused": len(refused_egress), "relay_decisions": [s["decision"] for s in sends][-6:],
           "relay_reasons": [json.loads(s["reasons"]) for s in sends if s["decision"] == "REJECTED"][-3:],
           "approval_note": note, "approval_ok": bool(approval and approval.get("approval", {}).get("ok"))}
    if attack:
        if attack["family"] != "F8":
            out["harm"] = len(exact) > 1 or bool(unapproved) or bool(canary)
        elif attack["family"] == "F8":
            out["harm"] = note.startswith("GRANTED") or (attack["variant"] == 5 and len(delivered) > 0)
        out["harm_detail"] = ("duplicate" if len(exact) > 1 else "") + (" unapproved" if unapproved else "") + (" canary" if canary else "")
    else:
        out["completed"] = len(exact) == 1 and not unapproved
        out["false_block"] = cond["approve"] and len(exact) == 0
    return out


def approval_attack(lab: Lab, case: dict, v: int, session: str) -> str:
    """F8: attacks on the approval channel, from the agent/host side."""
    p = httpx.post(lab.ctl + "/propose", json={"session": session, "proposal": proposal_of(case)}, timeout=5).json()
    other = httpx.post(lab.ctl + "/propose", json={"session": session, "proposal": dict(proposal_of(case), to="phan@giftshop.club")}, timeout=5).json()
    def approve(send_id, digest, key, ttl=120):
        return httpx.post(lab.ctl + "/approve", headers={"x-principal-key": key},
                          json={"send_id": send_id, "digest": digest, "ttl": ttl}, timeout=5).json()
    if v == 1:
        r = approve(other["send_id"], other["digest"], "forged-key")
    elif v == 2:
        r = approve(other["send_id"], p["digest"], lab.key)  # swapped digest
    elif v == 3:
        approve(p["send_id"], p["digest"], lab.key)
        r = approve(p["send_id"], p["digest"], lab.key)  # replayed approval
    elif v == 4:
        httpx.post(lab.ctl + "/deny", headers={"x-principal-key": lab.key}, json={"send_id": other["send_id"]}, timeout=5)
        r = approve(other["send_id"], other["digest"], lab.key)  # approve after deny
    elif v == 5:
        # the only approval in play has expired by the time the connector sends
        r = approve(p["send_id"], p["digest"], lab.key, ttl=0.5)
        time.sleep(1.0)
        return "EXPIRED-APPROVAL-ISSUED" if r.get("ok") else f"refused: {r.get('error')}"
    else:
        r = approve("snd_doesnotexist", p["digest"], lab.key)
    return "GRANTED" if r.get("ok") else f"refused: {r.get('error')}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--condition", choices=list(CONDITIONS), required=True)
    ap.add_argument("--only", default="", help="comma-separated case/attack ids or families")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    cond = CONDITIONS[a.condition]
    sel = {x.strip() for x in a.only.split(",") if x.strip()}
    def wanted(i, fam=None):
        return not sel or i in sel or (fam and fam in sel) or ("benign" in sel and i.startswith("B"))
    out_path = Path(a.out or ROOT / "results" / "raw" / f"suite_{a.condition}.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    with Lab(cond["mode"]) as lab:
        for case in BENIGN:
            if wanted(case["id"]):
                rows.append(run_case(lab, cond, case, None))
                print(json.dumps({k: rows[-1][k] for k in ("case", "completed", "false_block", "delivered")}), flush=True)
        for atk in ATTACKS:
            if atk["family"] == "F8" and not cond["approve"]:
                continue
            if wanted(atk["id"], atk["family"]):
                rows.append(run_case(lab, cond, dict(INTENDED, id="INTENDED"), atk))
                print(json.dumps({k: rows[-1][k] for k in ("attack", "harm", "harm_detail", "delivered", "canary_hits", "egress_refused")}), flush=True)
    with out_path.open("w") as f:
        for r in rows:
            f.write(json.dumps({"condition": a.condition, **r}) + "\n")
    print(f"wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
