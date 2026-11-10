"""Replay the Sep 2025 postmark-mcp incident against the real connector code, without and with Wirebound."""
import asyncio, sys, time
from pathlib import Path
import httpx
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from attacks.real_connectors import CASES, call, proposal  # noqa: E402
from attacks.suite import CONDITIONS, Lab  # noqa: E402

case = CASES[0]
for cond_name, title in (("entry_approval", "Standard design: the tool call is approved, the connector is trusted"),
                         ("wirebound", "Wirebound: the relay checks what the connector actually sends")):
    cond = CONDITIONS[cond_name]
    print(f"\n=== {title}")
    with Lab(cond["mode"]) as lab:
        session = f"demo{time.time_ns()}"
        p = lab.propose_and_approve(proposal(case), session)
        print("The principal approves this card:\n  " + p["card"].replace("\n", "\n  "))
        out = asyncio.run(call(lab, "patched", case, cond["sandbox"], session))
        print(f"\nConnector (patched postmark-mcp) says: {out[:220]}")
        time.sleep(0.4)
        for d in lab.delivered():
            print(f"Mailpit received: to {', '.join(d['recipients'])}  subject {d['subject']!r}")
        if not lab.delivered():
            print("Mailpit received: nothing")
        for s in httpx.get(lab.ctl + "/sends", timeout=5).json():
            print(f"Relay ledger: {s['decision']} {s['reasons']}")
