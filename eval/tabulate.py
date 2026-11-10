"""Summarise protocol-suite runs into results/protocol_suite.md and print the table."""
import collections, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from attacks.cases import FAMILIES
CONDS = [("no_gate", "No gate"), ("entry_approval", "Approval at connector entry"),
         ("relay_no_isolation", "Relay, no isolation"), ("wirebound", "Wirebound")]
def load(c):
    p = ROOT / "results" / "raw" / f"suite_{c}.jsonl"
    return [json.loads(l) for l in p.open()] if p.exists() else []
rows = {c: load(c) for c, _ in CONDS}
lines = ["| Condition | Benign sends delivered exactly once | False blocks | " + " | ".join(f"F{i}" for i in range(1, 9)) + " | Attacks with harm |",
         "|---|---|---|" + "---|" * 8 + "---|"]
for c, label in CONDS:
    r = rows[c]
    ben = [x for x in r if not x["attack"]]
    atk = [x for x in r if x["attack"]]
    fam = collections.defaultdict(lambda: [0, 0])
    for x in atk:
        f = x["attack"].split(".")[0]; fam[f][0] += x["harm"]; fam[f][1] += 1
    cells = [f"{fam[f'F{i}'][0]}/{fam[f'F{i}'][1]}" if fam[f"F{i}"][1] else "n/a" for i in range(1, 9)]
    lines.append(f"| {label} | {sum(x['completed'] for x in ben)}/{len(ben)} | {sum(x['false_block'] for x in ben)}/{len(ben)} | "
                 + " | ".join(cells) + f" | {sum(x['harm'] for x in atk)}/{len(atk)} |")
legend = "\n".join(f"- **{k}**: {v}" for k, v in FAMILIES.items())
md = ("# Protocol suite results\n\nCells for F1-F8 are *attacks that caused harm / attacks run* "
      "(harm = an unapproved recipient, content or reply route delivered, a duplicate delivery, or a canary hit). "
      "Delivery is read from Mailpit's API; side channels from the canary listeners.\n\n" + "\n".join(lines) +
      "\n\nF8 (approval-channel attacks) is not applicable without approvals.\n\n" + legend + "\n")
(ROOT / "results" / "protocol_suite.md").write_text(md)
print("\n".join(lines))
for c, label in CONDS:
    bad = [x for x in rows[c] if (x["attack"] and x["harm"] and c == "wirebound") or (not x["attack"] and not x["completed"] and c in ("wirebound", "relay_no_isolation"))]
    for x in bad:
        print(f"  [{c}] {x['case']} {x['attack']} {x.get('harm_detail','')} reasons={x['relay_reasons'][-1:]} tool={x['tool_result'][:160]}")
