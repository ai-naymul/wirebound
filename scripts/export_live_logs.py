"""Copy the live-agent run logs into results/live/runs/ for publication, with local paths replaced.

    python scripts/export_live_logs.py

For every run recorded in results/live/runs.jsonl it copies, from run/live/<run>/:
  task.json         the workspace and instruction the agent got
  transcript.jsonl  the agent CLI's own event stream (codex --json / claude stream-json)
  gate.jsonl        every tool call, approval card, approval decision and connector answer
Home and temp-directory paths are replaced with ~ and $TMPDIR. Lab session tokens are random per run and
carry no secret.
"""
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "run" / "live"
DST = ROOT / "results" / "live" / "runs"
HOME = os.path.expanduser("~")
TMP = re.compile(r"/(?:private/)?var/folders/[^/\"]+/[^/\"]+/T")
HOME_SLUG = re.compile(re.escape("-" + HOME.strip("/").replace("/", "-")))


def clean(text: str) -> str:
    text = TMP.sub("$TMPDIR", text)
    text = text.replace(HOME, "~")
    return HOME_SLUG.sub("-HOME", text)


def main():
    keys = [json.loads(l)["run_dir"] for l in (ROOT / "results" / "live" / "runs.jsonl").read_text().splitlines()]
    n = 0
    for rel in keys:
        src = ROOT / rel
        dst = DST / src.name
        dst.mkdir(parents=True, exist_ok=True)
        for name in ("task.json", "transcript.jsonl", "gate.jsonl"):
            if (src / name).exists():
                (dst / name).write_text(clean((src / name).read_text()))
        n += 1
    leftover = [p for p in DST.rglob("*") if p.is_file() and HOME in p.read_text()]
    print(f"exported {n} runs to {DST.relative_to(ROOT)}; files still containing the home path: {len(leftover)}")


if __name__ == "__main__":
    main()
