PY := .venv/bin/python
CONDITIONS := no_gate entry_approval relay_no_isolation wirebound

.PHONY: setup thirdparty test suite real tables verify demo live adaptive clean

setup:            ## Python 3.12 venv and dependencies (needs uv), Mailpit (needs Homebrew)
	uv venv --python 3.12 .venv
	uv pip install --python $(PY) -r requirements.txt
	command -v mailpit >/dev/null || brew install mailpit

thirdparty:       ## fetch the official Postmark MCP connector and build the defanged incident replay
	./scripts/thirdparty.sh

test:             ## unit tests: effect model, strict parsing, ledger, approval channel
	$(PY) -m pytest -q tests

suite:            ## protocol suite: 24 benign sends + 48 attacks under 4 conditions
	@for c in $(CONDITIONS); do echo "== $$c"; $(PY) -m attacks.suite --condition $$c | tail -1; done

real:             ## official and patched Postmark connectors under 4 conditions
	@for c in $(CONDITIONS); do echo "== $$c"; $(PY) -m attacks.real_connectors --condition $$c | tail -1; done

tables:           ## regenerate results/*.md from results/raw, results/live and results/adaptive
	$(PY) eval/tabulate.py
	$(PY) eval/tabulate_live.py

verify: test suite real tables   ## everything a reviewer needs; no API key, no model, ~10 minutes

live:             ## live LLM agents through the real connector (needs the codex and claude CLIs, logged in); 84 runs
	$(PY) -m agents.run_live --block main
	$(PY) -m agents.run_live --block injection

adaptive:         ## adaptive attackers (needs the claude CLI, GEMINI_API_KEY, OPENROUTER_API_KEY), then baseline replays
	$(PY) -m attacks.adaptive --attackers fable:4,gemini,deepseek,qwen --rounds 6 --budget 1.2
	$(PY) -m attacks.adaptive --replay --condition entry_approval
	$(PY) -m attacks.adaptive --replay --condition relay_no_isolation

demo:             ## the 2025 postmark-mcp incident, without and with Wirebound
	$(PY) eval/demo.py 2>/dev/null

clean:
	rm -rf run results/raw
