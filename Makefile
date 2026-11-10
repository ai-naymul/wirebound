PY := .venv/bin/python
CONDITIONS := no_gate entry_approval relay_no_isolation wirebound

.PHONY: setup thirdparty test suite real tables verify demo clean

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

tables:           ## regenerate results/*.md from results/raw
	$(PY) eval/tabulate.py

verify: test suite real tables   ## everything a reviewer needs; no API key, no model, ~10 minutes

demo:             ## the 2025 postmark-mcp incident, without and with Wirebound
	$(PY) eval/demo.py 2>/dev/null

clean:
	rm -rf run results/raw
