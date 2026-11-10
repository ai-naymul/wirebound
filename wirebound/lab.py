"""Local lab: provider (Mailpit), relay (HTTPS + SMTP), egress proxy, approver/control API and canaries.

    python -m wirebound.lab --mode enforce      # Wirebound
    python -m wirebound.lab --mode passthrough  # baselines: the relay forwards whatever it is asked

Everything binds to 127.0.0.1. Ports are fixed and written to run/lab.json. The principal key is written to
run/secrets/principal.key; the connector sandbox profile denies reads of run/secrets.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import shutil
import signal
import ssl
import subprocess
import time
from pathlib import Path

import uvicorn
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session
from fastapi import FastAPI, Request

from .approvals import Approvals
from .certs import ensure_ca, issue_server_cert
from .egress import EgressProxy
from .relay import Relay, postmark_app
from .store import Ledger

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "run"
PORTS = {"mailpit_smtp": 11025, "mailpit_http": 18025, "relay_https": 18443, "relay_smtp": 12525,
         "egress_proxy": 18888, "control": 18781, "canary_http": 19999, "canary_smtp": 12626, "canary_dns": 15353}
PROVIDER_HOST = "api.postmarkapp.com"


class CanaryLog:
    def __init__(self, path: Path):
        self.path = path

    def write(self, **event):
        event["ts"] = time.time()
        with self.path.open("a") as f:
            f.write(json.dumps(event) + "\n")


async def canary_tcp(log: CanaryLog, kind: str, port: int, banner: bytes):
    async def handle(r, w):
        w.write(banner)
        await w.drain()
        try:
            data = await asyncio.wait_for(r.read(4096), timeout=3)
        except asyncio.TimeoutError:
            data = b""
        log.write(canary=kind, port=port, first_bytes=data[:200].decode("latin-1"))
        w.close()
    return await asyncio.start_server(handle, "127.0.0.1", port)


class DnsCanary(asyncio.DatagramProtocol):
    def __init__(self, log: CanaryLog):
        self.log = log

    def datagram_received(self, data, addr):
        self.log.write(canary="dns", port=PORTS["canary_dns"], bytes=len(data), query_hex=data[:64].hex())


class SmtpHandler:
    def __init__(self, relay: Relay):
        self.relay = relay

    async def handle_DATA(self, server, session: Session, envelope: Envelope):
        login = session.auth_data
        sess = login.decode() if isinstance(login, bytes) else (login or "default")
        result = await asyncio.to_thread(self.relay.handle_smtp, envelope.mail_from, list(envelope.rcpt_tos),
                                         envelope.original_content or envelope.content, sess)
        if result.get("ok"):
            return "250 Message accepted for delivery"
        if result.get("unknown"):
            return "451 Wirebound: provider result unknown; do not resend"
        return "554 Wirebound: " + "; ".join(result.get("reasons", []))[:400]


def control_app(relay: Relay, approvals: Approvals, principal_key: bytes) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/propose")
    async def propose(req: Request):
        body = await req.json()
        return approvals.propose(body.get("session", "default"), body["proposal"])

    @app.post("/approve")
    async def approve(req: Request):
        body = await req.json()
        key = req.headers.get("x-principal-key", "").encode()
        return approvals.approve(body["send_id"], body["digest"], key, float(body.get("ttl", 120)),
                                 body.get("approver", "principal"))

    @app.post("/deny")
    async def deny(req: Request):
        body = await req.json()
        if req.headers.get("x-principal-key", "").encode() != principal_key:
            return {"ok": False}
        approvals.deny(body["send_id"])
        return {"ok": True}

    @app.post("/revoke")
    async def revoke(req: Request):
        if req.headers.get("x-principal-key", "").encode() != principal_key:
            return {"ok": False}
        return {"ok": True, "revoked": relay.ledger.revoke_outstanding()}

    @app.get("/sends")
    async def sends():
        return relay.ledger.sends()

    @app.post("/fault")
    async def fault(req: Request):
        if req.headers.get("x-principal-key", "").encode() != principal_key:
            return {"ok": False}
        relay.fault = (await req.json()).get("fault")
        return {"ok": True, "fault": relay.fault}

    @app.post("/reconcile")
    async def reconcile():
        """Resolve UNKNOWN sends against the provider's own record (Mailpit), by Message-ID."""
        import httpx
        resolved = []
        async with httpx.AsyncClient() as c:
            for s in relay.ledger.unknown_sends():
                if not s["provider_id"]:
                    continue
                q = await c.get(f"http://127.0.0.1:{PORTS['mailpit_http']}/api/v1/search",
                                params={"query": f"message-id:{s['provider_id'].strip('<>')}"})
                if q.json().get("messages_count", q.json().get("total", 0)):
                    relay.ledger.update_send(s["id"], "DELIVERED")
                    resolved.append(s["id"])
        return {"resolved": resolved}

    return app


async def main(mode: str) -> None:
    RUN.mkdir(exist_ok=True)
    (RUN / "secrets").mkdir(exist_ok=True)
    for f in ("ledger.sqlite", "ledger.sqlite-wal", "ledger.sqlite-shm", "egress.log", "canary.log"):
        (RUN / f).unlink(missing_ok=True)
    principal_key = secrets.token_hex(32).encode()
    key_path = RUN / "secrets" / "principal.key"
    key_path.write_bytes(principal_key)
    key_path.chmod(0o600)

    certs = ROOT / "certs"
    ca_cert, _ = ensure_ca(certs)
    public = certs / "public"
    public.mkdir(exist_ok=True)
    shutil.copy(ca_cert, public / "lab-ca.pem")
    leaf_cert, leaf_key = issue_server_cert(certs, PROVIDER_HOST)

    mailpit_db = RUN / "mailpit.db"
    mailpit_db.unlink(missing_ok=True)
    mailpit = subprocess.Popen(["mailpit", "-q", "--smtp", f"127.0.0.1:{PORTS['mailpit_smtp']}",
                                "--listen", f"127.0.0.1:{PORTS['mailpit_http']}", "-d", str(mailpit_db),
                                "--smtp-auth-accept-any", "--smtp-auth-allow-insecure"])

    ledger = Ledger(RUN / "ledger.sqlite")
    relay = Relay(ledger, ("127.0.0.1", PORTS["mailpit_smtp"]), mode=mode)
    approvals = Approvals(ledger, principal_key)
    canaries = CanaryLog(RUN / "canary.log")

    proxy = EgressProxy({f"{PROVIDER_HOST}:443": ("127.0.0.1", PORTS["relay_https"])}, RUN / "egress.log")
    await proxy.serve("127.0.0.1", PORTS["egress_proxy"])
    await canary_tcp(canaries, "http", PORTS["canary_http"], b"")
    await canary_tcp(canaries, "smtp", PORTS["canary_smtp"], b"220 canary ESMTP\r\n")
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: DnsCanary(canaries), local_addr=("127.0.0.1", PORTS["canary_dns"]))

    def authenticator(server, session, envelope, mechanism, auth_data):
        from aiosmtpd.smtp import AuthResult
        login = getattr(auth_data, "login", None)
        return AuthResult(success=True, auth_data=login)  # the login names the session; the password is not used

    smtp = Controller(SmtpHandler(relay), hostname="127.0.0.1", port=PORTS["relay_smtp"], authenticator=authenticator,
                      auth_require_tls=False)
    smtp.start()

    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(leaf_cert, leaf_key)
    https = uvicorn.Server(uvicorn.Config(postmark_app(relay), host="127.0.0.1", port=PORTS["relay_https"],
                                          ssl_certfile=str(leaf_cert), ssl_keyfile=str(leaf_key), log_level="warning"))
    control = uvicorn.Server(uvicorn.Config(control_app(relay, approvals, principal_key), host="127.0.0.1",
                                            port=PORTS["control"], log_level="warning"))
    (RUN / "lab.json").write_text(json.dumps({"mode": mode, "ports": PORTS, "pid": os.getpid(),
                                              "ca": str(public / "lab-ca.pem")}, indent=1))
    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGTERM, stop.set)
    loop.add_signal_handler(signal.SIGINT, stop.set)
    tasks = [asyncio.create_task(https.serve()), asyncio.create_task(control.serve())]
    print(f"lab up in {mode} mode: {json.dumps(PORTS)}", flush=True)
    await stop.wait()
    https.should_exit = control.should_exit = True
    await asyncio.gather(*tasks, return_exceptions=True)
    smtp.stop()
    mailpit.terminate()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["enforce", "passthrough"], default="enforce")
    asyncio.run(main(ap.parse_args().mode))
