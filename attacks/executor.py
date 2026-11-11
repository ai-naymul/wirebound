"""Execute one adaptive-attack attempt (data only) from inside the connector's position.

    python -I attacks/executor.py < attempt.json > result.json

The attacker model never runs code. It writes an attempt: a list of network steps (HTTPS requests through the
egress proxy, raw bytes over TLS, raw TCP or UDP, SMTP transactions). This fixed program performs them, under
the same Seatbelt profile as the connector when isolation is on, and reports what came back.

Environment: WB_PORTS (JSON), WB_CA (lab CA path), WB_SESSION (the connector's provider token).
"""
from __future__ import annotations

import base64
import json
import os
import smtplib
import socket
import ssl
import sys

import httpx

PORTS = json.loads(os.environ["WB_PORTS"])
CA = os.environ["WB_CA"]
SESSION = os.environ.get("WB_SESSION", "default")
PROXY = f"http://127.0.0.1:{PORTS['egress_proxy']}"
MAX = 1200


def raw(step: dict, field: str) -> bytes:
    v = step.get(field) or ""
    return base64.b64decode(v) if step.get("encoding") == "base64" else v.encode("utf-8", "surrogateescape")


def https(step: dict) -> dict:
    host = step.get("host") or "api.postmarkapp.com"
    headers = [(h["name"], h["value"]) for h in step.get("headers") or []]
    if not any(n.lower() == "x-postmark-server-token" for n, _ in headers):
        headers.append(("X-Postmark-Server-Token", SESSION))
    with httpx.Client(proxy=PROXY, verify=CA, timeout=10, trust_env=False) as c:
        r = c.request(step.get("method") or "POST", f"https://{host}{step.get('path') or '/email'}",
                      content=raw(step, "body"), headers=headers)
        return {"status": r.status_code, "response": r.text[:MAX]}


def tls_raw(step: dict) -> dict:
    """CONNECT through the egress proxy, open TLS (trusting the lab CA), write the attacker's bytes verbatim."""
    host = step.get("host") or "api.postmarkapp.com"
    port = int(step.get("port") or 443)
    s = socket.create_connection(("127.0.0.1", PORTS["egress_proxy"]), timeout=10)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    head = s.recv(4096)
    if b" 200" not in head.split(b"\r\n", 1)[0]:
        s.close()
        return {"status": "proxy-refused", "response": head[:MAX].decode("latin-1")}
    ctx = ssl.create_default_context(cafile=CA)
    t = ctx.wrap_socket(s, server_hostname=host)
    t.sendall(raw(step, "payload"))
    out = b""
    try:
        while len(out) < 65536:
            chunk = t.recv(65536)
            if not chunk:
                break
            out += chunk
    except (socket.timeout, ssl.SSLError):
        pass
    t.close()
    return {"status": "sent", "response": out[:MAX].decode("latin-1")}


def tcp(step: dict) -> dict:
    s = socket.create_connection((step.get("host") or "127.0.0.1", int(step["port"])), timeout=5)
    s.settimeout(3)
    banner = b""
    try:
        banner = s.recv(4096)
    except socket.timeout:
        pass
    s.sendall(raw(step, "payload"))
    out = b""
    try:
        while len(out) < 65536:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    s.close()
    return {"status": "sent", "response": (banner + b"|" + out)[:MAX].decode("latin-1")}


def udp(step: dict) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(raw(step, "payload"), (step.get("host") or "127.0.0.1", int(step["port"])))
    try:
        data, _ = s.recvfrom(4096)
        return {"status": "sent", "response": data[:MAX].hex()}
    except socket.timeout:
        return {"status": "sent", "response": ""}


def smtp(step: dict) -> dict:
    """An SMTP transaction to the relay's submission port (or another host:port if given)."""
    host = step.get("host") or "127.0.0.1"
    port = int(step.get("port") or PORTS["relay_smtp"])
    with smtplib.SMTP(host, port, timeout=10) as c:
        c.ehlo("connector.local")
        if step.get("login"):
            c.login(step["login"], "unused")
        else:
            c.login(SESSION, "unused")
        try:
            refused = c.sendmail(step.get("mail_from") or "", step.get("rcpt_to") or [], raw(step, "data"))
            return {"status": "accepted", "response": json.dumps({k: [v[0], v[1].decode("latin-1")] for k, v in refused.items()})}
        except smtplib.SMTPResponseException as exc:
            return {"status": exc.smtp_code, "response": exc.smtp_error.decode("latin-1")[:MAX]}
        except smtplib.SMTPRecipientsRefused as exc:
            return {"status": "recipients-refused", "response": str(exc)[:MAX]}


KINDS = {"https": https, "tls_raw": tls_raw, "tcp": tcp, "udp": udp, "smtp": smtp}


def main():
    attempt = json.load(sys.stdin)
    results = []
    for step in attempt.get("steps", [])[:8]:
        try:
            results.append({"kind": step.get("kind"), **KINDS[step["kind"]](step)})
        except Exception as exc:  # a refusal by the sandbox shows up here as PermissionError
            results.append({"kind": step.get("kind"), "status": "error", "response": f"{type(exc).__name__}: {exc}"[:MAX]})
    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
