"""Egress proxy: the only network exit available to a sandboxed connector.

It accepts HTTP CONNECT requests. A CONNECT to an allowlisted provider host is tunnelled to the local relay
listener that impersonates that host; every other destination is refused and recorded. Plain-HTTP proxy
requests are refused too, so the only way out is through the relay.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path


class EgressProxy:
    def __init__(self, routes: dict[str, tuple[str, int]], log_path: Path):
        # routes: "api.postmarkapp.com:443" -> ("127.0.0.1", relay_tls_port)
        self.routes = routes
        self.log_path = log_path

    def _log(self, **event) -> None:
        event["ts"] = time.time()
        with self.log_path.open("a") as f:
            f.write(json.dumps(event) + "\n")

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        request_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = request_line.split()
        if len(parts) != 3 or parts[0].upper() != "CONNECT":
            self._log(decision="refused", reason="non-CONNECT proxy request", request=request_line[:200])
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        target = parts[1].lower()
        route = self.routes.get(target)
        if route is None:
            self._log(decision="refused", reason="destination not allowlisted", target=target)
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        try:
            up_reader, up_writer = await asyncio.open_connection(*route)
        except OSError as exc:
            self._log(decision="error", target=target, error=str(exc))
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        self._log(decision="tunnel", target=target, route=f"{route[0]}:{route[1]}")
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(self._pipe(reader, up_writer), self._pipe(up_reader, writer))

    async def serve(self, host: str, port: int) -> asyncio.base_events.Server:
        return await asyncio.start_server(self.handle, host, port)
