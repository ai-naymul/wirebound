"""macOS Seatbelt profile for running an untrusted connector.

Network: outbound only to the egress proxy and the relay's SMTP port (plus local unix sockets for the runtime).
Files: reads of run/secrets and the lab CA private keys are denied; the public CA certificate stays readable.
"""
from __future__ import annotations

from pathlib import Path


def profile(root: Path, ports: dict[str, int]) -> str:
    root = root.resolve()
    return f"""(version 1)
(allow default)
(deny network-outbound)
(allow network-outbound (remote ip "localhost:{ports['egress_proxy']}"))
(allow network-outbound (remote ip "localhost:{ports['relay_smtp']}"))
(allow network-outbound (remote unix-socket))
(deny file-read* (subpath "{root / 'run' / 'secrets'}"))
(deny file-read* (subpath "{root / 'certs'}"))
(allow file-read* (subpath "{root / 'certs' / 'public'}"))
"""


def write_profile(root: Path, ports: dict[str, int]) -> Path:
    path = root / "run" / "connector.sb"
    path.write_text(profile(root, ports))
    return path


def wrap(command: list[str], profile_path: Path | None) -> list[str]:
    """Prefix a command with sandbox-exec, or return it unchanged when isolation is off (baselines)."""
    return ["sandbox-exec", "-f", str(profile_path), *command] if profile_path else command
