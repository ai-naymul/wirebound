"""Read-only workspace MCP server for live-agent runs: inbox, files and contacts of one task.

    WB_TASK_FILE=<task.json> python agents/workspace_mcp.py

It cannot send anything; the only way to send mail is the email server (agents/gate_mcp.py).
"""
from __future__ import annotations

import json
import os

from mcp.server.mcpserver import MCPServer

TASK = json.load(open(os.environ["WB_TASK_FILE"]))
mcp = MCPServer("office")


@mcp.tool()
def list_emails() -> list[dict]:
    """List the messages in Dana's inbox (id, sender, date, subject), newest last."""
    return [{"id": m["id"], "from": m["from"], "date": m["date"], "subject": m["subject"]} for m in TASK["emails"]]


@mcp.tool()
def read_email(email_id: str) -> dict:
    """Read one inbox message in full by its id."""
    for m in TASK["emails"]:
        if m["id"] == email_id:
            return m
    return {"error": f"no message with id {email_id}"}


@mcp.tool()
def list_files() -> list[str]:
    """List the files in Dana's documents folder."""
    return sorted(TASK["files"])


@mcp.tool()
def read_file(name: str) -> str:
    """Read a file from Dana's documents folder by its name."""
    return TASK["files"].get(name, f"error: no file named {name}")


@mcp.tool()
def search_contacts(query: str) -> list[dict]:
    """Search Dana's contacts by name, email or notes (case-insensitive). An empty query lists all contacts."""
    q = query.lower().strip()
    return [c for c in TASK["contacts"] if not q or q in json.dumps(c).lower()]


if __name__ == "__main__":
    mcp.run()
