"""Durable ledger for approvals and sends (SQLite). Every state change goes through here.

Artifact states: PREPARED -> AUTHORIZED -> CONSUMED (or DENIED / EXPIRED).
Send decisions: DISPATCHING -> DELIVERED | UNKNOWN (ambiguous provider result) | REJECTED.
Consumption is a single conditional UPDATE, so one approval can release at most one dispatch even under races.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts (
  send_id TEXT PRIMARY KEY, session TEXT NOT NULL, digest TEXT NOT NULL, effect_json TEXT NOT NULL,
  state TEXT NOT NULL, created REAL NOT NULL, expiry REAL, approved_by TEXT, nonce TEXT);
CREATE INDEX IF NOT EXISTS artifacts_digest ON artifacts(digest, state);
CREATE TABLE IF NOT EXISTS sends (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, channel TEXT NOT NULL, endpoint TEXT,
  digest TEXT, send_id TEXT, decision TEXT NOT NULL, reasons TEXT, provider_id TEXT,
  effect_json TEXT, meta_json TEXT);
"""


class Ledger:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)

    def _q(self, sql: str, args=()):
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # --- approvals ---
    def prepare(self, send_id: str, session: str, digest: str, effect: dict) -> None:
        self._q("INSERT INTO artifacts(send_id, session, digest, effect_json, state, created) VALUES (?,?,?,?,?,?)",
                (send_id, session, digest, json.dumps(effect, sort_keys=True), "PREPARED", time.time()))

    def artifact(self, send_id: str):
        rows = self._q("SELECT send_id, session, digest, effect_json, state, created, expiry, approved_by "
                       "FROM artifacts WHERE send_id=?", (send_id,))
        if not rows:
            return None
        k = ("send_id", "session", "digest", "effect_json", "state", "created", "expiry", "approved_by")
        return dict(zip(k, rows[0]))

    def authorize(self, send_id: str, digest: str, expiry: float, approver: str, nonce: str) -> bool:
        with self._lock:
            cur = self._db.execute("UPDATE artifacts SET state='AUTHORIZED', expiry=?, approved_by=?, nonce=? "
                                   "WHERE send_id=? AND digest=? AND state='PREPARED'",
                                   (expiry, approver, nonce, send_id, digest))
            return cur.rowcount == 1

    def deny(self, send_id: str) -> None:
        self._q("UPDATE artifacts SET state='DENIED' WHERE send_id=? AND state IN ('PREPARED','AUTHORIZED')", (send_id,))

    def consume(self, digest: str, session: str, now: float | None = None) -> str | None:
        """Atomically consume one authorized, unexpired approval with this digest in this session."""
        now = time.time() if now is None else now
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT send_id FROM artifacts WHERE digest=? AND session=? AND state='AUTHORIZED' "
                                       "AND expiry>? ORDER BY created LIMIT 1", (digest, session, now)).fetchone()
                if row is None:
                    self._db.execute("COMMIT")
                    return None
                cur = self._db.execute("UPDATE artifacts SET state='CONSUMED' WHERE send_id=? AND state='AUTHORIZED'",
                                       (row[0],))
                self._db.execute("COMMIT")
                return row[0] if cur.rowcount == 1 else None
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def revoke_outstanding(self) -> int:
        with self._lock:
            return self._db.execute("UPDATE artifacts SET state='REVOKED' WHERE state IN ('PREPARED','AUTHORIZED')").rowcount

    def session_artifacts(self, session: str | None = None):
        sql = "SELECT send_id, digest, effect_json, state FROM artifacts"
        rows = self._q(sql + (" WHERE session=?" if session else ""), (session,) if session else ())
        return [dict(zip(("send_id", "digest", "effect_json", "state"), r)) for r in rows]

    # --- sends ---
    def record_send(self, channel: str, endpoint: str, digest: str | None, send_id: str | None, decision: str,
                    reasons: list[str] | None = None, provider_id: str | None = None,
                    effect: dict | None = None, meta: dict | None = None) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO sends(ts, channel, endpoint, digest, send_id, decision, reasons, provider_id, effect_json, meta_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (time.time(), channel, endpoint, digest, send_id, decision, json.dumps(reasons or []), provider_id,
                 json.dumps(effect, sort_keys=True) if effect else None, json.dumps(meta, default=str) if meta else None))
            return cur.lastrowid

    def update_send(self, row_id: int, decision: str, provider_id: str | None = None) -> None:
        self._q("UPDATE sends SET decision=?, provider_id=COALESCE(?, provider_id) WHERE id=?",
                (decision, provider_id, row_id))

    def sends(self):
        rows = self._q("SELECT id, ts, channel, endpoint, digest, send_id, decision, reasons, provider_id FROM sends ORDER BY id")
        k = ("id", "ts", "channel", "endpoint", "digest", "send_id", "decision", "reasons", "provider_id")
        return [dict(zip(k, r)) for r in rows]

    def unknown_sends(self):
        return [s for s in self.sends() if s["decision"] == "UNKNOWN"]
