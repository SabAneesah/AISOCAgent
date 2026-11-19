"""Small SQLite persistence layer for SentinelAI."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", Path(__file__).resolve().parent.parent / "data" / "sentinel.db"))


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
        db.commit()
    finally:
        db.close()


def init_db() -> None:
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS security_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT UNIQUE, timestamp TEXT NOT NULL,
          hostname TEXT, event_type TEXT NOT NULL, username TEXT, source_ip TEXT, process_name TEXT,
          raw_event TEXT, source TEXT NOT NULL DEFAULT 'simulator'
        );
        CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_auth ON security_events(event_type, username, source_ip, timestamp);
        CREATE TABLE IF NOT EXISTS alerts (
          id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, title TEXT NOT NULL,
          description TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
          event_count INTEGER NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
          username TEXT, source_ip TEXT, category TEXT NOT NULL DEFAULT 'Authentication', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS alert_events (
          alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
          event_id INTEGER NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
          PRIMARY KEY(alert_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS investigations (
          id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL REFERENCES alerts(id),
          incident_type TEXT NOT NULL, risk_level TEXT NOT NULL, confidence REAL NOT NULL,
          summary TEXT NOT NULL, evidence TEXT NOT NULL, recommendations TEXT NOT NULL,
          potential_impact TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'completed', created_at TEXT NOT NULL
        );
        """)


def rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with connect() as db:
        return [dict(row) for row in db.execute(sql, params).fetchall()]


def one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    result = rows(sql, params)
    return result[0] if result else None


def json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)
