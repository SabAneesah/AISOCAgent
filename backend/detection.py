"""Explainable, deterministic event correlation rules."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .database import connect

RULES = [
    {"id": "DET-001", "name": "Brute-force login", "severity": "high", "threshold": 10, "window_seconds": 120},
    {"id": "DET-002", "name": "Repeated login failures", "severity": "medium", "threshold": 5, "window_seconds": 600},
]


def evaluate_event(event_id: int) -> list[int]:
    """Evaluate a newly stored event and create evidence-linked alerts."""
    created: list[int] = []
    with connect() as db:
        event = db.execute("SELECT * FROM security_events WHERE id=?", (event_id,)).fetchone()
        if not event:
            return created
        event = dict(event)
        if event["event_type"] == "failed_login":
            at = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            for rule in RULES:
                start = (at - timedelta(seconds=rule["window_seconds"])).isoformat()
                group_fields = ("username", "source_ip") if rule["id"] == "DET-001" else ("username",)
                clauses, values = ["event_type='failed_login'", "timestamp>=?", "timestamp<=?"], [start, event["timestamp"]]
                if "username" in group_fields and event.get("username"):
                    clauses.append("username=?"); values.append(event["username"])
                if "source_ip" in group_fields and event.get("source_ip"):
                    clauses.append("source_ip=?"); values.append(event["source_ip"])
                matching = db.execute(f"SELECT id,timestamp FROM security_events WHERE {' AND '.join(clauses)} ORDER BY timestamp", values).fetchall()
                if len(matching) < rule["threshold"]:
                    continue
                # Avoid creating another alert for the same burst on every event.
                grouping = " AND a.source_ip IS ?" if "source_ip" in group_fields else ""
                existing_params = [rule["id"], event.get("username")]
                if "source_ip" in group_fields:
                    existing_params.append(event.get("source_ip"))
                existing_params.extend([start, event["timestamp"]])
                exists = db.execute(f"SELECT a.id FROM alerts a JOIN alert_events ae ON ae.alert_id=a.id JOIN security_events e ON e.id=ae.event_id WHERE a.rule_id=? AND a.username IS ?{grouping} AND e.timestamp>=? AND e.timestamp<=? LIMIT 1", existing_params).fetchone()
                if exists:
                    db.execute("UPDATE alerts SET event_count=?,last_seen=? WHERE id=?", (len(matching), matching[-1]["timestamp"], exists["id"]))
                    db.executemany("INSERT OR IGNORE INTO alert_events(alert_id,event_id) VALUES(?,?)", [(exists["id"], row["id"]) for row in matching])
                    continue
                title = "Suspected brute-force authentication" if rule["id"] == "DET-001" else "Repeated authentication failures"
                description = f"{len(matching)} failed logins for {event.get('username') or 'unknown user'} from {event.get('source_ip') or 'unknown source'} within {rule['window_seconds']} seconds."
                cur = db.execute("INSERT INTO alerts(rule_id,title,description,severity,event_count,first_seen,last_seen,username,source_ip,category,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (rule["id"], title, description, rule["severity"], len(matching), matching[0]["timestamp"], matching[-1]["timestamp"], event.get("username"), event.get("source_ip"), "Authentication", datetime.now(timezone.utc).isoformat()))
                alert_id = int(cur.lastrowid)
                db.executemany("INSERT INTO alert_events(alert_id,event_id) VALUES(?,?)", [(alert_id, row["id"]) for row in matching])
                created.append(alert_id)
        elif event["event_type"] == "process_started":
            watchlist = {part.strip().lower() for part in __import__("os").getenv("SENTINEL_PROCESS_WATCHLIST", "mimikatz.exe,procdump.exe,psexec.exe").split(",")}
            if (event.get("process_name") or "").lower() in watchlist:
                cur = db.execute("INSERT INTO alerts(rule_id,title,description,severity,event_count,first_seen,last_seen,username,source_ip,category,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("DET-003", "Watchlisted process execution", f"Process {event['process_name']} matched the configured watchlist.", "medium", 1, event["timestamp"], event["timestamp"], event.get("username"), event.get("source_ip"), "Process", datetime.now(timezone.utc).isoformat()))
                alert_id = int(cur.lastrowid); db.execute("INSERT INTO alert_events(alert_id,event_id) VALUES(?,?)", (alert_id, event_id)); created.append(alert_id)
        elif event["event_type"] == "successful_login":
            start = (datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) - timedelta(minutes=10)).isoformat()
            clauses, values = ["event_type='failed_login'", "timestamp>=?", "timestamp<=?"], [start, event["timestamp"]]
            if event.get("username"):
                clauses.append("username=?"); values.append(event["username"])
            failures = db.execute(f"SELECT id,timestamp FROM security_events WHERE {' AND '.join(clauses)} ORDER BY timestamp", values).fetchall()
            if len(failures) >= 5:
                cur = db.execute("INSERT INTO alerts(rule_id,title,description,severity,event_count,first_seen,last_seen,username,source_ip,category,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("DET-004", "Successful login after repeated failures", f"A successful login followed {len(failures)} failures within 10 minutes.", "high", len(failures) + 1, failures[0]["timestamp"], event["timestamp"], event.get("username"), event.get("source_ip"), "Authentication", datetime.now(timezone.utc).isoformat()))
                alert_id = int(cur.lastrowid); db.executemany("INSERT INTO alert_events(alert_id,event_id) VALUES(?,?)", [(alert_id, row["id"]) for row in failures] + [(alert_id, event_id)]); created.append(alert_id)
    return created
