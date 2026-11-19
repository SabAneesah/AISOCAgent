from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .agent import investigate
from .database import connect, init_db, one, rows
from .detection import evaluate_event

app = FastAPI(title="SentinelAI SOC API", version="0.1.0", description="Local-first security event monitoring and investigation API")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup() -> None:
    init_db()


class EventIn(BaseModel):
    timestamp: datetime | None = None
    hostname: str | None = "localhost"
    event_type: Literal["failed_login", "successful_login", "process_started", "other"]
    username: str | None = None
    source_ip: str | None = None
    process_name: str | None = None
    raw_event: dict[str, Any] | str | None = None
    source: str = "api"
    event_key: str | None = None


class IngestBatch(BaseModel):
    events: list[EventIn] = Field(max_length=1000)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "SentinelAI"}


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": "SentinelAI SOC API",
        "status": "ok",
        "dashboard": "http://127.0.0.1:5173",
        "health": "/api/health",
        "api_docs": "/docs",
    }


@app.get("/api/events")
def list_events(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), event_type: str | None = None, search: str | None = None) -> dict[str, Any]:
    where, params = [], []
    if event_type:
        where.append("event_type=?"); params.append(event_type)
    if search:
        where.append("(username LIKE ? OR source_ip LIKE ? OR process_name LIKE ?)"); params.extend([f"%{search}%"] * 3)
    clause = " WHERE " + " AND ".join(where) if where else ""
    total = one("SELECT COUNT(*) AS count FROM security_events" + clause, tuple(params))["count"]
    items = rows("SELECT * FROM security_events" + clause + " ORDER BY timestamp DESC LIMIT ? OFFSET ?", tuple(params + [limit, offset]))
    return {"items": items, "total": total}


@app.get("/api/events/{event_id}")
def get_event(event_id: int) -> dict[str, Any]:
    item = one("SELECT * FROM security_events WHERE id=?", (event_id,))
    if not item: raise HTTPException(404, "Event not found")
    return item


@app.post("/api/events/ingest")
def ingest(batch: IngestBatch) -> dict[str, Any]:
    inserted, duplicate, alert_ids = 0, 0, []
    for event in batch.events:
        timestamp = (event.timestamp or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        raw = json.dumps(event.raw_event, ensure_ascii=False) if isinstance(event.raw_event, dict) else event.raw_event
        key = event.event_key or (f"{event.source}:{event.hostname}:{timestamp}:{event.event_type}:{event.username}:{event.source_ip}:{event.process_name}" if event.source == "windows" else None)
        with connect() as db:
            try:
                cur = db.execute("INSERT INTO security_events(event_key,timestamp,hostname,event_type,username,source_ip,process_name,raw_event,source) VALUES(?,?,?,?,?,?,?,?,?)", (key, timestamp, event.hostname, event.event_type, event.username, event.source_ip, event.process_name, raw, event.source))
                event_id = int(cur.lastrowid); inserted += 1
            except Exception as exc:
                if "UNIQUE constraint failed" in str(exc): duplicate += 1; continue
                raise
        alert_ids.extend(evaluate_event(event_id))
    return {"inserted": inserted, "duplicates": duplicate, "alerts_created": alert_ids}


@app.get("/api/alerts")
def list_alerts(severity: str | None = None, status: str | None = None, search: str | None = None, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    where, params = [], []
    if severity: where.append("severity=?"); params.append(severity.lower())
    if status: where.append("status=?"); params.append(status)
    if search: where.append("(username LIKE ? OR source_ip LIKE ? OR title LIKE ?)"); params.extend([f"%{search}%"] * 3)
    clause = " WHERE " + " AND ".join(where) if where else ""
    items = rows("SELECT * FROM alerts" + clause + " ORDER BY created_at DESC LIMIT ?", tuple(params + [limit]))
    return {"items": items, "total": one("SELECT COUNT(*) AS count FROM alerts" + clause, tuple(params))["count"]}


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int) -> dict[str, Any]:
    alert = one("SELECT * FROM alerts WHERE id=?", (alert_id,))
    if not alert: raise HTTPException(404, "Alert not found")
    alert["events"] = rows("SELECT e.* FROM security_events e JOIN alert_events ae ON ae.event_id=e.id WHERE ae.alert_id=? ORDER BY e.timestamp", (alert_id,))
    alert["investigations"] = rows("SELECT * FROM investigations WHERE alert_id=? ORDER BY created_at DESC", (alert_id,))
    return alert


@app.get("/api/incidents")
def incidents() -> dict[str, Any]:
    return {"items": rows("SELECT i.*,a.title,a.severity,a.username,a.source_ip FROM investigations i JOIN alerts a ON a.id=i.alert_id ORDER BY i.created_at DESC"), "total": one("SELECT COUNT(*) AS count FROM investigations")["count"]}


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: int) -> dict[str, Any]:
    result = one("SELECT i.*,a.title,a.severity,a.username,a.source_ip,a.rule_id FROM investigations i JOIN alerts a ON a.id=i.alert_id WHERE i.id=?", (incident_id,))
    if not result: raise HTTPException(404, "Incident not found")
    result["evidence"] = json.loads(result["evidence"]); result["recommendations"] = json.loads(result["recommendations"])
    result["events"] = rows("SELECT e.* FROM security_events e JOIN alert_events ae ON ae.event_id=e.id WHERE ae.alert_id=? ORDER BY e.timestamp", (result["alert_id"],))
    return result


@app.post("/api/alerts/{alert_id}/investigate")
def start_investigation(alert_id: int) -> dict[str, Any]:
    try: return investigate(alert_id)
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc


@app.get("/api/investigations/{investigation_id}")
def get_investigation(investigation_id: int) -> dict[str, Any]:
    result = one("SELECT * FROM investigations WHERE id=?", (investigation_id,))
    if not result: raise HTTPException(404, "Investigation not found")
    result["evidence"] = json.loads(result["evidence"]); result["recommendations"] = json.loads(result["recommendations"])
    return result


@app.get("/api/dashboard/stats")
def dashboard_stats() -> dict[str, Any]:
    counts = {row["event_type"]: row["count"] for row in rows("SELECT event_type,COUNT(*) AS count FROM security_events GROUP BY event_type")}
    severities = {row["severity"]: row["count"] for row in rows("SELECT severity,COUNT(*) AS count FROM alerts GROUP BY severity")}
    series = rows("SELECT substr(timestamp,1,13) AS hour,COUNT(*) AS count FROM security_events WHERE timestamp>=datetime('now','-24 hours') GROUP BY hour ORDER BY hour")
    categories = rows("SELECT category,COUNT(*) AS count FROM alerts GROUP BY category")
    return {"total_events": sum(counts.values()), "total_alerts": sum(severities.values()), "critical_alerts": severities.get("critical", 0), "high_alerts": severities.get("high", 0), "investigations": one("SELECT COUNT(*) AS count FROM investigations")["count"], "event_types": counts, "alerts_by_severity": severities, "events_over_time": series, "incidents_by_category": categories}


@app.post("/api/demo/brute-force")
def simulate_brute_force(count: int = Query(30, ge=10, le=100)) -> dict[str, Any]:
    """Generate a harmless synthetic incident using TEST-NET documentation addresses."""
    now = datetime.now(timezone.utc)
    payload = [EventIn(timestamp=now.replace(microsecond=0) - __import__("datetime").timedelta(seconds=count-i), hostname="demo-endpoint", event_type="failed_login", username="demo-admin", source_ip="192.0.2.10", raw_event={"simulation": True}, source="simulator", event_key=f"demo:{now.timestamp()}:{i}") for i in range(count)]
    result = ingest(IngestBatch(events=payload))
    alerts = rows("SELECT id FROM alerts WHERE rule_id='DET-001' AND username='demo-admin' ORDER BY id DESC LIMIT 1")
    return {**result, "alert_id": alerts[0]["id"] if alerts else None, "message": "Synthetic events created; no authentication attempts were made."}


@app.post("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, status: Literal["open", "investigating", "resolved"]) -> dict[str, Any]:
    with connect() as db:
        cur = db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        if not cur.rowcount: raise HTTPException(404, "Alert not found")
    return {"id": alert_id, "status": status}
