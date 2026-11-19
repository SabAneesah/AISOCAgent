"""Controlled investigation workflow. LLM usage is optional and evidence stays bounded."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from .database import connect, json_value, one, rows


def investigate(alert_id: int) -> dict[str, Any]:
    alert = one("SELECT * FROM alerts WHERE id=?", (alert_id,))
    if not alert:
        raise ValueError("Alert not found")
    evidence_rows = rows("SELECT e.timestamp,e.event_type,e.username,e.source_ip,e.process_name,e.hostname FROM security_events e JOIN alert_events ae ON ae.event_id=e.id WHERE ae.alert_id=? ORDER BY e.timestamp LIMIT 100", (alert_id,))
    evidence = [f"{alert['event_count']} supporting events linked to {alert['rule_id']}."]
    if alert.get("username"):
        evidence.append(f"Attempts targeted account {alert['username']}.")
    if alert.get("source_ip"):
        evidence.append(f"Observed source address: {alert['source_ip']}.")
    if evidence_rows:
        duration = max(0, (datetime.fromisoformat(evidence_rows[-1]["timestamp"].replace("Z", "+00:00")) - datetime.fromisoformat(evidence_rows[0]["timestamp"].replace("Z", "+00:00"))).total_seconds())
        evidence.append(f"Observed across {duration:.0f} seconds; first {evidence_rows[0]['timestamp']} and last {evidence_rows[-1]['timestamp']}.")
    risk = "High" if alert["severity"] in ("high", "critical") else "Medium"
    summary = f"{alert['title']}: {alert['description']} This pattern is consistent with automated credential guessing, but does not by itself prove account compromise."
    recommendations = ["Review authentication activity for this account and source.", "Check whether a successful login followed the failures.", "Verify the source with the device owner and your environment's context.", "Consider a temporary block only after analyst verification."]
    # Optional provider integration can be added without changing stored report shape.
    # Raw logs are deliberately not sent to a provider by default.
    provider = os.getenv("SENTINEL_LLM_PROVIDER", "disabled")
    status = "completed (local analysis)" if provider == "disabled" else "completed (local analysis; provider adapter not configured)"
    report = {"alert_id": alert_id, "incident_type": "Suspected brute-force authentication" if alert["rule_id"] in ("DET-001", "DET-002") else alert["title"], "risk_level": risk, "confidence": 0.82 if len(evidence_rows) else 0.5, "summary": summary, "evidence": evidence, "potential_impact": "Unauthorized account access if credentials are guessed and no additional controls prevent sign-in.", "recommendations": recommendations, "requires_human_review": True, "status": status, "created_at": datetime.now(timezone.utc).isoformat()}
    with connect() as db:
        cur = db.execute("INSERT INTO investigations(alert_id,incident_type,risk_level,confidence,summary,evidence,recommendations,potential_impact,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (alert_id, report["incident_type"], risk, report["confidence"], summary, json_value(evidence), json_value(recommendations), report["potential_impact"], "completed", report["created_at"]))
        report["id"] = int(cur.lastrowid)
    return report
