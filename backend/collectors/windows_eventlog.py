"""Opt-in Windows Security log reader. Requires administrative access and pywin32."""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from typing import Any


def normalize_record(record: Any) -> dict[str, Any] | None:
    """Normalize a win32evtlog record without retaining the full message by default."""
    event_id = record.EventID & 0xFFFF
    if event_id not in (4624, 4625):
        return None
    strings = list(record.StringInserts or [])
    # Windows event field offsets vary by provider/OS; preserve only parsed values
    # when safely identifiable. Unparsed fields remain unavailable, never guessed.
    username = next((str(value) for value in strings if isinstance(value, str) and value.lower() not in ("-", "anonymous logon", "system") and "\\" not in value), None)
    source_ip = next((str(value) for value in strings if isinstance(value, str) and value.count(".") == 3 and all(part.isdigit() for part in value.split("."))), None)
    timestamp = record.TimeGenerated.replace(tzinfo=timezone.utc).isoformat()
    return {"timestamp": timestamp, "hostname": record.Computer or socket.gethostname(), "event_type": "failed_login" if event_id == 4625 else "successful_login", "username": username, "source_ip": source_ip, "source": "windows", "event_key": f"windows:{record.Computer}:{event_id}:{record.RecordNumber}", "raw_event": {"event_id": event_id, "record_number": record.RecordNumber, "channel": "Security"}}


def read_recent(max_events: int = 100) -> list[dict[str, Any]]:
    try:
        import win32evtlog
    except ImportError as exc:
        raise RuntimeError("Install the optional pywin32 package on Windows first") from exc
    handle = win32evtlog.OpenEventLog(None, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    records = []
    try:
        while len(records) < max_events:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch: break
            for record in batch:
                normalized = normalize_record(record)
                if normalized: records.append(normalized)
                if len(records) >= max_events: break
    finally:
        win32evtlog.CloseEventLog(handle)
    return list(reversed(records))
