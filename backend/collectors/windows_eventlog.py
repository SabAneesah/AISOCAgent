"""Opt-in Windows Security log reader. Requires administrative access and pywin32."""
from __future__ import annotations

import json
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any


def normalize_record(record: Any) -> dict[str, Any] | None:
    """Normalize a win32evtlog record without retaining the full message by default."""
    event_id = getattr(record, "EventID", 0) & 0xFFFF
    if event_id not in (4624, 4625):
        return None
    strings = [str(value).strip() if value is not None else "" for value in (record.StringInserts or [])]
    # These indexes follow the documented Microsoft-Windows-Security-Auditing
    # event templates: TargetUserName at 5; IpAddress at 17 for 4624 and 19
    # for 4625. If a provider/version gives a shorter payload, leave fields unset
    # rather than guessing from unrelated event text.
    username_index = 5
    ip_index = 17 if event_id == 4624 else 19
    username = strings[username_index] if len(strings) > username_index else None
    source_ip = strings[ip_index] if len(strings) > ip_index else None
    if username in ("", "-", "ANONYMOUS LOGON"):
        username = None
    try:
        source_ip = str(ipaddress.ip_address(source_ip)) if source_ip and source_ip not in ("-", "::1", "127.0.0.1") else None
    except ValueError:
        source_ip = None
    generated = getattr(record, "TimeGenerated", None)
    if generated is None:
        return None
    timestamp = generated.replace(tzinfo=timezone.utc).isoformat()
    # PyWin32's PyEventLogRecord exposes ComputerName, not Computer.
    hostname = getattr(record, "ComputerName", None) or socket.gethostname()
    record_number = getattr(record, "RecordNumber", None)
    if record_number is None:
        return None
    return {"timestamp": timestamp, "hostname": hostname, "event_type": "failed_login" if event_id == 4625 else "successful_login", "username": username, "source_ip": source_ip, "source": "windows", "event_key": f"windows:{hostname}:{event_id}:{record_number}", "raw_event": {"event_id": event_id, "record_number": record_number, "channel": "Security"}}


def read_recent(max_events: int = 100) -> list[dict[str, Any]]:
    try:
        import win32evtlog
    except ImportError as exc:
        raise RuntimeError("Install the optional pywin32 package on Windows first") from exc
    try:
        handle = win32evtlog.OpenEventLog(None, "Security")
    except Exception as exc:
        error_code = getattr(exc, "winerror", None)
        if error_code is None and getattr(exc, "args", None):
            error_code = exc.args[0]
        if error_code == 1314:
            raise RuntimeError("Windows denied access to the Security log. Run this collector from an elevated PowerShell window; the account must have the 'Manage auditing and security log' user right (SeSecurityPrivilege).") from exc
        raise
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
