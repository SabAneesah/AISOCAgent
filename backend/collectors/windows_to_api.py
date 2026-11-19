"""Read a bounded batch of Windows Security events and post normalized records locally."""
from __future__ import annotations

import argparse
import json
import time
import urllib.request

from .windows_eventlog import read_recent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--watch", action="store_true", help="Poll recent Security events repeatedly; stop with Ctrl+C")
    parser.add_argument("--interval", type=int, default=15, help="Seconds between polls when --watch is enabled")
    args = parser.parse_args()
    if args.interval < 2:
        parser.error("--interval must be at least 2 seconds")
    while True:
        try:
            events = read_recent(max_events=min(max(args.limit, 1), 500))
        except RuntimeError as exc:
            parser.exit(1, f"Collector error: {exc}\n")
        if events:
            request = urllib.request.Request(f"{args.api.rstrip('/')}/api/events/ingest", data=json.dumps({"events": events}).encode(), headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(request, timeout=60) as response:
                print(response.read().decode(), flush=True)
        else:
            print("No supported Security events found in the latest batch.", flush=True)
        if not args.watch:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
