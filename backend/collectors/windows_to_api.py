"""Read a bounded batch of Windows Security events and post normalized records locally."""
from __future__ import annotations

import argparse
import json
import urllib.request

from .windows_eventlog import read_recent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    events = read_recent(max_events=min(max(args.limit, 1), 500))
    request = urllib.request.Request(f"{args.api.rstrip('/')}/api/events/ingest", data=json.dumps({"events": events}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=15) as response:
        print(response.read().decode())


if __name__ == "__main__":
    main()
