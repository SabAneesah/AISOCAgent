"""Send harmless synthetic failed-login events to a running local SentinelAI API."""
import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--count", type=int, default=30)
    args = parser.parse_args()
    if not 10 <= args.count <= 100:
        parser.error("--count must be between 10 and 100")
    now = datetime.now(timezone.utc)
    events = [{"timestamp": (now - timedelta(seconds=args.count-i)).isoformat(), "hostname": "demo-endpoint", "event_type": "failed_login", "username": "demo-admin", "source_ip": "192.0.2.10", "raw_event": {"simulation": True}, "source": "simulator", "event_key": f"cli-demo:{now.timestamp()}:{i}"} for i in range(args.count)]
    request = urllib.request.Request(f"{args.api.rstrip('/')}/api/events/ingest", data=json.dumps({"events": events}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            print(response.read().decode())
    except TimeoutError:
        parser.exit(1, f"Timed out waiting for the API at {args.api}. The batch may already have been ingested; check the dashboard before retrying.\n")
    except urllib.error.URLError as exc:
        parser.exit(1, f"Could not reach the API at {args.api}: {exc.reason}. Start the backend and retry.\n")
    print("Only synthetic data was sent; no login attempts were made.")


if __name__ == "__main__":
    main()
