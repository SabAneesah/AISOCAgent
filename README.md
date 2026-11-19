# SentinelAI

SentinelAI is a local-first mini SOC for learning and portfolio demonstrations. It collects normalized security events, runs explainable deterministic detections, links alerts to evidence, and presents investigation reports through a React dashboard.

> The initial investigation implementation is local and evidence-based. It does not call an LLM yet. This keeps the first monitoring pipeline usable without credentials or external transmission of endpoint data; a provider-backed LangGraph adapter is a next implementation step.

## Features

- FastAPI backend with SQLite persistence and duplicate-resistant event ingestion.
- Rule-based authentication correlation (10 failures in 2 minutes → High; repeated failures → Medium) and process watchlist detection.
- Windows Security Event Log reader for IDs 4624/4625, opt-in and Windows-only.
- Synthetic brute-force simulator using documentation-only IP addresses.
- Alert/event relationships, incident reports, severity filters, searchable tables, event charts, and JSON report export.
- Human-review reminder and no automated endpoint remediation.

## Architecture and stack

See [architecture diagram](docs/architecture.md). Python 3.11+, FastAPI, SQLite, React, Vite, Recharts, and lucide-react. Local runtime footprint is small; no Elasticsearch or background service is required.

## Run locally

### Backend

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

On Linux/macOS, activate with `source .venv/bin/activate`. The API docs are at `http://127.0.0.1:8000/docs`.

### Dashboard

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite (normally `http://127.0.0.1:5173`). Set `VITE_API_URL` if the API uses a different local address.

## Simulate an incident

Click **Run demo** in the dashboard or, with the API running, execute from the repository root:

```powershell
python -m simulator.brute_force_simulator
```

The workflow is documented in [docs/demo.md](docs/demo.md). This sends only synthetic failed-login events and never attempts to authenticate to a real account.

## Optional Windows Event Log collection

Install the optional `pywin32` dependency on Windows (`python -m pip install pywin32`) and run the API elevated if your machine requires admin access to read the Security channel. Then execute from the repository root:

```powershell
python -m backend.collectors.windows_to_api --limit 100
```

This reads a bounded batch of recent 4624/4625 events. Field extraction is best-effort because event layouts differ across Windows versions. Inspect events before using them for operational decisions. Linux authentication log ingestion is a future extension.

## API overview

- `GET /api/events`, `GET /api/events/{id}`, `POST /api/events/ingest`
- `GET /api/alerts`, `GET /api/alerts/{id}`, `POST /api/alerts/{id}/investigate`
- `GET /api/incidents`, `GET /api/incidents/{id}`, `GET /api/investigations/{id}`
- `GET /api/dashboard/stats`, `POST /api/demo/brute-force`

Full interactive schema: `/docs`.

## Security and privacy notes

- The API and dashboard development server bind to loopback in the provided commands.
- The SQLite database and collected logs stay local by default; database files are ignored by Git.
- Do not commit `.env`, API credentials, personal security logs, or employer data.
- Log content is untrusted. The MVP does not send logs to an external model or provide shell execution tools.
- Recommendations are suggestions. The product does not block addresses, modify accounts, or perform remediation.
- Windows username/IP normalization is incomplete and may return unknown fields.

## Current limitations and next steps

- Optional Wazuh integration, Linux collector, configurable rule loading, streaming updates, and multi-endpoint support are not included.
- Provider-backed LangGraph investigation, IP reputation lookups, calibrated confidence, and MITRE mapping remain future work. Current reports are deterministic local assessments, not an LLM's judgement.
- Add automated backend and frontend verification, screenshots, and a short demo recording before portfolio release.
