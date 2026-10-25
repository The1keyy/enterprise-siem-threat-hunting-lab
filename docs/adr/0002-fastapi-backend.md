# ADR 0002 — FastAPI backend

- **Status:** Accepted
- **Date:** 2026-10-25
- **Stack:** Python 3.12, FastAPI, SQLAlchemy 2, SQLite for development (`docs/VERSIONS.md`)

## Decision

A FastAPI service is the only process that talks to Wazuh. The React console talks to FastAPI. Analyst state lives in SQLite. Configuration comes from environment variables.

## Context / why

Wazuh does not store this project's incidents, notes, dispositions, saved hunts, or audit log. Something has to hold that state, hide Wazuh credentials from the browser, and host the risk-score math. Python 3.12 is already the language for detection tests, so the API uses the same runtime. SQLite is enough for one analyst on a lab machine. Postgres waits for a later ADR if there is a real reason.

## Alternatives considered

| Option | Why it lost |
|---|---|
| Browser calls the Wazuh API and indexer directly | Credentials end up in the frontend. There is still no place to store a case. |
| Django | Heavier than this API needs. FastAPI plus SQLAlchemy covers the routes and the models. |
| Node.js API beside the React app | Works, and it splits the backend away from the Python detection tests. |
| Postgres on day one | Another service to run before there is a second user. |

## Tradeoffs

- Two processes to start on the Mac: Vite and Uvicorn.
- SQLite has one writer. That matches a single admin. It will not be the story if this ever becomes multi-user.
- Live mode must fail with a clear error when WAZUH01 is unreachable. Falling back to fixture data would hide an outage.
- Self-signed lab TLS needs an explicit CA bundle path. Turning verification off requires a logged, lab-only flag.

## What I must understand

- `DATA_MODE=demo` returns fixtures and `"demo": true`. `DATA_MODE=live` never does that.
- The manager API (planned port `55000`, JWT) and the indexer (planned port `9200`) are different clients. **VERIFY** both ports on 4.14.9.
- Read-only users only. The backend does not use the Wazuh admin account.
- Incidents, notes, risk events, saved hunts, and the audit log are SQLite tables. Alerts stay in Wazuh.
- Response actions, when they exist, default to dry-run and write the audit log.

## Likely interview questions + short answers

**Why doesn't the React app call Wazuh itself?**
The browser would need the Wazuh password, and Wazuh still wouldn't store my case notes. The API keeps the credentials and owns the analyst data.

**Why SQLite?**
One analyst, one lab, no extra database VM. If I need Postgres later I will write an ADR. I don't want a second service before the first incident workflow works.

**What does the UI show when the lab is off?**
In live mode it shows an error. It does not quietly switch to demo data. Demo mode is a separate switch, and the banner stays up.
