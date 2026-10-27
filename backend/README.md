# SentinelForge API

FastAPI service between the analyst console and Wazuh. Demo mode serves the shared fixtures in `/fixtures` and stores analyst state in SQLite. Live mode calls Wazuh and does not fall back to those fixtures.

Python **3.12**. Versions are pinned in `requirements.txt` and `docs/VERSIONS.md`.

## Setup

From the repo root:

```bash
python3.12 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements-dev.txt
cp .env.example .env
```

`.env` stays gitignored. Fill in `SESSION_SECRET` and a bcrypt password hash. Do not put the password itself in `.env`.

```bash
backend/.venv/bin/python scripts/validation/hash_password.py
```

Copy the printed hash into `CONSOLE_ADMIN_PASSWORD_HASH`.

`DATA_MODE=demo` serves fixtures and marks responses with `"demo": true`. `DATA_MODE=live` refuses to start when the Wazuh URL, user, or password is empty or still a placeholder. Live overview, sources, health, entities, detections, and hunt runs call Wazuh and return `"demo": false`. If Wazuh is unreachable they return **503** with the reason. They never fall back to demo data. Incidents stay in SQLite. Creating incidents from live alerts is not wired.

## Migrate

From `backend/`:

```bash
.venv/bin/alembic upgrade head
```

The first revision creates `incidents`, `incident_events`, `notes`, `risk_events`, `saved_hunts`, and `audit_log`. Starting the server also runs this upgrade. In demo mode, the first run seeds incidents and notes from `/fixtures` with `demo=true`.

The database file is `backend/data/sentinelforge.db` (gitignored).

## Run

From `backend/`:

```bash
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

OpenAPI docs: http://127.0.0.1:8000/docs

`GET /health` does not require a login. Every `/api/*` route does. `POST /auth/login` checks the bcrypt hash and sets an httpOnly, SameSite=Lax cookie. Login attempts are written to `audit_log`.

Response actions (`POST /api/incidents/{id}/actions`) are **LAB ONLY**. `confirm` must be true. The call writes `audit_log.dry_run=true` and returns `Dry run: no action executed`. Nothing is isolated, disabled, or blocked.

Wazuh credentials are never returned by an endpoint. Request logs record the method, path, and status only.

## Test

From the repo root:

```bash
make test
make lint
```

Plain `uvicorn` from `backend/` and `npm run dev` from `frontend/` still work. Docker is optional:

```bash
docker compose up --build
```

The API is on http://localhost:8000 and the built console is on http://localhost:8080. Compose sets `API_CORS_ORIGIN` to that console origin. Local Vite stays on http://localhost:5173, which is the default in `.env.example`.

Use `localhost` for `VITE_API_URL`, not `127.0.0.1`. The session cookie is same-site only when the page and the API share a host name.

`make dev-backend` and `make dev-frontend` start the two processes separately.
