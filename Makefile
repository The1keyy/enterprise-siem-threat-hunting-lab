.PHONY: dev-backend dev-frontend test lint validate up logtest-up logtest-down logtest logtest-clean

PYTHON = backend/.venv/bin/python

LOGTEST_COMPOSE = docker compose --env-file scripts/validation/logtest/.env -f scripts/validation/logtest/docker-compose.yml

dev-backend:
	cd backend && .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000

dev-frontend:
	cd frontend && npm run dev

test:
	cd backend && .venv/bin/pytest
	cd frontend && npm test

lint:
	cd backend && .venv/bin/ruff check .
	cd frontend && npm run lint

validate:
	$(PYTHON) scripts/validation/validate_detections.py
	$(PYTHON) scripts/validation/sigma_check.py
	$(PYTHON) -m pytest tests/detections

up:
	docker compose up --build

# --wait blocks until the healthcheck is healthy. 120s is the cap; a stuck
# analysisd fails here with compose's timeout instead of a later logtest error.
logtest-up:
	$(LOGTEST_COMPOSE) up -d --wait --wait-timeout 120

logtest-down:
	$(LOGTEST_COMPOSE) down -v --remove-orphans

# Same project only. Does not prune images or other compose projects.
logtest-clean:
	$(LOGTEST_COMPOSE) down -v --remove-orphans

# Checks analysisd, ossec.log ERROR lines, and XML rule counts against
# GET /rules?filename= before it runs cases.
logtest:
	backend/.venv/bin/python scripts/validation/run_logtest.py $(if $(ID),--id $(ID),)
