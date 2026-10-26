.PHONY: dev-backend dev-frontend test lint up

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

up:
	docker compose up --build
