FROM python:3.12-slim

WORKDIR /opt/sentinelforge/backend

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /opt/sentinelforge/backend
COPY fixtures/ /opt/sentinelforge/fixtures

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
