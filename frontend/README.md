# frontend/

The SentinelForge analyst console: React 19 + Vite + TypeScript + Tailwind + Recharts.

It is a polished SOC console on top of Wazuh. It never talks to Wazuh directly; all data comes
through `backend/`.

## Data modes
- `VITE_DATA_MODE=demo`: uses labeled fixtures in `src/fixtures/` and always shows a
  **DEMO DATA** banner.
- `VITE_DATA_MODE=live`: uses the backend API at `VITE_API_URL`.

**Status:** Not started (created in Step 3).
