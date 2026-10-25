# frontend/

The SentinelForge analyst console: React 19 + Vite + TypeScript + Tailwind + Recharts.

It is a SOC console on top of Wazuh. It never talks to Wazuh directly. Live data will come
through `backend/` once that exists. Step 3 is the shell and design system only.

## Data modes

- `VITE_DATA_MODE=demo`: labeled fixtures in `src/fixtures/` and a **DEMO DATA** banner.
  No dashboard fixtures yet.
- `VITE_DATA_MODE=live`: requests go to `VITE_API_URL`. The backend is not built yet, so
  live mode has nothing to call.

Copy `frontend/.env.example` to `frontend/.env` to change the mode locally. `.env` is gitignored.

## Run

From this folder:

```bash
npm install
npm run dev
```

Open http://localhost:5173

`/dev/components` lists every base component. That route exists only in `npm run dev`.

## Checks

```bash
npm run lint
npm run build
npx tsc --noEmit
```

**Status:** Step 3 shell and design system. Pages are placeholders.
