# frontend/

The SentinelForge analyst console: React 19 + Vite + TypeScript + Tailwind + Recharts.

It is a SOC console on top of Wazuh. The browser talks to the FastAPI service, not to Wazuh.

## Data modes

- `VITE_DATA_MODE=demo`: labeled fixtures and a **DEMO DATA** banner. This is the default.
- `VITE_DATA_MODE=live`: requests go to `VITE_API_URL`. The API must already be running.

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

**Status:** Demo pages run from fixtures. Nothing on those pages is `LAB VALIDATED`.
