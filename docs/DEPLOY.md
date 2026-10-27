# Deploy the demo console

The public site is demo-only. It serves the fixtures bundled into the frontend. It does not run the API, it does not talk to Wazuh, and demo mode does not show a login form. The DEMO DATA banner stays.

The API is intentionally not public. Live mode runs only inside the lab.

Do not set `VITE_API_URL` or any other `VITE_` variable on Vercel. The build refuses to run there unless `VITE_DATA_MODE` is exactly `demo`, and it refuses if any other `VITE_` variable is present. That keeps a lab URL out of the public bundle.

## Why fixtures stay outside `frontend/`

`frontend/src/fixtures/*.ts` imports `../../../fixtures/*.json`. Those JSON files are the shared source for the API and the console.

The repository root `vercel.json` installs and builds `frontend/` and publishes `frontend/dist`. The build runs from a full checkout, so `../fixtures` is on disk. Leave the Vercel Root Directory empty (the repository root). Do not set it to `frontend`. That setting uploads only the frontend folder and the fixture imports fail.

## Dashboard

1. Push `main` to GitHub.
2. In Vercel, Add New → Project, and import `The1keyy/enterprise-siem-threat-hunting-lab`.
3. Leave Root Directory as the repository root. The root `vercel.json` sets the install command, the build command, the output directory, the SPA rewrite, and the headers. Framework is overridden there, so the preset can stay blank.
4. Do not add environment variables. An unset `VITE_DATA_MODE` builds the demo. `VITE_DATA_MODE=live`, or any other `VITE_` variable, fails the build on purpose.
5. Deploy.

Every push to `main` deploys Production. Other branches deploy a Preview. GitHub Actions also builds the frontend with `VERCEL=1` and `VITE_DATA_MODE=demo`, and checks that `VITE_DATA_MODE=live` is rejected.

The rewrite sends every app path to `index.html`, so a refresh on `/incidents/INC-a69e4a81` still loads the app. Hashed files under `/assets/` are cached for a year. `index.html` is not. The content security policy allows scripts, styles, fonts, and connections from this origin only, and `frame-ancestors 'none'` stops the site from being framed.

## CLI

From the repo, with the Vercel account logged in:

```bash
npm install -g vercel
vercel
```

Run that from the repository root, not from `frontend/`. The first `vercel` links the project. Leave the root as this directory. Do not set `VITE_DATA_MODE`. Then:

```bash
vercel --prod
```

Do not deploy a copy of `frontend/` that was separated from the repo. The build reads `fixtures/` next to it.

## Custom domain

Optional. Project → Settings → Domains → add the domain and follow the DNS records Vercel shows. No code change. The same demo build is served.

## Local production check

```bash
cd frontend
npm run build
npx vite preview --host 127.0.0.1 --port 4173
```

`npm run build` without `VERCEL=1` still bundles demo mode when `VITE_DATA_MODE` is unset or `demo`. To see the guard refuse a live build:

```bash
VERCEL=1 VITE_DATA_MODE=live node scripts/assert-demo-build.mjs
```

That command exits non-zero.
