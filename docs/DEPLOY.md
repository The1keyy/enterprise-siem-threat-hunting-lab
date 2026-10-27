# Deploy the demo console

The public site is demo-only. It serves the fixtures bundled into the frontend. It does not run the API, it does not talk to Wazuh, and demo mode does not show a login form. The DEMO DATA banner stays.

The API is intentionally not public. Live mode runs only inside the lab.

Do not set `VITE_API_URL` or any other `VITE_` variable on Vercel. The build refuses to run there unless `VITE_DATA_MODE` is exactly `demo`, and it refuses if any other `VITE_` variable is present. That keeps a lab URL out of the public bundle.

## Why fixtures stay outside `frontend/`

`frontend/src/fixtures/*.ts` imports `../../../fixtures/*.json`. Those JSON files are the shared source for the API and the console.

Copying them into `frontend/` at prebuild is not more reliable on Vercel. With Root Directory set to `frontend`, Vercel does not upload the parent directory unless you turn on the checkbox below. A copy step would fail for the same reason: the files to copy were never uploaded.

Leave the imports where they are. Turn the checkbox on so the build can see `../fixtures`. A missing file fails `npm run build` with the same path.

Projects created after 27 August 2020 have that checkbox on by default. Confirm it anyway.

**Where:** Project → Settings → Build and Deployment → Root Directory → Edit → enable **Include source files outside of the Root Directory in the Build Step**.

## Dashboard

1. Push `main` to GitHub.
2. In Vercel, Add New → Project, and import `The1keyy/enterprise-siem-threat-hunting-lab`.
3. Set Root Directory to `frontend`.
4. Enable **Include source files outside of the Root Directory in the Build Step** (path above).
5. Framework Preset: Vite. Build command: `npm run build`. Output: `dist`. `frontend/vercel.json` sets the framework, the SPA rewrite, and the headers.
6. Environment variable, for Production, Preview, and Development: `VITE_DATA_MODE` = `demo`. Add no other `VITE_` variable.
7. Deploy.

Every push to `main` deploys Production. Other branches deploy a Preview. GitHub Actions also builds the frontend with `VERCEL=1` and `VITE_DATA_MODE=demo`, and checks that `VITE_DATA_MODE=live` is rejected.

`frontend/vercel.json` sends every path to `index.html`, so a refresh on `/incidents/INC-0001` still loads the app. Hashed files under `/assets/` are cached for a year. `index.html` is not. The content security policy allows scripts, styles, fonts, and connections from this origin only, and `frame-ancestors 'none'` stops the site from being framed.

## CLI

From the repo, with the Vercel account logged in:

```bash
npm install -g vercel
cd frontend
vercel
```

The first `vercel` links the project. When it asks for the root, this directory is already `frontend`. Set `VITE_DATA_MODE` to `demo` when prompted, or in the dashboard before production. Then:

```bash
vercel --prod
```

The CLI still needs the parent `fixtures/` directory. Run it from a full checkout, and leave the "include source files outside the root" option enabled on the linked project. Do not point the CLI at a copy of `frontend/` that was separated from the repo.

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
