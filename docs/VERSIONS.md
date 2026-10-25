# Pinned versions

This file is the single source of truth for versions. Change a version only with a short ADR in
`docs/adr/`.

**Last checked:** 2026-10-25 (application stack locked in Step 3)

Anything marked **VERIFY** must be confirmed against the official download page on the day you
install it.

## SIEM

| Component | Version | Notes |
|---|---|---|
| Wazuh manager / indexer / dashboard | **4.14.9** | Latest 4.x on the official release notes as of 2026-10-25. Wazuh 5.0 is in beta/RC: **do not use** for this project. |
| Wazuh agents (Windows + Linux) | **4.14.9** | Agent version must not be newer than the manager. |

## Lab operating systems (free evaluation/community editions)

| VM | OS | Notes |
|---|---|---|
| DC01 | Windows Server 2022 or 2025 Evaluation | 180-day eval from Microsoft Evaluation Center. **VERIFY** which is offered. |
| WS01 | Windows 11 Enterprise Evaluation | Windows 10 reached end of support in Oct 2025, so use Windows 11. **VERIFY** eval length. |
| UBU01 | Ubuntu Server 24.04 LTS | |
| WAZUH01 | Ubuntu Server 24.04 LTS | **VERIFY** it is on the Wazuh 4.14 supported OS list before installing. |
| SURI01 | Ubuntu Server 24.04 LTS + Suricata (stable) | Optional/stretch. **VERIFY** Suricata version at install. |

**Hypervisor:** VMware Workstation Pro 26.0.1 on the Windows lab PC (reported 2026-10-25).
**VERIFY** license terms for that build. The host OS is Windows 10 Home 64-bit and is out of
support; the lab stays on a host-only network.

## Endpoint telemetry

| Component | Version | Notes |
|---|---|---|
| Sysmon | Latest from Microsoft Sysinternals | **VERIFY** version at install and record it here. |
| Sysmon config base | sysmon-modular or SwiftOnSecurity | Credited in `configs/sysmon/README.md`. Chosen in Step 12. |
| auditd | Ubuntu 24.04 package | |

## Application stack

| Component | Version | Notes |
|---|---|---|
| Node.js | **24.22.1** | Installed for Step 3 (`node -v`). Node 24 LTS. |
| npm | **11.19.1** | Installed with that Node. |
| React / React DOM | **19.3.1** | Locked in `frontend/package-lock.json`. |
| Vite | **8.3.5** | `@vitejs/plugin-react` **6.1.2**. |
| TypeScript | **6.0.3** | `strict` is on. |
| Tailwind CSS | **4.3.3** | `@tailwindcss/vite` **4.3.3**. Tokens live in `frontend/src/styles/tokens.css` via `@theme`. |
| react-router | **8.5.0** | Current major at Step 3. |
| Recharts | **3.10.1** | Installed. Chart wrappers start in Step 4. |
| lucide-react | **1.61.0** | |
| clsx | **2.1.1** | |
| ESLint | **10.13.0** | Flat config in `frontend/eslint.config.js`, plus Prettier **3.9.10**. |
| @fontsource/inter | **5.3.0** | Inter is bundled. No font CDN. |
| Vitest | **5.0.5** | Added in Step 4. jsdom **30.1.3**, Testing Library React **16.3.3**, jest-dom **7.0.1**. |
| Python | **3.12** | |
| FastAPI / SQLAlchemy 2 / pydantic-settings | Current stable at Step 7 | Locked in `backend/requirements.txt` with exact pins. |
| Database | SQLite (dev) | Postgres only if an ADR justifies it. |

## Detection tooling

| Component | Version | Notes |
|---|---|---|
| sigma-cli / pySigma | Current stable at Step 11 | Pinned in CI. |
| yamllint, shellcheck, PSScriptAnalyzer | Current stable | Installed on the Mac via Homebrew / PowerShell Gallery. |

## Mac development tools

```bash
brew install node@24 python@3.12 powershell shellcheck yamllint
# Docker Desktop (free for personal use) — needed in Step 9 for wazuh-logtest
```
