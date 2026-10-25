# Project status

> Cursor/AI: read this file first at the start of every new chat, and update it at the end of
> every step.

## Current step
**Step 3: Frontend setup and design system. Done.**
**Next:** Step 4: SOC Overview (demo). Not started.

## Repository
- GitHub: https://github.com/The1keyy/enterprise-siem-threat-hunting-lab (branch `main`)
- Local path: `/Users/adage-131/Desktop/siem-pro`

## Step log

| Step | Description | State |
|---|---|---|
| 1 | Repo scaffold | Done |
| 2 | Architecture & ADRs | Done |
| 3 | Frontend setup + design system | Done |
| 4 | SOC Overview (demo) | Not started |
| 5 | Incidents + Investigation (demo) | Not started |
| 6 | Remaining pages (demo) | Not started |
| 7 | Backend setup | Not started |
| 8 | Wazuh integration code | Not started |
| 9 | Local wazuh-logtest in Docker | Not started |
| 10 | MVP detections | Not started |
| 11 | Detection-as-code CI | Not started |
| 12 | Lab configs + scripts | Not started |
| 13 | Hunts + simulations | Not started |
| 14 | Correlation + risk scoring | Not started |
| 15–20 | Windows lab build, validation, polish | Later (Windows lab) |

## Validation summary
Real counts only. Update these as work actually happens.

| Item | Count |
|---|---|
| Detections written | 0 |
| `SYNTAX VALID` | 0 |
| `LOGTEST VALID` | 0 |
| `LAB VALIDATED` | 0 |
| Saved hunts | 0 |
| Attack simulations run in lab | 0 |
| Telemetry sources confirmed ingesting | 0 |
| CI | No workflows yet |

## What exists so far
- Folder structure with a README per folder
- Root files:
  - `README.md`, `LICENSE` (MIT)
  - `.gitignore`, `.gitattributes`, `.editorconfig`, `.env.example`
- `docs/VERSIONS.md` (pinned versions)
- `architecture/ARCHITECTURE.md` (network, VM plan, data flow)
- `docs/ROADMAP.md` (SF-001–SF-020, MVP story, steps 3–20)
- `docs/MAC_VS_WINDOWS.md`
- `docs/adr/0001-wazuh-as-siem.md`, `0002-fastapi-backend.md`, `0003-console-on-top-of-wazuh.md`
- `scripts/validation/check_scaffold.sh` (verifies the structure)
- `.cursor/rules/` (Cursor project rules)
- `frontend/` analyst console shell (Step 3): design tokens, AppShell, base components, demo/live client. No dashboard data yet.
- No backend and no lab scripts yet

## Frontend versions (Step 3)
Locked in `frontend/package-lock.json`. See `docs/VERSIONS.md`.

| Tool | Version |
|---|---|
| Node.js | 24.22.1 |
| npm | 11.19.1 |
| React | 19.3.1 |
| Vite | 8.3.5 |
| TypeScript | 6.0.3 |
| Tailwind CSS | 4.3.3 |
| react-router | 8.5.0 |

## Lab host
Recorded in Step 2. Used for the VM plan in `architecture/ARCHITECTURE.md`.

| Item | Value |
|---|---|
| CPU | Intel Core i7-13700F, 16 cores / 24 threads |
| RAM | 32 GB. Plan leaves at least 10 GB for the host (14 GB with the default guest set). |
| Storage | 1 TB SSD |
| Host OS | Windows 10 Home 64-bit, out of support. Lab stays off the home LAN. |
| Hypervisor | VMware Workstation Pro 26.0.1 |
| Default powered-on guests | WAZUH01 8 GB, DC01 4 GB, WS01 4 GB, UBU01 2 GB. SURI01 off. |

## Open questions
- [ ] **VERIFY** Wazuh 4.14.9 published hardware minimums, indexer heap file, and `-Xms`/`-Xmx` (or the real setting names) before install.
- [ ] **VERIFY** Windows Server evaluation edition offered (2022 vs 2025) and Windows 11 eval length.
- [ ] **VERIFY** manager API port, indexer port, dashboard port, and index pattern names on 4.14.9.
- [ ] WS01 stays at 4 GB unless the guest is unusable. 6 GB is allowed only with SURI01 powered off.
- [ ] SSH from the Mac to the Windows host is the recommended path and is not set up yet.

## Needs Windows validation
Step 3 is Mac-only UI. Nothing in the frontend needs the Windows lab.

Still documented, not built:

- Host-only or LAN segment for `10.10.10.0/24`, no bridged victim NIC
- Temporary NAT adapter for updates, then removed
- WS01 virtual TPM and VM encryption on Workstation Pro 26.0.1
- Static IPs, DC01 DNS, domain join
- Wazuh 4.14.9 all-in-one on the 8 GB VM, including the heap cap
- Windows Event IDs and `win.eventdata.*` fields for SF-001–SF-012
- SSH listener on the Windows host, limited to the Mac
