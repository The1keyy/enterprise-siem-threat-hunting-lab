# Project status

> Cursor/AI: read this file first at the start of every new chat, and update it at the end of
> every step.

## Current step
**Step 1: Repo scaffold. Done.**
**Next:** Step 2: Architecture & ADRs (docs only).

## Repository
- GitHub: https://github.com/The1keyy/enterprise-siem-threat-hunting-lab (branch `main`)
- Local path: `/Users/adage-131/Desktop/siem-pro`

## Step log

| Step | Description | State |
|---|---|---|
| 1 | Repo scaffold | Done |
| 2 | Architecture & ADRs | Not started |
| 3 | Frontend setup + design system | Not started |
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
- `scripts/validation/check_scaffold.sh` (verifies the structure)
- `.cursor/rules/` (Cursor project rules)

## Open questions
- [ ] Windows PC hardware (RAM / CPU / free disk). Needed for VM sizing in Step 2.

## Needs Windows validation
Nothing yet.
