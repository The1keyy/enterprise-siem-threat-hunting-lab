# SentinelForge

[![detections](https://github.com/The1keyy/enterprise-siem-threat-hunting-lab/actions/workflows/detections.yml/badge.svg?branch=main)](https://github.com/The1keyy/enterprise-siem-threat-hunting-lab/actions/workflows/detections.yml)
[![app](https://github.com/The1keyy/enterprise-siem-threat-hunting-lab/actions/workflows/app.yml/badge.svg?branch=main)](https://github.com/The1keyy/enterprise-siem-threat-hunting-lab/actions/workflows/app.yml)
[![logtest](https://github.com/The1keyy/enterprise-siem-threat-hunting-lab/actions/workflows/logtest.yml/badge.svg?branch=main)](https://github.com/The1keyy/enterprise-siem-threat-hunting-lab/actions/workflows/logtest.yml)
[![secrets](https://github.com/The1keyy/enterprise-siem-threat-hunting-lab/actions/workflows/secrets.yml/badge.svg?branch=main)](https://github.com/The1keyy/enterprise-siem-threat-hunting-lab/actions/workflows/secrets.yml)

**Enterprise SIEM & Live Threat Hunting Platform**

Repository: enterprise-siem-threat-hunting-lab · Project name: SentinelForge

> **Status: In development (Phase 1: foundation).**
> Nothing in this repository has been lab-validated yet. Metrics will appear here only once they
> are real.

SentinelForge is a free, open-source SOC lab built on **Wazuh**. It adds a custom analyst console
(FastAPI + React) for:
- incident investigation
- threat hunting
- explainable risk scoring
- MITRE ATT&CK coverage

Detections are managed as code and validated in CI and in an isolated Active Directory lab.

## Detection-as-Code

Counts below are from `detections/metadata/SF-*.yml` (14 files).

| Status | Count |
|---|---|
| `SYNTAX VALID` | 12 (SF-001 through SF-012, Windows) |
| `LOGTEST VALID` | 2 (SF-013 and SF-014, Linux sshd) |
| `LAB VALIDATED` | 0 |

A detection moves in this order:

1. The Wazuh rule, Sigma rule, metadata, sample cases, and write-up land together.
2. `tests/logs/SF-XXX.yml` holds the synthetic cases. Windows cases are `lab_reference` and stay `LIMITED` in logtest.
3. On the Mac, `make logtest-up` then `make logtest` runs those cases in `wazuh/wazuh-manager:4.14.9`.
4. CI runs four checks: `detections` (YAML, the validator, Sigma, pytest), `app` (frontend and backend), `logtest` (the same manager image and compose file), and `secrets` (gitleaks). `LIMITED` does not fail logtest. A `FAIL` does. A detection already marked `LOGTEST VALID` must fully `PASS` in that run.
5. Lab validation is a later step, from a simulation inside `sentinelforge.lab`, with evidence. CI does not set `LAB VALIDATED`.

## Planned lab
| Host | Role |
|---|---|
| DC01 | Windows Server: Active Directory, DNS |
| WS01 | Windows 11: domain-joined workstation |
| UBU01 | Ubuntu Server: Linux telemetry |
| WAZUH01 | Wazuh manager, indexer, dashboard |
| SURI01 | Suricata network sensor (optional) |

## Repository layout
| Folder | Purpose |
|---|---|
| `frontend/` | SentinelForge analyst console (React + Vite + TypeScript) |
| `backend/` | API layer between the console and Wazuh (FastAPI) |
| `detections/` | Detection-as-code: Wazuh rules, Sigma rules, metadata |
| `hunting/` | Saved threat hunts |
| `scripts/` | PowerShell/Bash lab setup, attack simulations, validation tooling |
| `configs/` | Windows, Sysmon, Linux, Wazuh, Suricata configuration |
| `incidents/` | Incident reports from lab investigations |
| `architecture/` | Architecture diagrams and design |
| `docs/` | ADRs, detection writeups, runbooks, project status |
| `screenshots/` | Real screenshots from the running lab only |
| `tests/` | Sample logs and automated tests |

## Validation statuses
Every detection, script, and config carries one of these statuses:

| Status | Meaning |
|---|---|
| `NOT TESTED` | Written, not checked |
| `SYNTAX VALID` | Passes CI linting |
| `LOGTEST VALID` | Fires correctly in `wazuh-logtest` against sample logs |
| `LAB VALIDATED` | Fired from a real simulation in the lab, with evidence |
| `NEEDS TUNING` | Fires, but with false positives or gaps |

## Project status
See [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md).

## License
MIT. See [LICENSE](LICENSE).
