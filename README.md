# SentinelForge

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
