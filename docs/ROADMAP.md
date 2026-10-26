# Roadmap

SF-013 and SF-014 are `LOGTEST VALID` on synthetic sshd lines. SF-001 through SF-006 are written and `SYNTAX VALID` (`REQUIRES WINDOWS VALIDATION`). The other rows are not written yet. Nothing is `LAB VALIDATED`.

The MVP set is one Windows attack story:

**failed logons → successful logon → suspicious PowerShell → privilege change → remote connection**

About 12 detections are MVP (`SF-001`–`SF-012`). `SF-013`–`SF-020` are stretch. Stretch work does not block the story.

Every Windows row is **REQUIRES WINDOWS VALIDATION**. In the Mac column, "Yes" means `wazuh-logtest` can evaluate that synthetic sample. "Limited" means the eventchannel path cannot be replayed (Step 9.1), so the Mac status stops at `SYNTAX VALID`. Neither value means the guest already emits the event.

## MVP detections — the story

| ID | Name | MITRE | Telemetry | Event IDs or log | Tier | LOGTEST on Mac? | Step 10 batch |
|---|---|---|---|---|---|---|---|
| SF-001 | Repeated failed logons | T1110.001 | `windows_security` | Security **4625**. Field `win.eventdata.targetUserName` is in the 4.14.9 ruleset. | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 1 |
| SF-002 | Password spray | T1110.003 | `windows_security` | Security **4625** from one source IP. `different_field` is absent, so distinct users are Step 14. | MVP | Limited (eventchannel can't be replayed, see Step 9.1). **VERIFY** that a Windows agent honors `frequency` / `timeframe` the same way logtest did for sshd. | 1 |
| SF-003 | Successful logon after failures | T1078 | `windows_security` | Security **4624** after the SF-001 burst, same account and source IP. | MVP | Limited (eventchannel can't be replayed, see Step 9.1). Same frequency **VERIFY** on a Windows agent. | 1 |
| SF-004 | Suspicious PowerShell script block | T1059.001 | `powershell` | PowerShell Operational **4104**. Parent 91802. Logging must be enabled first. Cradle strings are SF-006. | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 2 |
| SF-005 | Encoded PowerShell process | T1059.001 | `sysmon` | Sysmon **1** `commandLine` for powershell.exe or pwsh.exe. Rule 67027 matches **4688** and does not read commandLine, so this rule does not use 4688. | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 2 |
| SF-006 | PowerShell download cradle | T1105 | `powershell`, `sysmon` | **4104** cradle text, plus Sysmon **3** `destinationIp` when PowerShell connects. The two rules do not wait for each other. | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 2 |
| SF-007 | User added to local Administrators | T1098 | `windows_security` | Security **4732**. **VERIFY** against a lab event on WS01. | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 3 |
| SF-008 | User added to a privileged domain group | T1098 | `windows_security` | Security **4728** for a global group such as Domain Admins. **4756** is universal. **VERIFY** which event DC01 emits. | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 3 |
| SF-009 | New local or domain user | T1136.001 | `windows_security` | Security **4720**. | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 3 |
| SF-010 | Inbound RDP logon | T1021.001 | `windows_security` | Security **4624**, logon type **10**. **VERIFY** decoded field name (`win.eventdata.logonType` is a candidate). | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 4 |
| SF-011 | SMB / admin-share remote logon | T1021.002 | `windows_security` | Security **4624**, logon type **3**. Share detail **5140** or **5145**. **VERIFY** which share event the audit policy produces. | MVP | Limited (eventchannel can't be replayed, see Step 9.1) | 4 |
| SF-012 | WinRM / PowerShell remoting | T1021.006 | `windows_security` | Security **4624** type **3**. WinRM Operational event IDs: **VERIFY**. | MVP | Limited (eventchannel can't be replayed, see Step 9.1). WinRM-specific ID is not assumed. | 4 |

Story order inside the MVP: `SF-001` and `SF-002`, then `SF-003`, then `SF-004`–`SF-006`, then `SF-007`–`SF-009`, then `SF-010`–`SF-012`.

**REQUIRES WINDOWS VALIDATION** for `SF-001`–`SF-012`: real Event IDs, `win.eventdata.*` fields, Sysmon config, and PowerShell logging. Parent Wazuh rule IDs used later get `<!-- VERIFY: -->` in the XML.

## Stretch detections

| ID | Name | MITRE | Telemetry | Event IDs or log | Tier | LOGTEST on Mac? | Step 10 batch |
|---|---|---|---|---|---|---|---|
| SF-013 | Linux SSH failure burst | T1110.001 | `linux_auth` | `sshd` failed-password lines in auth log or journal. **VERIFY** Ubuntu 24.04 path. | Stretch | Yes | 0 |
| SF-014 | Linux SSH success after failures | T1078 | `linux_auth` | `sshd` accepted-password line. | Stretch | Yes | 0 |
| SF-015 | Suspicious Linux command execution | T1059.004 | `auditd` | auditd `EXECVE` / `SYSCALL`. **VERIFY** key names. | Stretch | Yes | later |
| SF-016 | LSASS memory access | T1003.001 | `sysmon` | Sysmon **10**. **REQUIRES WINDOWS VALIDATION**. | Stretch | Limited (eventchannel can't be replayed, see Step 9.1) | later |
| SF-017 | Scheduled task created | T1053.005 | `windows_security` | Security **4698**. **REQUIRES WINDOWS VALIDATION**. | Stretch | Limited (eventchannel can't be replayed, see Step 9.1) | later |
| SF-018 | Security log cleared | T1070.001 | `windows_security` | Security **1102**. **REQUIRES WINDOWS VALIDATION**. | Stretch | Limited (eventchannel can't be replayed, see Step 9.1) | later |
| SF-019 | New service installed | T1543.003 | `windows_security` | System **7045**. **VERIFY** channel and Wazuh decoder. **REQUIRES WINDOWS VALIDATION**. | Stretch | Limited (eventchannel can't be replayed, see Step 9.1) | later |
| SF-020 | Suricata alert on lab traffic | T1071 | `suricata` | eve.json alert record. **VERIFY** schema for the Suricata version that gets installed. | Stretch | Yes, with a synthetic eve line. The sensor itself needs SURI01. | later |

`SF-013`–`SF-015` need the Ubuntu guest, not the Windows host. `SF-016`–`SF-019` are **REQUIRES WINDOWS VALIDATION**. `SF-020` needs SURI01, which stays powered off until then.

## Console features

| Feature | Tier | Why it is in that tier |
|---|---|---|
| App shell, design system, demo banner | MVP | Required before any page is honest about fixture data. |
| SOC Overview | MVP | Shows the story's alerts, failures, and latest incident. Empty states stay empty until data exists. |
| Incidents queue and investigation workspace | MVP | Timeline, entities, MITRE, evidence, notes, disposition, risk breakdown. |
| Threat hunting: query, results, saved hunts, promote to incident | MVP | The same story must be huntable, not only alerted. |
| Detections library and rule detail | MVP | Shows `SF-001`–`SF-012` metadata, XML, and Sigma. |
| MITRE coverage | MVP | The story's techniques, colored by validation status with a text label. |
| Data sources and system health | MVP | Needed when live mode is turned on. Until then they show an empty or unreachable state. |
| Single-admin auth, CORS, `DATA_MODE=demo\|live` | MVP | Live mode errors when Wazuh is unreachable. It does not fall back to demo data. |
| Read-only Wazuh API and indexer clients | MVP | Written on the Mac against mocks. Real calls wait for the lab. |
| Correlation into one incident, explainable risk score | MVP | Backend logic, tested with synthetic events. Weights are defined in Step 14, not measured here. |
| Entities list and profile | MVP | Simple profiles for the user and host in the story. |
| Automation and Settings pages | Stretch | Placeholders only until a later step. |
| Response actions (isolate, disable account, block IP) | Stretch | `LAB ONLY`, dry-run, explicit approval, audit log. |
| Archives-heavy hunt views | Stretch | Depends on archives indexing and disk headroom. |
| Suricata / SURI01 views | Stretch | `SF-020` and the optional VM. |
| `SF-013`–`SF-020` in the library | Stretch | Present as planned IDs. Not required for the first attack story. |

No alert counts, MTTD, or coverage percentages belong on this page until metadata and the lab produce them.

## Implementation order

| Step | Work | Where it runs |
|---|---|---|
| 3 | Frontend setup and design system | Mac |
| 4 | SOC Overview in demo mode | Mac |
| 5 | Incidents and investigation in demo mode | Mac |
| 6 | Hunting, entities, detections, MITRE, sources, health. Automation and Settings stay placeholders. | Mac |
| 7 | FastAPI, SQLite, demo/live switch, admin auth | Mac |
| 8 | Wazuh API and indexer clients, mocked tests, `# VERIFY:` on uncertain fields | Mac |
| 9 | `wazuh-logtest` in Docker | Mac |
| 10 | MVP detections `SF-001`–`SF-012`, in batches | Mac, then **REQUIRES WINDOWS VALIDATION** |
| 11 | Detection-as-code CI | GitHub Actions |
| 12 | Lab configs and PowerShell/Bash scripts, written and linted only | Mac. Apply later on the lab. |
| 13 | Saved hunts and simulations with cleanup | Written on Mac. Simulations run only in the lab. |
| 14 | Correlation, risk scoring, ADR for where correlation lives | Mac, pytest with a synthetic story |
| 15 | Lab build runbook and VM build | Windows host. **REQUIRES WINDOWS VALIDATION** |
| 16 | Audit policy, PowerShell logging, Sysmon, agents, archives, custom rules | Lab. **REQUIRES WINDOWS VALIDATION** |
| 17 | `DATA_MODE=live` to WAZUH01, read-only users, CA bundle | Mac plus lab |
| 18 | Validate detections one at a time from real output | Lab |
| 19 | Full attack story and `incidents/INC-0001.md` from real alerts | Lab |
| 20 | README metrics from real counts, screenshot checklist, interview notes | After the lab evidence exists |

Steps 3–14 do not need the Windows PC. Steps 15–20 do.
