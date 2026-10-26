# Project status

> Cursor/AI: read this file first at the start of every new chat, and update it at the end of
> every step.

## Current step
**Step 10 batch 2 Done.** SF-004, SF-005, and SF-006 are `SYNTAX VALID`. Analysisd loaded rules 100200, 100210, 100220, and 100221 from `sentinelforge_100200_powershell.xml`. Their logtest cases are `LIMITED` (eventchannel is not replayed), so they are not `LOGTEST VALID`. SF-001, SF-002, and SF-003 stay `SYNTAX VALID`. SF-013 and SF-014 stay `LOGTEST VALID`. Nothing is `LAB VALIDATED`.
**Next:** Step 10 batch 3 (SF-007, SF-008, SF-009) not started.

## Repository
- GitHub: https://github.com/The1keyy/enterprise-siem-threat-hunting-lab (branch `main`)
- Local path: `/Users/adage-131/Desktop/siem-pro`

## Step log

| Step | Description | State |
|---|---|---|
| 1 | Repo scaffold | Done |
| 2 | Architecture & ADRs | Done |
| 3 | Frontend setup + design system | Done |
| 4 | SOC Overview (demo) | Done |
| 5 | Incidents + Investigation (demo) | Done |
| 6A | Hunting, detections, MITRE (demo) | Done |
| 6B | Entities, sources, health, automation, settings (demo) | Done |
| 7A | FastAPI backend core (demo) | Done |
| 7B | Connect the frontend, plus Docker | Done |
| 8 | Wazuh integration code | Done (mock-tested; live behavior REQUIRES LAB VALIDATION) |
| 9 | Local wazuh-logtest in Docker | Done (9.1: Filebeat off, no leftover volumes) |
| 10 | MVP detections | Batch 0 done (SF-013, SF-014). Batch 1 done (SF-001, SF-002, SF-003, `SYNTAX VALID`). Batch 2 done (SF-004, SF-005, SF-006, `SYNTAX VALID`). Batches 3–4 not started |
| 11 | Detection-as-code CI | Not started |
| 12 | Lab configs + scripts | Not started |
| 13 | Hunts + simulations | Not started |
| 14 | Correlation + risk scoring | Not started |
| 15–20 | Windows lab build, validation, polish | Later (Windows lab) |

## Validation summary
Real counts only. Update these as work actually happens.

| Item | Count |
|---|---|
| Detections written | 8 (SF-001, SF-002, SF-003, SF-004, SF-005, SF-006, SF-013, SF-014) |
| `SYNTAX VALID` | 6 (Windows auth and PowerShell) |
| `LOGTEST VALID` | 2 (Linux SSH) |
| `LAB VALIDATED` | 0 |
| Saved hunts | 0 |
| Attack simulations run in lab | 0 |
| Telemetry sources confirmed ingesting | 0 |
| CI | No workflows yet |

| ID | Status | Evidence |
|---|---|---|
| SF-001 | `SYNTAX VALID` | Rule 100100 loaded (level 11, `T1110.001`). Logtest cases `LIMITED`. Not a Windows result. |
| SF-002 | `SYNTAX VALID` | Rule 100110 loaded (level 10, `T1110.003`). Same-IP burst. Distinct users are Step 14. `different_field` is absent in 4.14.9. |
| SF-003 | `SYNTAX VALID` | Rule 100120 loaded (level 12, `T1078` only). Chains on 100100. Two `same_field` elements are unproven until the lab. |
| SF-004 | `SYNTAX VALID` | Rule 100200 loaded (level 12, `T1059.001`). Script block 4104. Logtest cases `LIMITED`. Not a Windows result. |
| SF-005 | `SYNTAX VALID` | Rule 100210 loaded (level 13, `T1059.001` only). Sysmon 1 command line. 4688 is not used. Logtest cases `LIMITED`. |
| SF-006 | `SYNTAX VALID` | Rules 100220 (level 12) and 100221 (level 10), both `T1105`. Script block and Sysmon 3. They do not wait for each other. Logtest cases `LIMITED`. |
| SF-013 | `LOGTEST VALID` | Rule 100701 on the 6th invalid-user failure; 100702 on the 6th known-user failure. Five failures stayed on 5710. |
| SF-014 | `LOGTEST VALID` | Rule 100710 / 100711 after that burst, same source IP. Five failures then a success stayed on 5715. |
| SF-007–SF-012, SF-015–SF-020 | `NOT TESTED` | Not written |

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
- `frontend/` analyst console shell (Step 3), SOC Overview (Step 4), incidents (Step 5), and hunting, detections, and MITRE pages (Step 6A).
- SF-013 and SF-014 are real rules in `detections/wazuh/rules/sentinelforge_100700_linux.xml`. Logtest on 2026-10-26 passed both, including the below-threshold and benign cases. Status is `LOGTEST VALID`. `observed_result` is still `NOT YET VALIDATED`. `lastTriggered` and `alertCount` are null.
- SF-001, SF-002, and SF-003 are real rules in `detections/wazuh/rules/sentinelforge_100100_auth.xml` (100100, 100110, 100120). On 2026-10-26 analysisd started with `Total rules enabled: 8459` and no analysisd error. `GET /rules?rule_ids=100100,100110,100120` returned all three `enabled`. Status is `SYNTAX VALID`. Logtest printed `LIMITED` for every Windows case and did not call logtest for them. They are not `LOGTEST VALID`. `observed_result` is `NOT YET VALIDATED`. `lastTriggered` and `alertCount` are null.
- SF-004, SF-005, and SF-006 are real rules in `detections/wazuh/rules/sentinelforge_100200_powershell.xml` (100200, 100210, 100220, 100221). On 2026-10-26 analysisd started with `Total rules enabled: 8465` and no analysisd error. `GET /rules?filename=sentinelforge_100200_powershell.xml` returned all four `enabled`. Status is `SYNTAX VALID`. Logtest (`tests/results/logtest-20261026T171603Z.json`) printed `LIMITED` for every PowerShell case and did not call logtest for them. They are not `LOGTEST VALID`. `observed_result` is `NOT YET VALIDATED`. `lastTriggered` and `alertCount` are null. SF-007–SF-012 and SF-015–SF-020 are still the placeholder "Not written yet (Step 10)" with status `NOT TESTED`.
- Ten hunt drafts are fixtures. Demo "Run hunt" matches incident timeline events and does not query `wazuh-archives-*`. Live "Run hunt" queries that index and returns 503 if Wazuh is down. Promoting a result writes a SQLite incident.
- The ATT&CK page counts techniques from those detections. Lab-validated coverage is 0. The Navigator layer JSON marks its format version `VERIFY`.
- All 10 sidebar pages render in demo mode. Entity risk reuses `finalRiskScore` from incident breakdowns. Data-source volume counts fixture timeline events. Health cards and agents are `Offline` / `never connected` because the lab is not running. Automation workflows are a design preview and do not run. Settings is read-only.
- Overview numbers are demo fixtures in `frontend/src/fixtures/overview.ts`. They are not lab measurements.
- Incident queue numbers, timelines, and risk scores are demo fixtures in `frontend/src/fixtures/incidents.ts`. Final scores are `round(subtotal × multiplier)` and are covered by tests. They are not lab measurements. Step 14 replaces the weights.
- Shared demo JSON lives in `/fixtures` (`overview`, `incidents`, `detections`, `hunts`, `entities`, `sources`, `health`). Each file has `_notice`: `DEMO DATA — synthetic, not real telemetry`. The frontend fixture modules import those files. `scripts/validation/export_fixtures.mjs` generated them.
- `backend/` is a FastAPI app on Python 3.12. Demo mode seeds SQLite from `/fixtures` and returns `"demo": true`. `GET /health` is open. `/api/*` requires the lab-admin cookie. Live mode calls the Wazuh manager API and indexer. Responses set `"demo": false`. If Wazuh is unreachable the route returns 503 and does not serve fixtures. Incidents stay in SQLite. There is no live Wazuh in this environment, so nothing here is LAB VALIDATED.
- Response actions are LAB ONLY and dry-run. `confirm: true` writes `audit_log.dry_run=true` and returns `Dry run: no action executed`. Nothing is executed.
- With `VITE_DATA_MODE=live` the console calls the API with credentials and redirects to `/login` on 401. `DATA_MODE=demo` on the API still returns `"demo": true`, so the DEMO banner and pill stay up. Incident status, notes, promoted hunts, and dry-run actions are stored in SQLite. Local fixture mode (`VITE_DATA_MODE=demo`) does not call the API.
- Root `Makefile` targets: `dev-backend`, `dev-frontend`, `test`, `lint`, `up`, `logtest-up`, `logtest-down`, `logtest`, `logtest-clean`. `docker compose up --build` runs the API and a static console. Plain `uvicorn` and `npm run dev` still work.
- `make logtest-up` runs `docker compose up -d --wait --wait-timeout 120` and returns only after the healthcheck is healthy, or fails at 120 seconds. It starts only `wazuh/wazuh-manager:4.14.9` as `wazuh-logtest`. Image architecture used: `linux/arm64` (container `uname -m` was `aarch64`). No `platform: linux/amd64`. Custom rules are mounted at `/var/ossec/etc/rules/sentinelforge` and loaded by an entrypoint snippet. That script deletes `/etc/services.d/filebeat` before s6 starts services, so Filebeat is not running. Alert and archive directories are 32m tmpfs. There are no named volumes. `make logtest-down` and `make logtest-clean` remove this container and its volumes only. Analysisd still reached `is running`.
- `make logtest` on 2026-10-26 (`tests/results/logtest-20261026T123424Z.json`, gitignored): printed `0 detections found`. CANARY-001 passed. Invalid-user sshd fired built-in rule **5710** level 5, MITRE `T1110.001` and `T1021.004`. Accepted publickey did not fire 5710 (rule 5715 level 3 fired instead). CANARY-002 is `REQUIRES WINDOWS VALIDATION / logtest-limited`: eventchannel JSON decoded as `json` and rule **1002** level 2, not Windows rule 60122. That is not a pass.
- Wazuh clients live in `backend/app/integrations/`. Tests use synthetic mocks in `backend/tests/wazuh_mocks/`. Severity bands are ADR 0004. Runbooks: `docs/runbooks/wazuh-readonly-users.md`, `docs/runbooks/wazuh-archives.md`.
- Batch standard: `docs/detections/_BATCH_STANDARD.md`. Ruleset notes: `docs/detections/_ruleset-notes.md`. `scripts/validation/build_detection_fixtures.py` refreshes `fixtures/detections.json` from metadata. Step 10 batches 3–4 are not started.

## VERIFY in Step 17 (Wazuh 4.14.9)

These are coded as the expected 4.14 shape and are not confirmed on a running manager:

- Manager API base `https://<WAZUH_MANAGER_IP>:55000`
- `POST /security/user/authenticate` with HTTP Basic auth, JWT in `data.token`, no `expires_in` (cache TTL 900s)
- `Authorization: Bearer <token>`
- `GET /agents`, `GET /manager/status`, `GET /manager/info`, `GET /rules`
- Pagination query names `limit` and `offset`, and `total_affected_items`
- Rule object fields `filename` and `status` (`enabled`)
- Agent fields `name`, `ip`, `status` (`active`, `disconnected`, `never_connected`), `os.name`, `os.version`, `version`, `lastKeepAlive`
- Manager status `affected_items[0]` is a map of `wazuh-*` daemons to `running`
- Manager info `version`
- Read-only API RBAC role and policy names
- Indexer base `https://<WAZUH_MANAGER_IP>:9200` with HTTP Basic auth
- Index patterns `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*`
- Time field `timestamp` (not `@timestamp`), and whether terms fields need a `.keyword` suffix
- `date_histogram` `fixed_interval`, `key_as_string`, and `max.value_as_string`
- `hits.total.value`
- `rule.groups` values: `authentication_failed`, `authentication_success`, `windows`, `sysmon`, `windows_powershell`, `sshd`, `audit`, `suricata`
- `data.srcip`, `data.win.system.eventID`, `data.win.eventdata.targetUserName`, `ipAddress`, `logonType`, `commandLine`, `image`, `parentImage`
- `rule.mitre.id` and `rule.mitre.tactic`
- `GET /_cluster/health` and `GET /_nodes/stats/fs` (`total_in_bytes`, `available_in_bytes`)
- Built-in rule levels top out at 15 (ADR 0004)
- `logall_json` and the Filebeat archives module path, plus archives retention
- Indexer read-only role limited to the two index patterns
- Path of `root-ca.pem` on the all-in-one
- The Wazuh dashboard is not queried; its health status stays null until a later check

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
Step 8 is mock-tested on the Mac. The clients do not talk to a real manager here. Live behavior **REQUIRES LAB VALIDATION**. Dry-run actions do not change a host. Detections and Windows data-source cards that will need Windows validation are tagged. That tag is a plan, not a test result. Health and agent rows in demo mode are not live checks.

Step 9 logtest does not prove Windows field names. CANARY-002 stayed logtest-limited after a second eventchannel replay (decoder `json`, rule 1002, alert false). Windows eventchannel events can't be faithfully replayed in logtest. Step 10 must not mark those detections `LOGTEST VALID` from this harness. They are validated in the lab. Windows Event IDs still need a lab agent.

Still documented, not built:

- Host-only or LAN segment for `10.10.10.0/24`, no bridged victim NIC
- Temporary NAT adapter for updates, then removed
- WS01 virtual TPM and VM encryption on Workstation Pro 26.0.1
- Static IPs, DC01 DNS, domain join
- Wazuh 4.14.9 all-in-one on the 8 GB VM, including the heap cap
- Windows agent events for SF-001–SF-012. Field names for SF-001–SF-006 were read from the 4.14.9 ruleset. A real 4624/4625 from DC01 or WS01 is still required. Frequency, two `same_field` elements, and a `<field>` check on a frequency rule were not replayed. SF-004 and SF-006 still need Script Block Logging (4104) on WS01. SF-005 and SF-006 still need Sysmon EID 1 and EID 3 on WS01. Match behavior for those rules was not replayed.
- SSH listener on the Windows host, limited to the Mac
