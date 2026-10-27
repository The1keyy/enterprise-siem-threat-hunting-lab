# Windows lab handoff

Start here on the lab PC. Nothing below has run on a VM. Nothing is `LAB VALIDATED`. Snapshot before every script.

## Counts (2026-10-27, Mac)

| Item | Count |
|---|---|
| Detections | 14. `SYNTAX VALID` 12 (SF-001–SF-012). `LOGTEST VALID` 2 (SF-013, SF-014). `LAB VALIDATED` 0 |
| Hunts | 10 (HUNT-001–HUNT-010), all `NOT TESTED` |
| Simulations | 14 plus `Invoke-AttackStory.ps1`, all `NOT TESTED`, 0 run |
| CI workflows | 5: `app`, `scripts`, `detections`, `logtest`, `secrets` |

Attack story from the correlation model, not a lab measurement: `INC-a69e4a81`, subtotal 135, DC01 sets 1.7, final **230, critical**.

## Run order

1. Lab build — `docs/runbooks/01-lab-build.md` (DC01, WS01, UBU01, then WAZUH01).
2. Telemetry — Sysmon, audit policy, PowerShell script block, channels in `docs/TELEMETRY_MATRIX.md`.
3. Wazuh config — `docs/runbooks/03-wazuh-config.md`, then `scripts/bash/wazuh01-checks.sh`.
4. Connect SentinelForge — SSH tunnel below, then `.env`, then live mode.
5. Simulations — `docs/runbooks/04-simulations.md`. Snapshot first. Isolated `10.10.10.0/24` only.

## When each VERIFY is checked

**Before the first VM.** Windows Server eval 2022 vs 2025. Windows 11 eval length. Ubuntu 24.04 on the Wazuh 4.14 supported list. Suricata version if SURI01 is built. Workstation Pro 26.0.1 license terms and the VMnet / LAN-segment name. Wazuh 4.14.9 hardware minimums, indexer heap file, and the real `-Xms`/`-Xmx` names. Dashboard, API, and indexer ports.

**While installing agents.** Sysmon zip hash and `Sysmon64.exe` version (config targets 15.21). Wazuh MSI hash. Apt revision `4.14.9-1` and `WAZUH_AGENT_NAME` on Ubuntu. `wazuh-agent.exe` path under `C:\Program Files (x86)\ossec-agent`.

**While configuring WAZUH01.** `logall_json`. Filebeat `archives.enabled`. `PUT _plugins/_ism/policies/`. `rule_dir etc/rules` and the `wazuh` owner. Path of `root-ca.pem`. Index patterns `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*`. Time field `timestamp`. Whether terms need `.keyword`. `date_histogram` `fixed_interval`. `hits.total.value`. `GET /_cluster/health` and `GET /_nodes/stats/fs`. API `POST /security/user/authenticate`, JWT in `data.token`, pagination `limit`/`offset`.

**When SentinelForge first polls.** `rule.groups` contains `sentinelforge`. Archive 4625 paths: `data.win.system.eventID`, `data.win.eventdata.ipAddress`, `data.win.eventdata.targetUserName` (eventID may be a string or a number). SF-002 timeframe is 120 seconds in `risk_config.yml`. SID paths: `data.win.system.security.userID`, `targetUserSid`, `subjectUserSid`, Sysmon `user`. Hunt `query_string` leading `*`. `/var/log/auth.log` on UBU01. WinRM Operational event ID. A real 4624 type 10, 5140 or 5145, and Sysmon 1 `wsmprovhost.exe`.

## Hashes to record

Both files are still placeholders. The MSI URL returned HTTP 200 on 2026-10-26. The file was not downloaded.

- Sysmon zip → `configs/sysmon/SYSMON_ZIP_SHA256.txt` (replace `<SYSMON_ZIP_SHA256>`)
- Wazuh agent MSI → `scripts/powershell/WAZUH_AGENT_MSI_SHA256.txt` (replace `<WAZUH_AGENT_MSI_SHA256>`)
- URL: `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi`

## ISOs, hardware, snapshots

ISOs: Windows Server 2022 or 2025 Evaluation (DC01), Windows 11 Enterprise Evaluation (WS01), Ubuntu Server 24.04 LTS (UBU01, WAZUH01, optional SURI01).

Host: i7-13700F, 32 GB, 1 TB SSD, Windows 10 Home, VMware Workstation Pro 26.0.1. Guests: WAZUH01 8 GB, DC01 4 GB, WS01 4 GB, UBU01 2 GB. SURI01 off. Gateway `10.10.10.1`. DC01 `.10`, WS01 `.20`, UBU01 `.30`, WAZUH01 `.40`, SURI01 `.50`. Domain `sentinelforge.lab`.

Snapshots, in order, from `docs/runbooks/01-lab-build.md`: clean install; after the rename reboot; after the forest (DC01); before user creation; before telemetry; after telemetry and before the agent. WS01 also snapshots after domain join. UBU01 snapshots the clean Ubuntu install. Snapshot again before every simulation.

## Mac to WAZUH01

Host-only `10.10.10.0/24` exists only on the Windows PC. The Mac cannot reach `.40` directly. SSH to the Windows host and forward:

| Mac | Remote |
|---|---|
| `127.0.0.1:55000` | `10.10.10.40:55000` |
| `127.0.0.1:9200` | `10.10.10.40:9200` |

Copy `.env.example` to `.env`. Set `DATA_MODE=live`, `WAZUH_API_URL=https://127.0.0.1:55000`, `WAZUH_INDEXER_URL=https://127.0.0.1:9200`, the read-only users, `WAZUH_CA_BUNDLE`, `CONSOLE_ADMIN_PASSWORD_HASH`, and `SESSION_SECRET`. Leave `WAZUH_TLS_INSECURE=false`. `CORRELATION_POLL_SECONDS=60` and `CORRELATION_POLL_ENABLED=true`. Frontend: `VITE_DATA_MODE=live` and `VITE_API_URL=http://localhost:8000`.

## Live mode

`make dev-backend` and `make dev-frontend`. The poller runs only when `DATA_MODE=live`. If the indexer is down it logs the error, `GET /api/correlation/status` shows it, and the checkpoint stays. It does not load fixtures. `POST /api/correlation/run` (logged in) runs one cycle. Set `CORRELATION_POLL_SECONDS=0` to disable the background task.
