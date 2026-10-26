# configs/wazuh/

Wazuh 4.14.9 configuration snippets. Placeholders use `<WAZUH_MANAGER_IP>`. Secrets stay in `secrets/`, which is gitignored.

| Path | Purpose | Status |
|---|---|---|
| `agent-windows/ossec.conf.snippet` | Event channels from `configs/windows/channels.md` | SYNTAX VALID. REQUIRES WINDOWS VALIDATION |
| `agent-linux/ossec.conf.snippet` | auth.log, syslog, audit.log on UBU01 | SYNTAX VALID. Not installed |
| `manager/ossec.conf.snippet` | `logall_json` | SYNTAX VALID. Not applied |
| `manager/filebeat-archives.md` | Filebeat archives module and the 100 GB retention math | NOT TESTED |
| `manager/ism-wazuh-archives-7d.json` | Delete `wazuh-archives-*` after 7 days | SYNTAX VALID JSON. Not applied |
| `manager/ism-wazuh-alerts-30d.json` | Delete `wazuh-alerts-*` after 30 days | SYNTAX VALID JSON. Not applied |

Apply order: `docs/runbooks/03-wazuh-config.md`. Rule files are copied by `scripts/bash/deploy_rules.sh`.
