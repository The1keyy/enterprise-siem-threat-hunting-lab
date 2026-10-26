# scripts/bash/

Setup and deploy scripts for Ubuntu lab VMs (UBU01, WAZUH01, optional SURI01).

## Standards
- `#!/usr/bin/env bash`
- `set -euo pipefail`
- Must pass `shellcheck`
- LF line endings

| Script | Run on | Status |
|---|---|---|
| `deploy_rules.sh` | WAZUH01, or the Mac with `--ssh user@host` | SYNTAX VALID after shellcheck. Not run on a manager |
| `ubu01-setup.sh` | UBU01 | SYNTAX VALID after shellcheck. Not run on UBU01 |
| `wazuh01-checks.sh` | WAZUH01 | SYNTAX VALID after shellcheck. Read-only. Not run on WAZUH01 |

`deploy_rules.sh` copies `detections/wazuh/rules/sentinelforge_*.xml` to `/var/ossec/etc/rules/`, runs `wazuh-analysisd -t`, and restarts `wazuh-manager` only when that test passes. It then checks the API rule count. Set `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, and `WAZUH_API_CA` on WAZUH01, or let it prompt. It does not disable TLS verification.

`ubu01-setup.sh` sets `10.10.10.30`, installs rsyslog so `/var/log/auth.log` exists, loads the auditd rules, and installs Wazuh agent `4.14.9-1`. The apt revision is **VERIFY** if the repository does not have that version. Logs go to `/var/log/sentinelforge/`.

`wazuh01-checks.sh` prints service, disk, agent, archives, and rule-count checks. It does not restart anything.
