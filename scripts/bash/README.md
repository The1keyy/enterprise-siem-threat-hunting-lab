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

`deploy_rules.sh` copies `detections/wazuh/rules/sentinelforge_*.xml` to `/var/ossec/etc/rules/`, runs `wazuh-analysisd -t`, and restarts `wazuh-manager` only when that test passes. It then checks the API rule count. Set `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, and `WAZUH_API_CA` on WAZUH01, or let it prompt. It does not disable TLS verification.

UBU01 setup is Step 12C and is not in this folder yet.
