# configs/wazuh/

Wazuh 4.14.9 configuration snippets.

| Snippet | Purpose |
|---|---|
| Agent `ossec.conf` (Windows) | Collect Security, Sysmon/Operational, PowerShell/Operational channels |
| Agent `ossec.conf` (Linux) | Collect auth.log, syslog, audit.log |
| Manager | Enable archives (`logall_json`) for hunting; load custom rules/decoders |

`secrets/` (gitignored) holds the lab CA certificate locally. It is never committed.

**Status:** Empty (Step 12). Agent snippets: **REQUIRES WINDOWS VALIDATION**.
