# detections/wazuh/rules/

Custom Wazuh rules (XML). They are deployed to `/var/ossec/etc/rules/` on WAZUH01.

## Rule ID ranges (100000–109999 only)

| Range | Category |
|---|---|
| 100100 | Authentication |
| 100200 | PowerShell |
| 100300 | Accounts / groups |
| 100400 | Persistence |
| 100500 | Lateral movement |
| 100600 | Credential access |
| 100700 | Linux |
| 100800 | Defense evasion |
| 100900 | Network |
| 101000 | Correlation |

**Status:** `sentinelforge_100700_linux.xml` (SF-013, SF-014) and `sentinelforge_100100_auth.xml` (SF-001, SF-002, SF-003). Windows rules are `SYNTAX VALID` only.
