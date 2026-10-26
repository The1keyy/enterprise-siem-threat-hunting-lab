# Windows event channels for the Wazuh agent

> REQUIRES WINDOWS VALIDATION
> Run on: both
> Status: SYNTAX VALID as documentation. The agent entries are `configs/wazuh/agent-windows/ossec.conf.snippet`.

`docs/TELEMETRY_MATRIX.md` is the source. 12B collects exactly these channels.

| Channel | Enable first? | Used by |
|---|---|---|
| Security | No. It is on. `apply-audit-policy.ps1` sets the subcategories and the 1 GB maximum. | SF-001, SF-002, SF-003, SF-007, SF-008, SF-009, SF-010, SF-011 |
| System | No. It is on. No current rule reads it. It is in this list so 12B does not invent a different set. | none |
| Microsoft-Windows-Sysmon/Operational | Yes. The channel is created by `configs/sysmon/install-sysmon.ps1`. | SF-005, SF-006, SF-012 |
| Microsoft-Windows-PowerShell/Operational | The channel is usually present. 4104 is not written until `enable-ps-logging.ps1` turns on Script Block Logging. | SF-004, SF-006 |
| Microsoft-Windows-WinRM/Operational | Yes, when `wevtutil gl` shows it disabled. No event ID is assigned here. | SF-012, collect only |

On DC01 and WS01, as Administrator:

```text
wevtutil gl Microsoft-Windows-WinRM/Operational
wevtutil sl Microsoft-Windows-WinRM/Operational /e:true
```

Do not copy a WinRM event ID from a blog into a rule. A rule waits until a lab event shows the ID.
