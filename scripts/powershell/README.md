# scripts/powershell/

> REQUIRES WINDOWS VALIDATION
> Run on: DC01, WS01, or both, as each script header says
> Status: setup scripts are SYNTAX VALID after PSScriptAnalyzer. Simulations under `simulations/` stay `NOT TESTED`. None of these scripts have run on a Windows host.

| Script | Run on | What it does |
|---|---|---|
| `01-Set-StaticIP.ps1` | DC01 or WS01 | Lab address from the architecture plan. DNS `10.10.10.10`. |
| `02-Rename-Computer.ps1` | DC01 or WS01 | Rename. Does not reboot. |
| `10-Install-ADDS-Forest.ps1` | DC01 | `sentinelforge.lab`. Prompts for the DSRM password. Reboots. |
| `11-New-LabOUsAndUsers.ps1` | DC01 | Lab OUs and `sf-test-*` users. `sf-test-admin` is not a Domain Admin. |
| `20-Join-Domain.ps1` | WS01 | Prompts for a join account. Reboots. |
| `30-Apply-Telemetry.ps1` | both | Calls the audit, PowerShell logging, and Sysmon scripts. |
| `40-Install-WazuhAgent.ps1` | both | Wazuh agent 4.14.9. Refuses a placeholder MSI hash. Merges the Windows agent snippet. |
| `99-Get-LabStatus.ps1` | both | Read-only report. Writes only its log file. |
| `simulations/` | WS01 or DC01 | Lab-only telemetry. Status `NOT TESTED`. See `docs/runbooks/04-simulations.md`. |

Order and snapshot points: `docs/runbooks/01-lab-build.md`. Do not run a simulation from the build runbook.

Logs go to `C:\SentinelForge\logs\`. Passwords are prompted and are not written there. `-WhatIf` skips changes.

`WAZUH_AGENT_MSI_SHA256.txt` is still the placeholder `<WAZUH_AGENT_MSI_SHA256>`.
