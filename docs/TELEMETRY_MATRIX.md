# Telemetry matrix

> REQUIRES WINDOWS VALIDATION for every Windows row. Linux rows are lab checks on UBU01.
> This file is the source for Steps 12A, 12B, and 12C. 12B writes the agent snippets. 12C is not started.

Rows are SF-001 through SF-014 only. A setting is listed because a detection reads that event, or because Step 12A requires the command-line field on Security 4688. Subcategories that no row uses are not set: Special Logon, Other Object Access Events, and Security System Extension.

| ID | Host(s) | Channel or log | Event IDs | Audit subcategory or Sysmon event | Config file | Agent localfile |
|---|---|---|---|---|---|---|
| SF-001 | DC01, WS01 | Security | 4625 (and 4624 is the same policy) | Logon, Success and Failure. Not Account Logon. | `configs/windows/audit-policy/apply-audit-policy.ps1` | `configs/wazuh/agent-windows/ossec.conf.snippet` location `Security` |
| SF-002 | DC01, WS01 | Security | 4625 | Logon, Success and Failure | same audit script | same Windows snippet, `Security` |
| SF-003 | DC01, WS01 | Security | 4624 | Logon, Success and Failure | same audit script | same Windows snippet, `Security` |
| SF-004 | WS01. The rule also matches DC01 if that host sends the event. | `Microsoft-Windows-PowerShell/Operational` | 4104 | Script Block Logging. Not an audit subcategory. | `configs/windows/powershell-logging/enable-ps-logging.ps1` | same Windows snippet. Query keeps 4104 only. |
| SF-005 | WS01. The same Sysmon file is installed on DC01 for SF-012. | `Microsoft-Windows-Sysmon/Operational` | 1 | Sysmon process create for `powershell.exe` and `pwsh.exe`, including CommandLine. Not Security 4688. | `configs/sysmon/sysmonconfig-sentinelforge.xml` | same Windows snippet. No query, so other Sysmon IDs from the pinned config are kept. |
| SF-006 | WS01 | PowerShell Operational, and Sysmon Operational | 4104, and Sysmon 3 | Script Block Logging, plus Sysmon network connect for `powershell.exe` and `pwsh.exe` | both the PowerShell script and the Sysmon file | same Windows snippet, both channels |
| SF-007 | WS01. A 4732 on DC01 matches the same rule. | Security | 4732 | Security Group Management, Success | audit script | same Windows snippet, `Security` |
| SF-008 | DC01 | Security | 4728, 4756 | Security Group Management, Success | audit script | same Windows snippet, `Security` |
| SF-009 | DC01, WS01 | Security | 4720 | User Account Management, Success | audit script | same Windows snippet, `Security` |
| SF-010 | DC01, WS01 | Security | 4624 type 10 | Logon, Success | audit script | same Windows snippet, `Security` |
| SF-011 | DC01, WS01 | Security | 5140, 5145, 4624 type 3 | File Share Success, Detailed File Share Success, and Logon Success | audit script | same Windows snippet, `Security`. The query includes 5145. The stock agent query excludes it. |
| SF-012 | DC01, WS01 | Sysmon Operational. WinRM Operational is collected and has no event ID yet. | Sysmon 1 (`wsmprovhost.exe`), Sysmon 3 destination port 5985. WinRM event ID is not invented. | Sysmon process create and network connect | Sysmon file. Channel enable notes: `configs/windows/channels.md` | same Windows snippet: Sysmon Operational and `Microsoft-Windows-WinRM/Operational` |
| SF-013 | UBU01 | syslog file `/var/log/auth.log`. 12C installs rsyslog so this file exists. The journald agent input is not used. | none. `sshd` lines: `invalid user`, `Failed password` | none | `configs/linux` rsyslog check is 12C. auditd rules are `configs/linux/auditd/sentinelforge.rules`. | `configs/wazuh/agent-linux/ossec.conf.snippet` location `/var/log/auth.log` |
| SF-014 | UBU01 | same sshd log as SF-013 | none. `Accepted password`, `Accepted publickey` | none | same as SF-013 | same Linux snippet, `/var/log/auth.log` |

## Command line on Security 4688

Not an SF row. SF-005 does not alert on 4688. Step 12A still turns on Process Creation, Success, and `ProcessCreationIncludeCmdLine_Enabled`, so a lab 4688 can carry a command line. The script is `configs/windows/audit-policy/apply-audit-policy.ps1`.

## Process images in the Sysmon file that no current rule alerts on

`schtasks.exe` and `sc.exe` process creation is in the merged Sysmon config because Step 12A requires those images. No SF-001–SF-014 rule matches them.

## Linux files the agent reads

Decision for Ubuntu 24.04: SF-013 and SF-014 stay on `/var/log/auth.log` because the logtest cases are syslog lines from that path. 12C installs rsyslog and checks the file is being written. The agent does not use `log_format` `journald`. That alternative is in `configs/wazuh/agent-linux/README.md`. It is not proven on UBU01 yet.

| File | Why |
|---|---|
| `/var/log/auth.log` | SF-013 and SF-014 |
| `/var/log/syslog` | Host syslog beside auth.log. No current SF rule. |
| `/var/log/audit/audit.log` | auditd records from `configs/linux/auditd/sentinelforge.rules`. No current SF rule. |

## Agent channels

12B collects these in `configs/wazuh/agent-windows/ossec.conf.snippet`.

| Channel | Used by | Enable first? |
|---|---|---|
| Security | SF-001–SF-003, SF-007–SF-011 | On by default. The audit script raises the max size to 1 GB. |
| System | No current rule. Listed because the agent channel set for 12B includes it. | On by default. |
| `Microsoft-Windows-Sysmon/Operational` | SF-005, SF-006, SF-012 | Created when Sysmon is installed. |
| `Microsoft-Windows-PowerShell/Operational` | SF-004, SF-006 | 4104 is written only after Script Block Logging. |
| `Microsoft-Windows-WinRM/Operational` | SF-012, collect only | Often disabled. `channels.md` has the `wevtutil` command. No event ID until a lab event shows one. |
