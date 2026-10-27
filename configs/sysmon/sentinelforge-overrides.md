# SentinelForge Sysmon overrides

> REQUIRES WINDOWS VALIDATION
> Run on: both (DC01 and WS01)
> Status: SYNTAX VALID after the Mac XML parse and pytest. Not a lab result.

The merged file is `sysmonconfig-sentinelforge.xml`. It is the pinned upstream file plus two `RuleGroup` elements inserted immediately before `</EventFiltering>`. Upstream include and exclude groups are unchanged.

Sysmon event 1 records `CommandLine` whenever that process create is logged. There is no separate command-line switch in schema 4.91. The Security 4688 command-line registry value is a different setting, in the audit script.

An include group adds events. It does not delete an upstream include. The pytest fails if a `ProcessCreate` or `NetworkConnect` exclude names the same image or port.

## `sentinelforge-process` / `ProcessCreate` include

| Line in the group | What it logs | Why |
|---|---|---|
| `Image` `powershell.exe` | Every process whose image name is `powershell.exe` | SF-005. Upstream logs this via `OriginalFileName`, not via a bare `Image` match. |
| `Image` `pwsh.exe` | Every `pwsh.exe` process create | SF-005. Upstream only includes `pwsh.exe` inside a `Clear-EventLog` rule, so a normal `pwsh` start would be dropped by the include filter. |
| `OriginalFileName` `pwsh.exe` | A renamed binary whose original name is still `pwsh.exe` | Same SF-005 gap. |
| `Image` `wsmprovhost.exe` | Every WinRM host process create | SF-012 rule 100520. Upstream matches `OriginalFileName` only. |
| `Image` `schtasks.exe` | Every `schtasks.exe` start, with its command line | Included so the command line is recorded. Upstream includes `schtasks.exe` only when the command line contains `/create` or `/change`. No current rule alerts on it. |
| `Image` `sc.exe` | Every `sc.exe` start, with its command line | Included so the command line is recorded. Upstream includes `sc.exe` only for some service-create command lines. No current rule alerts on it. |

## `sentinelforge-network` / `NetworkConnect` include

| Line in the group | What it logs | Why |
|---|---|---|
| `Image` `powershell.exe` | TCP or UDP from `powershell.exe` | SF-006 rule 100221. Upstream already includes this image. The line is repeated so the requirement does not depend on that other group. |
| `Image` `pwsh.exe` | Connections from `pwsh.exe` | SF-006. Upstream's shell group includes `powershell.exe` and does not include `pwsh.exe`. |
| `DestinationPort` `5985` | Any process connecting to TCP/UDP 5985 | SF-012 rule 100521. Upstream already has this port. The line is repeated for the same reason. |

The upstream `NetworkConnect` filter is an include list. A destination that is not on that list is not logged. Port 5985 and these two images have to be on the list or SF-006 and SF-012 stay blind.
