# configs/windows/

> REQUIRES WINDOWS VALIDATION
> Run on: both, except the GPO notes which are applied from DC01
> Status: SYNTAX VALID after PSScriptAnalyzer reported no errors. Not a lab result.

## What it does

Turns on the advanced audit subcategories and PowerShell logging in `docs/TELEMETRY_MATRIX.md`, and lists the event channels the Wazuh agent snippet collects.

## Where it goes

| Path | Host | Apply |
|---|---|---|
| `audit-policy/apply-audit-policy.ps1` | DC01 and WS01, elevated | Local `auditpol`. Domain-wide steps are `audit-policy/GPO-NOTES.md`. |
| `powershell-logging/enable-ps-logging.ps1` | DC01 and WS01, elevated | Registry policy keys. Transcription is set to off. |
| `channels.md` | DC01 and WS01 | Notes only. 12B writes the agent config. |

## How to verify

On the Mac, PSScriptAnalyzer and the PowerShell parser. On the host, after a snapshot: `auditpol /get /category:*`, and a 4104 event after a local `powershell -Command` that is not an attack. That host check is not done.
