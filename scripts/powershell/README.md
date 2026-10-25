# scripts/powershell/

> **REQUIRES WINDOWS VALIDATION.** Everything here is written on macOS and is `NOT TESTED` until
> it runs in the lab.

These scripts set up the Windows lab:
- DC01 promotion
- test OUs/users (`sf-test-*`)
- WS01 domain join
- audit policy
- PowerShell logging
- Sysmon
- Wazuh agent

## Standards
- Idempotent
- `-WhatIf` support
- Strict mode
- No hardcoded passwords
- CRLF line endings (enforced by `.gitattributes`)

## Lint on Mac
```bash
pwsh -c "Install-Module PSScriptAnalyzer -Scope CurrentUser -Force"
pwsh -c "Invoke-ScriptAnalyzer -Path scripts/powershell -Recurse"
```

**Status:** Empty (Step 12).
