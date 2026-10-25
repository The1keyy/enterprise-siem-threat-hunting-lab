# scripts/

| Folder | Contents | Runs on |
|---|---|---|
| `powershell/` | DC01/WS01 setup scripts | Windows lab: **REQUIRES WINDOWS VALIDATION** |
| `powershell/simulations/` | Lab-only attack simulations + cleanup scripts | Windows lab only |
| `bash/` | UBU01/WAZUH01 setup scripts | Ubuntu lab VMs |
| `validation/` | Repo checks, logtest runner, detection validator | Mac + CI |

All scripts are written and linted on the Mac (PSScriptAnalyzer via `pwsh`, `shellcheck`).
