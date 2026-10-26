# configs/sysmon/

> REQUIRES WINDOWS VALIDATION
> Run on: both (DC01 and WS01)
> Status: SYNTAX VALID for the XML and the install script's parse. The binary is not installed on this Mac.

## What it does

Installs Microsoft Sysmon with a merged configuration so SF-005, SF-006, and SF-012 have process and network events.

## Base config

Chosen base: **sysmon-modular** (Olaf Hartong), not SwiftOnSecurity.

| | sysmon-modular | SwiftOnSecurity/sysmon-config |
|---|---|---|
| License | MIT. Copy: `upstream/LICENSE.md` | Creative Commons Attribution 4.0. Usable with credit. The last schema bump in that repo is schema 4.5 (2021). |
| Pinned file | `upstream/sysmonconfig-15.21.xml` | not used |

- Source: https://github.com/olafhartong/sysmon-modular
- Release tag: `configs-a45dedb13a43`
- Commit: `a45dedb13a43c0d8ea1fc6b580a0ac396fa74457`
- Asset: `sysmonconfig-15.21.xml`
- SHA256: `64bec37ba849c5f2934a55d2a29e7ddfae46a30d56f7f2908d1f8a454898797e` (matches that release's `SHA256SUMS`). `.gitattributes` marks this file `-text -eol` so Git does not rewrite its line endings.
- `schemaversion="4.91"`
- Upstream says this file targets Sysmon **15.21**. `docs/VERSIONS.md` does not pin a Sysmon binary. **VERIFY** the lab `Sysmon64.exe` is 15.21 before install. A different build can reject schema 4.91.

SwiftOnSecurity's config is the project this one credits. It was not copied, because its schema is older than the events this lab needs.

## Where it goes

`sysmonconfig-sentinelforge.xml` is the file `install-sysmon.ps1` passes to `Sysmon64.exe` on DC01 and WS01. The overrides are documented in `sentinelforge-overrides.md`.

## How to apply

1. On the lab host, download `https://download.sysinternals.com/files/Sysmon.zip`. **VERIFY** that URL that day.
2. `Get-FileHash -Algorithm SHA256` and replace `<SYSMON_ZIP_SHA256>` in `SYSMON_ZIP_SHA256.txt`. The script stops if the placeholder is still there, or if the zip hash differs.
3. Snapshot the VM.
4. From an elevated PowerShell 5.1 prompt: `.\install-sysmon.ps1`
5. A second run uses `Sysmon64.exe -accepteula -c` instead of `-i`.

## How to verify

`sysmon -c` style check is on the host: `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1` after a `powershell.exe` start. That has not been run. Status stays SYNTAX VALID.

On the Mac: `pytest tests/configs/test_sysmon_config.py` parses the merged file.
