# REQUIRES WINDOWS VALIDATION
# Purpose: Install or update Sysmon 64-bit with sysmonconfig-sentinelforge.xml.
#          The zip hash must be recorded in SYSMON_ZIP_SHA256.txt during lab setup.
# Run on: both
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# VERIFY: this URL is the Sysinternals download page's current zip. Confirm it
# on the day you install, then record that file's SHA256 in SYSMON_ZIP_SHA256.txt.
$DownloadUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$Here = Split-Path -Parent $PSCommandPath
$HashFile = Join-Path $Here 'SYSMON_ZIP_SHA256.txt'
$ConfigPath = Join-Path $Here 'sysmonconfig-sentinelforge.xml'

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Missing $ConfigPath"
}

$expected = $null
foreach ($line in Get-Content -LiteralPath $HashFile) {
    $text = $line.Trim()
    if ($text.Length -eq 0 -or $text.StartsWith('#')) {
        continue
    }
    $expected = $text
    break
}
if ($null -eq $expected -or $expected -eq '<SYSMON_ZIP_SHA256>') {
    throw "Write the lab Sysmon.zip SHA256 into $HashFile before installing. Get-FileHash -Algorithm SHA256."
}
if ($expected -notmatch '^[0-9a-fA-F]{64}$') {
    throw "SYSMON_ZIP_SHA256.txt must contain one 64-character hex digest."
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) 'sentinelforge-sysmon'
$zipPath = Join-Path $work 'Sysmon.zip'
if ($PSCmdlet.ShouldProcess($DownloadUrl, 'Download Sysmon.zip and install')) {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
    New-Item -ItemType Directory -Path $work | Out-Null
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
    if ($actual.ToLowerInvariant() -ne $expected.ToLowerInvariant()) {
        throw "Sysmon.zip SHA256 is $actual, expected $expected. Do not install."
    }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $work -Force
    $binary = Join-Path $work 'Sysmon64.exe'
    if (-not (Test-Path -LiteralPath $binary)) {
        throw "Sysmon64.exe was not in the zip."
    }
    $service = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        & $binary -accepteula -i $ConfigPath
    }
    else {
        & $binary -accepteula -c $ConfigPath
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon64 exited $LASTEXITCODE"
    }
}
