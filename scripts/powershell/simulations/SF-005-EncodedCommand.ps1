# REQUIRES WINDOWS VALIDATION
# Purpose: powershell.exe -EncodedCommand of Write-Output "sentinelforge-lab".
#          The token is Unicode base64 and is at least 20 characters.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+, Sysmon process creation
# Status: NOT TESTED
# Atomic: T1059.001 Test #15 is the -EncodedCommand shape. That test needs
#         AtomicTestHarnesses, which is not installed and not downloaded.
# Expected events: Sysmon 1
# Expected rules: 100210

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$IUnderstandLabOnly,
    [string]$SnapshotText
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SentinelForge.LabGuard.psm1') -Force

$started = [datetime]::UtcNow
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01', 'DC01')

$commandText = 'Write-Output "sentinelforge-lab"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($commandText)
$token = [Convert]::ToBase64String($bytes)
if ($token.Length -lt 20) {
    throw "Encoded token is $($token.Length) characters. The rule needs at least 20."
}
$powershellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $powershellExe)) {
    throw "powershell.exe was not found at $powershellExe."
}
if ($PSCmdlet.ShouldProcess('powershell.exe', 'EncodedCommand of Write-Output')) {
    & $powershellExe -NoProfile -NonInteractive -EncodedCommand $token
    if ($LASTEXITCODE -ne 0) {
        throw "Encoded command exited $LASTEXITCODE."
    }
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-005' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('powershell.exe -NoProfile -NonInteractive -EncodedCommand <unicode base64 of Write-Output sentinelforge-lab>') -ExpectedRuleIds @('100210') -CleanupStatus 'nothing-to-remove' -Notes "Token length $($token.Length). The child process exits on its own. REQUIRES WINDOWS VALIDATION." -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-005-EncodedCommand-Cleanup.ps1 -IUnderstandLabOnly'
