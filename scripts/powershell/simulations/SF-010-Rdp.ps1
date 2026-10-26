# REQUIRES WINDOWS VALIDATION
# Purpose: Semi-manual RDP. Prints the mstsc steps. -LaunchClient only opens
#          the client. It does not type a password or click through a prompt.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# Atomic: technique T1021.001. Test number VERIFY. No Atomic body is downloaded.
# Expected events: 4624 logon type 10
# Expected rules: 100500. 100501 when the account is sf-test-admin. 100502 when
#                 the target computer is DC01.
# mstsc cannot bind to 10.10.10.200. Expect ipAddress 10.10.10.20.

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$IUnderstandLabOnly,
    [string]$SnapshotText,
    [switch]$LaunchClient
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SentinelForge.LabGuard.psm1') -Force

$started = [datetime]::UtcNow
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01')

Write-Output '1. Snapshot WS01 and DC01 if you have not already.'
Write-Output '2. On WS01, the Computer field is DC01.sentinelforge.lab.'
Write-Output '3. Click Connect. Accept the certificate only when the name is DC01.sentinelforge.lab.'
Write-Output '4. Sign in as SENTINELFORGE\sf-test-admin for rule 100501. Any other sf-test user is the 100500 case. The target DC01 is rule 100502.'
Write-Output '5. When the desktop appears, sign out. Do not leave the session open.'
Write-Output 'Source IP: mstsc cannot bind to 10.10.10.200. Expect 4624 ipAddress 10.10.10.20.'

$commands = @('manual mstsc /v:DC01.sentinelforge.lab')
if ($LaunchClient -and $PSCmdlet.ShouldProcess('DC01.sentinelforge.lab', 'Start mstsc')) {
    $mstsc = Join-Path $env:SystemRoot 'System32\mstsc.exe'
    Start-Process -FilePath $mstsc -ArgumentList '/v:DC01.sentinelforge.lab'
    $commands = @('mstsc.exe /v:DC01.sentinelforge.lab')
    Write-Output 'mstsc is open. Finish the steps above, then sign out.'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-010' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands $commands -ExpectedRuleIds @('100500', '100501', '100502') -CleanupStatus 'manual-sign-out' -Notes 'Sign out of the RDP window. Expect source 10.10.10.20. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-010-Rdp-Cleanup.ps1 -IUnderstandLabOnly'
