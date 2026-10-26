# REQUIRES WINDOWS VALIDATION
# Purpose: Invoke-Command to DC01 and run hostname.exe. Uses the current logon.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+. WinRM must already be enabled on
#           DC01. This script does not call Enable-PSRemoting.
# Status: NOT TESTED
# Atomic: technique T1021.006. Test number VERIFY. No Atomic body is downloaded.
# Expected events: Sysmon 1 for wsmprovhost.exe, Sysmon 3 destination port 5985
# Expected rules: 100520 and 100521
# Invoke-Command cannot bind a source address. Expect 10.10.10.20.
# No WinRM Operational event ID is claimed. VERIFY that ID in the lab.

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
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01')
$remoteComputer = 'DC01.sentinelforge.lab'
Write-Output 'Prerequisite: WinRM is already enabled on DC01. This script does not enable it.'

if ($PSCmdlet.ShouldProcess($remoteComputer, 'Invoke-Command hostname')) {
    $remoteName = Invoke-Command -ComputerName $remoteComputer -ScriptBlock {
        & 'C:\Windows\System32\hostname.exe'
    }
    Write-Output "REMOTE $remoteName"
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-012' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('Invoke-Command DC01.sentinelforge.lab hostname.exe') -ExpectedRuleIds @('100520', '100521') -CleanupStatus 'session-ended' -Notes 'The remoting session ends when Invoke-Command returns. Expect source 10.10.10.20. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-012-WinRm-Cleanup.ps1 -IUnderstandLabOnly'
