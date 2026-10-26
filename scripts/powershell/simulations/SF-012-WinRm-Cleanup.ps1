# REQUIRES WINDOWS VALIDATION
# Purpose: SF-012 does not leave a remoting session. This records that cleanup.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED

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
Write-Output 'PASS Invoke-Command already returned. No session to close.'
$recordPath = Write-LabRunRecord -DetectionId 'SF-012' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('no remoting session left') -ExpectedRuleIds @('100520', '100521') -CleanupStatus 'session-ended' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
