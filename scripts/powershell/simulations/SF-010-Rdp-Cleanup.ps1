# REQUIRES WINDOWS VALIDATION
# Purpose: Remind the operator to sign out of the RDP session. Does not log
#          off an arbitrary session.
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
Write-Output 'Sign out of the RDP window to DC01. This script does not call logoff.'
Remove-LabAttackerAddress -WhatIf:$WhatIfPreference
$recordPath = Write-LabRunRecord -DetectionId 'SF-010' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('manual sign-out of the RDP session') -ExpectedRuleIds @('100500') -CleanupStatus 'manual-sign-out' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
