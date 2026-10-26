# REQUIRES WINDOWS VALIDATION
# Purpose: SF-004 leaves no process and no file. This records that cleanup.
# Run on: WS01 or DC01
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
Write-Output 'PASS nothing to remove'
$recordPath = Write-LabRunRecord -DetectionId 'SF-004' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('no process left') -ExpectedRuleIds @('100200') -CleanupStatus 'nothing-to-remove' -Notes 'No file or process was created.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
