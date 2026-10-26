# REQUIRES WINDOWS VALIDATION
# Purpose: Delete the \\DC01\C$ mapping and remove .200.
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
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01')
Remove-LabSmbMapping -Share 'C$' -WhatIf:$WhatIfPreference
Remove-LabAttackerAddress -WhatIf:$WhatIfPreference
$recordPath = Write-LabRunRecord -DetectionId 'SF-011' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('net use \\DC01\C$ /delete', 'Remove-NetIPAddress 10.10.10.200') -ExpectedRuleIds @('100510') -CleanupStatus 'removed' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
