# REQUIRES WINDOWS VALIDATION
# Purpose: Remove sf-test-bob from local Administrators. Idempotent.
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

$member = 'SENTINELFORGE\sf-test-bob'
$present = $false
foreach ($entry in @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)) {
    if ($entry.Name -like '*\sf-test-bob') {
        $present = $true
    }
}
$cleanup = 'already-absent'
if ($present -and $PSCmdlet.ShouldProcess($member, 'Remove-LocalGroupMember')) {
    Remove-LocalGroupMember -Group 'Administrators' -Member $member
    $cleanup = 'removed'
}
elseif (-not $present) {
    Write-Output 'PASS sf-test-bob is not in local Administrators'
}
else {
    $cleanup = 'whatif'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-007' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('Remove-LocalGroupMember Administrators SENTINELFORGE\sf-test-bob') -ExpectedRuleIds @('100300') -CleanupStatus $cleanup -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
