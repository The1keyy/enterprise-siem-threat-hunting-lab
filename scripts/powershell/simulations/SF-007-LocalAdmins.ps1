# REQUIRES WINDOWS VALIDATION
# Purpose: Add sf-test-bob to the local Administrators group on WS01.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# Atomic: technique T1098. Test number VERIFY. No Atomic body is downloaded.
# Expected events: 4732 for targetSid S-1-5-32-544
# Expected rules: 100300

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
if ($present) {
    Write-Output 'PASS sf-test-bob is already in local Administrators'
}
elseif ($PSCmdlet.ShouldProcess($member, 'Add-LocalGroupMember')) {
    Add-LocalGroupMember -Group 'Administrators' -Member $member
    Write-Output 'PASS added sf-test-bob'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-007' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('Add-LocalGroupMember Administrators SENTINELFORGE\sf-test-bob') -ExpectedRuleIds @('100300') -CleanupStatus 'pending' -Notes 'Run the cleanup now. Do not leave sf-test-bob in Administrators. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-007-LocalAdmins-Cleanup.ps1 -IUnderstandLabOnly'
