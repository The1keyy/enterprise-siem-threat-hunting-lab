# REQUIRES WINDOWS VALIDATION
# Purpose: Delete sf-test-temp if it exists. Idempotent.
# Run on: DC01
# Requires: Administrator, PowerShell 5.1+, ActiveDirectory module
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
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('DC01')
Import-Module ActiveDirectory

$existing = Get-ADUser -Filter "SamAccountName -eq 'sf-test-temp'" -ErrorAction SilentlyContinue
$cleanup = 'already-absent'
if ($existing) {
    if ($PSCmdlet.ShouldProcess('sf-test-temp', 'Remove-ADUser')) {
        Remove-ADUser -Identity 'sf-test-temp' -Confirm:$false
        $cleanup = 'removed'
        Write-Output 'PASS deleted sf-test-temp'
    }
    else {
        $cleanup = 'whatif'
    }
}
else {
    Write-Output 'PASS sf-test-temp is already absent'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-009' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('Remove-ADUser sf-test-temp') -ExpectedRuleIds @('100320') -CleanupStatus $cleanup -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
