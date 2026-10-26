# REQUIRES WINDOWS VALIDATION
# Purpose: Remove sf-test-carol from Domain Admins. Idempotent.
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

$groups = @(Get-ADPrincipalGroupMembership -Identity 'sf-test-carol' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
$cleanup = 'already-absent'
if ($groups -contains 'Domain Admins') {
    if ($PSCmdlet.ShouldProcess('sf-test-carol', 'Remove-ADGroupMember Domain Admins')) {
        Remove-ADGroupMember -Identity 'Domain Admins' -Members 'sf-test-carol' -Confirm:$false
        $cleanup = 'removed'
        Write-Output 'PASS removed sf-test-carol from Domain Admins'
    }
    else {
        $cleanup = 'whatif'
    }
}
else {
    Write-Output 'PASS sf-test-carol is not in Domain Admins'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-008' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('Remove-ADGroupMember Domain Admins sf-test-carol') -ExpectedRuleIds @('100310') -CleanupStatus $cleanup -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
