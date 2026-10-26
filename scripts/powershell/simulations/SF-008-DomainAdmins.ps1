# REQUIRES WINDOWS VALIDATION
# Purpose: Add sf-test-carol to Domain Admins on DC01, briefly.
# Run on: DC01
# Requires: Administrator, PowerShell 5.1+, ActiveDirectory module
# Status: NOT TESTED
# Atomic: technique T1098. Test number VERIFY. No Atomic body is downloaded.
# Expected events: 4728 for the Domain Admins RID 512
# Expected rules: 100310
# Extra confirmation is required. Run the cleanup immediately. This script
# does not remove the member; the cleanup script does.

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$IUnderstandLabOnly,
    [switch]$IUnderstandDomainAdmins,
    [string]$SnapshotText,
    [string]$DomainAdminText
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SentinelForge.LabGuard.psm1') -Force

$started = [datetime]::UtcNow
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('DC01')
if (-not $IUnderstandDomainAdmins) {
    throw 'Refusing to run: -IUnderstandDomainAdmins was not passed.'
}
if ([string]::IsNullOrWhiteSpace($DomainAdminText)) {
    $DomainAdminText = Read-Host 'Type "I will remove sf-test-carol" to continue'
}
if ($DomainAdminText -cne 'I will remove sf-test-carol') {
    throw 'Refusing to run: Domain Admins confirmation was not "I will remove sf-test-carol".'
}

Import-Module ActiveDirectory
$groups = @(Get-ADPrincipalGroupMembership -Identity 'sf-test-carol' | ForEach-Object { $_.Name })
if ($groups -contains 'Domain Admins') {
    Write-Output 'PASS sf-test-carol is already in Domain Admins. Run the cleanup.'
}
elseif ($PSCmdlet.ShouldProcess('sf-test-carol', 'Add-ADGroupMember Domain Admins')) {
    Add-ADGroupMember -Identity 'Domain Admins' -Members 'sf-test-carol'
    Write-Output 'PASS added sf-test-carol. Run the cleanup now.'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-008' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('Add-ADGroupMember Domain Admins sf-test-carol') -ExpectedRuleIds @('100310') -CleanupStatus 'pending' -Notes 'Do not leave sf-test-carol in Domain Admins. A display name without RID 512 does not fire 100310. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-008-DomainAdmins-Cleanup.ps1 -IUnderstandLabOnly'
