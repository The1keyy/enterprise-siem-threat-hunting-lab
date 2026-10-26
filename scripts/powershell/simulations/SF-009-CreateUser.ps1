# REQUIRES WINDOWS VALIDATION
# Purpose: Create domain user sf-test-temp. The password is prompted and not stored.
# Run on: DC01
# Requires: Administrator, PowerShell 5.1+, ActiveDirectory module
# Status: NOT TESTED
# Atomic: technique T1136.001. Test number VERIFY. No Atomic body is downloaded.
# Expected events: 4720
# Expected rules: 100320
# The rule matches any 4720. The account name is not the match.

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
if ($existing) {
    throw 'sf-test-temp already exists. Run SF-009-CreateUser-Cleanup.ps1 first.'
}
$domainDn = (Get-ADDomain).DistinguishedName
$ou = Get-ADOrganizationalUnit -Filter "Name -eq 'Lab Users'" -SearchBase $domainDn -ErrorAction SilentlyContinue
if (-not $ou) {
    throw 'OU Lab Users is missing. Run 11-New-LabOUsAndUsers.ps1 first.'
}
if ($PSCmdlet.ShouldProcess('sf-test-temp', 'New-ADUser')) {
    $password = Read-Host -AsSecureString -Prompt 'Password for sf-test-temp (not stored)'
    if ($password.Length -lt 1) {
        throw 'Password was empty.'
    }
    New-ADUser -Name 'sf-test-temp' -SamAccountName 'sf-test-temp' -UserPrincipalName 'sf-test-temp@sentinelforge.lab' -AccountPassword $password -Enabled $true -PasswordNeverExpires $true -Path "OU=Lab Users,$domainDn"
    $password = $null
    Write-Output 'PASS created sf-test-temp'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-009' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('New-ADUser sf-test-temp') -ExpectedRuleIds @('100320') -CleanupStatus 'pending' -Notes 'The password is not in this record. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-009-CreateUser-Cleanup.ps1 -IUnderstandLabOnly'
