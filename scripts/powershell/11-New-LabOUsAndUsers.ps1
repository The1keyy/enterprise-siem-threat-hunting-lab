# REQUIRES WINDOWS VALIDATION
# Purpose: Create lab OUs, three standard users, and sf-test-admin in the Lab Admins group.
#          sf-test-admin is not added to Domain Admins. Passwords are prompted.
# Run on: DC01
# Requires: Administrator, PowerShell 5.1+, sentinelforge.lab
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogDir = 'C:\SentinelForge\logs'
$LogFile = Join-Path $LogDir '11-New-LabOUsAndUsers.log'
$Domain = 'sentinelforge.lab'
$OuNames = @('Lab Users', 'Lab Admins', 'Lab Workstations', 'Lab Servers')
$StandardUsers = @('sf-test-alice', 'sf-test-bob', 'sf-test-carol')

function Write-LabLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $Message
    if (Test-Path -LiteralPath $LogDir) {
        Add-Content -LiteralPath $LogFile -Value $line -Encoding utf8
    }
    Write-Output $line
}

if (-not (Test-Path -LiteralPath $LogDir)) {
    if ($PSCmdlet.ShouldProcess($LogDir, 'Create log directory')) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if (-not $computer.PartOfDomain -or $computer.Domain -ne $Domain) {
    throw "DC01 is not in $Domain."
}
Import-Module ActiveDirectory
$domainDn = (Get-ADDomain).DistinguishedName

if ($WhatIfPreference) {
    Write-LabLog 'VERIFY SKIP ou-users WhatIf would create Lab OUs, sf-test-alice, sf-test-bob, sf-test-carol, and sf-test-admin'
    exit 0
}

foreach ($ouName in $OuNames) {
    $existingOu = Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -SearchBase $domainDn -ErrorAction SilentlyContinue
    if ($existingOu) {
        continue
    }
    if ($PSCmdlet.ShouldProcess($ouName, 'New-ADOrganizationalUnit')) {
        New-ADOrganizationalUnit -Name $ouName -Path $domainDn -ProtectedFromAccidentalDeletion $true
    }
}

function New-LabAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Sam,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $found = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue
    if ($found) {
        return
    }
    $password = Read-Host -AsSecureString -Prompt "Password for $Sam (not written to the log)"
    if ($password.Length -lt 1) {
        throw "Password for $Sam was empty."
    }
    if ($PSCmdlet.ShouldProcess($Sam, 'New-ADUser')) {
        New-ADUser -Name $Sam -SamAccountName $Sam -UserPrincipalName "$Sam@$Domain" -AccountPassword $password -Enabled $true -PasswordNeverExpires $true -Path $Path
    }
}

$usersOu = "OU=Lab Users,$domainDn"
foreach ($sam in $StandardUsers) {
    New-LabAccount -Sam $sam -Path $usersOu
}
New-LabAccount -Sam 'sf-test-admin' -Path $usersOu

$group = Get-ADGroup -Filter "Name -eq 'Lab Admins'" -ErrorAction SilentlyContinue
if (-not $group) {
    if ($PSCmdlet.ShouldProcess('Lab Admins', 'New-ADGroup')) {
        New-ADGroup -Name 'Lab Admins' -SamAccountName 'LabAdmins' -GroupScope Global -GroupCategory Security -Path "OU=Lab Admins,$domainDn"
    }
}
$members = @(Get-ADGroupMember -Identity 'Lab Admins' -ErrorAction SilentlyContinue | ForEach-Object { $_.SamAccountName })
if ($members -notcontains 'sf-test-admin') {
    if ($PSCmdlet.ShouldProcess('sf-test-admin', 'Add-ADGroupMember Lab Admins')) {
        Add-ADGroupMember -Identity 'Lab Admins' -Members 'sf-test-admin'
    }
}

$missing = @()
foreach ($sam in @($StandardUsers + 'sf-test-admin')) {
    $found = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
    if (-not $found) {
        $missing += $sam
    }
}
$adminGroups = @(Get-ADPrincipalGroupMembership -Identity 'sf-test-admin' | ForEach-Object { $_.Name })
if ($missing.Count -gt 0) {
    Write-LabLog "VERIFY FAIL accounts missing $($missing -join ',')"
    throw 'VERIFY FAIL accounts'
}
if ($adminGroups -contains 'Domain Admins') {
    Write-LabLog 'VERIFY FAIL sf-test-admin is in Domain Admins'
    throw 'VERIFY FAIL Domain Admins'
}
if ($adminGroups -notcontains 'Lab Admins') {
    Write-LabLog 'VERIFY FAIL sf-test-admin is not in Lab Admins'
    throw 'VERIFY FAIL Lab Admins'
}
Write-LabLog 'VERIFY PASS ou-users Lab OUs, standard users, and sf-test-admin in Lab Admins only'
