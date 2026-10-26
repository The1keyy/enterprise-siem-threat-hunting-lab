# REQUIRES WINDOWS VALIDATION
# Purpose: Create the sentinelforge.lab forest on DC01. The DSRM password is prompted.
#          Install-ADDSForest reboots the server. Snapshot before you run this.
# Run on: DC01
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogDir = 'C:\SentinelForge\logs'
$LogFile = Join-Path $LogDir '10-Install-ADDS-Forest.log'
$Domain = 'sentinelforge.lab'

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

$active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
if ($active -ne 'DC01') {
    throw "Run this on DC01 after the rename reboot. Active name is $active."
}

$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if ($computer.PartOfDomain -and $computer.Domain -eq $Domain) {
    Write-LabLog "VERIFY PASS forest $Domain"
    exit 0
}
if ($WhatIfPreference) {
    Write-LabLog "VERIFY SKIP forest WhatIf would install $Domain and reboot DC01"
    exit 0
}

Write-LabLog 'Snapshot DC01 now if you have not. This script reboots when the forest install finishes.'
if ($PSCmdlet.ShouldProcess('DC01', 'Install Windows feature AD-Domain-Services')) {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
}
$dsrm = Read-Host -AsSecureString -Prompt 'DSRM password (not stored in the log)'
if ($dsrm.Length -lt 1) {
    throw 'DSRM password was empty.'
}
if ($PSCmdlet.ShouldProcess($Domain, 'Install-ADDSForest and reboot')) {
    Install-ADDSForest -DomainName $Domain -DomainNetbiosName 'SENTINELFORGE' -SafeModeAdministratorPassword $dsrm -InstallDns -Force
}
Write-LabLog 'If DC01 is still up, the forest install did not reboot. Reboot before script 11.'
