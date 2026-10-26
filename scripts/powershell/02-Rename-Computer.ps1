# REQUIRES WINDOWS VALIDATION
# Purpose: Rename this VM to DC01 or WS01. A reboot is required before the name is active.
#          This script does not reboot. Snapshot, then reboot, before the next script.
# Run on: DC01 | WS01
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('DC01', 'WS01')]
    [string]$Hostname
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogDir = 'C:\SentinelForge\logs'
$LogFile = Join-Path $LogDir '02-Rename-Computer.log'

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
$pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName

if ($active -eq $Hostname) {
    Write-LabLog "VERIFY PASS hostname active $active"
    exit 0
}
if ($pending -eq $Hostname) {
    Write-LabLog "VERIFY PASS hostname pending $pending active $active. Reboot before the next script."
    exit 0
}
if ($WhatIfPreference) {
    Write-LabLog "VERIFY SKIP rename WhatIf would rename $active to $Hostname and would not reboot"
    exit 0
}
if ($PSCmdlet.ShouldProcess($active, "Rename-Computer $Hostname")) {
    Rename-Computer -NewName $Hostname -Force
}
$pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
if ($pending -ne $Hostname) {
    Write-LabLog "VERIFY FAIL hostname pending $pending wanted $Hostname"
    throw 'VERIFY FAIL hostname'
}
Write-LabLog "VERIFY PASS hostname pending $pending. Reboot before the next script. This script did not reboot."
