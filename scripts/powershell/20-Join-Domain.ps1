# REQUIRES WINDOWS VALIDATION
# Purpose: Join WS01 to sentinelforge.lab. The join credential is prompted.
#          sf-test-admin is not a Domain Admin. The account you type must be allowed to join a computer.
#          The script reboots when the join is started. Snapshot first.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogDir = 'C:\SentinelForge\logs'
$LogFile = Join-Path $LogDir '20-Join-Domain.log'
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
if ($active -ne 'WS01') {
    throw "Run this on WS01 after the rename reboot. Active name is $active."
}
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if ($computer.PartOfDomain -and $computer.Domain -eq $Domain) {
    Write-LabLog "VERIFY PASS domain $Domain"
    exit 0
}
if ($WhatIfPreference) {
    Write-LabLog "VERIFY SKIP domain WhatIf would join $Domain and reboot"
    exit 0
}

Write-LabLog 'Snapshot WS01 now if you have not. A successful join reboots.'
$credential = Get-Credential -Message "Account that may join WS01 to $Domain"
if ($PSCmdlet.ShouldProcess($Domain, 'Add-Computer and reboot')) {
    Add-Computer -DomainName $Domain -Credential $credential -Force
    Restart-Computer -Force
}
Write-LabLog 'If WS01 is still up, reboot it before telemetry.'
