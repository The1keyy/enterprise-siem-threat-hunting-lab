# REQUIRES WINDOWS VALIDATION
# Purpose: Give DC01 or WS01 the lab static address. DNS is 10.10.10.10.
# Run on: DC01 | WS01
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('DC01', 'WS01')]
    [string]$Hostname,
    [string]$InterfaceAlias
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Plan = @{
    DC01 = @{ Address = '10.10.10.10'; Prefix = 24; Gateway = '10.10.10.1' }
    WS01 = @{ Address = '10.10.10.20'; Prefix = 24; Gateway = '10.10.10.1' }
}
$Dns = '10.10.10.10'
$Want = $Plan[$Hostname]
$LogDir = 'C:\SentinelForge\logs'
$LogFile = Join-Path $LogDir '01-Set-StaticIP.log'

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

if (-not $InterfaceAlias) {
    $up = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface })
    if ($up.Count -ne 1) {
        $names = ($up | ForEach-Object { $_.Name }) -join ', '
        throw "Pass -InterfaceAlias. Up hardware adapters: $names"
    }
    $InterfaceAlias = $up[0].Name
}

$have = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $Want.Address -and $_.PrefixLength -eq $Want.Prefix }
$route = Get-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -eq $Want.Gateway }
$dnsNow = @(Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 |
    Select-Object -ExpandProperty ServerAddresses)
$ready = ($null -ne $have) -and ($null -ne $route) -and ($dnsNow -contains $Dns)

if ($ready) {
    Write-LabLog "VERIFY PASS static-ip $Hostname $($Want.Address) on $InterfaceAlias"
    exit 0
}
if ($WhatIfPreference) {
    Write-LabLog "VERIFY SKIP static-ip WhatIf would set $($Want.Address)/$($Want.Prefix) gateway $($Want.Gateway) dns $Dns on $InterfaceAlias"
    exit 0
}

if ($PSCmdlet.ShouldProcess($InterfaceAlias, "Set $($Want.Address) dns $Dns")) {
    Set-NetIPInterface -InterfaceAlias $InterfaceAlias -Dhcp Disabled
    Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne $Want.Address } |
        Remove-NetIPAddress -Confirm:$false
    if (-not $have) {
        New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $Want.Address -PrefixLength $Want.Prefix -DefaultGateway $Want.Gateway | Out-Null
    }
    elseif (-not $route) {
        New-NetRoute -InterfaceAlias $InterfaceAlias -DestinationPrefix '0.0.0.0/0' -NextHop $Want.Gateway | Out-Null
    }
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $Dns
}

$have = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq $Want.Address }
$dnsNow = @(Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 |
    Select-Object -ExpandProperty ServerAddresses)
if (($null -eq $have) -or ($dnsNow -notcontains $Dns)) {
    Write-LabLog "VERIFY FAIL static-ip address or DNS on $InterfaceAlias"
    throw "VERIFY FAIL static-ip"
}
Write-LabLog "VERIFY PASS static-ip $Hostname $($Want.Address) dns $Dns"
