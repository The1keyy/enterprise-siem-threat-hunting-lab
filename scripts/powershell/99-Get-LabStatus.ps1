# REQUIRES WINDOWS VALIDATION
# Purpose: Read-only report. It does not change the host.
# Run on: both
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogDir = 'C:\SentinelForge\logs'
$LogFile = Join-Path $LogDir '99-Get-LabStatus.log'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$SysmonConfig = Join-Path $Root 'configs\sysmon\sysmonconfig-sentinelforge.xml'
$failed = $false

function Write-LabLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $Message
    if (Test-Path -LiteralPath $LogDir) {
        Add-Content -LiteralPath $LogFile -Value $line -Encoding utf8
    }
    Write-Output $line
}

function Add-Status {
    param(
        [Parameter(Mandatory = $true)][bool]$Ok,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Detail
    )
    $state = 'FAIL'
    if ($Ok) {
        $state = 'PASS'
    }
    else {
        $script:failed = $true
    }
    Write-LabLog "VERIFY $state $Name $Detail"
}

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' } | ForEach-Object { $_.IPAddress })
Add-Status -Ok ($active.Length -gt 0) -Name 'hostname' -Detail $active
Add-Status -Ok ($ips.Count -gt 0) -Name 'ipv4' -Detail ($ips -join ',')
Add-Status -Ok ($computer.Domain.Length -gt 0) -Name 'domain' -Detail ("partOfDomain=$($computer.PartOfDomain) domain=$($computer.Domain)")

$subcategories = @(
    @{ Name = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'User Account Management'; Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Process Creation'; Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'File Share'; Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}' },
    @{ Name = 'Detailed File Share'; Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}' }
)
foreach ($item in $subcategories) {
    $output = & auditpol.exe /get "/subcategory:$($item.Guid)"
    $text = $output -join ' '
    $ok = $text -match 'Success'
    Add-Status -Ok $ok -Name "audit $($item.Name)" -Detail $text
}

$sysmon = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
$sysmonDetail = 'service missing'
$sysmonOk = $false
if ($sysmon) {
    $sysmonOk = $sysmon.Status -eq 'Running'
    $sysmonDetail = $sysmon.Status.ToString()
}
if (Test-Path -LiteralPath $SysmonConfig) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SysmonConfig).Hash
    $sysmonDetail = "$sysmonDetail repo-config=$hash"
}
Add-Status -Ok $sysmonOk -Name 'sysmon' -Detail $sysmonDetail

function Get-PolicyDword {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $property = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if (-not $property) {
        return $null
    }
    return $property.$Name
}
$policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$scriptBlock = Get-PolicyDword -Path (Join-Path $policy 'ScriptBlockLogging') -Name 'EnableScriptBlockLogging'
$module = Get-PolicyDword -Path (Join-Path $policy 'ModuleLogging') -Name 'EnableModuleLogging'
$transcript = Get-PolicyDword -Path (Join-Path $policy 'Transcription') -Name 'EnableTranscripting'
Add-Status -Ok ($scriptBlock -eq 1 -and $module -eq 1 -and $transcript -eq 0) -Name 'ps-logging' -Detail "scriptblock=$scriptBlock module=$module transcript=$transcript"

$agent = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
$agentDetail = 'service missing'
$agentOk = $false
if ($agent) {
    $agentOk = $agent.Status -eq 'Running'
    $agentDetail = $agent.Status.ToString()
    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $display = $null
    foreach ($root in $uninstallRoots) {
        foreach ($item in @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
            $nameProp = $item.PSObject.Properties['DisplayName']
            $versionProp = $item.PSObject.Properties['DisplayVersion']
            if ($nameProp -and $versionProp -and $nameProp.Value -like 'Wazuh Agent*') {
                $display = $versionProp.Value
                break
            }
        }
        if ($display) {
            break
        }
    }
    if ($display) {
        $agentDetail = "$agentDetail version=$display"
    }
}
Add-Status -Ok $agentOk -Name 'wazuh-agent' -Detail $agentDetail

$channels = @(
    'Security',
    'System',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-WinRM/Operational'
)
foreach ($channel in $channels) {
    try {
        $newest = Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop
        Add-Status -Ok $true -Name "last-event $channel" -Detail ("id={0} time={1}" -f $newest.Id, $newest.TimeCreated.ToString('o'))
    }
    catch {
        Add-Status -Ok $false -Name "last-event $channel" -Detail $_.Exception.Message
    }
}

if ($failed) {
    throw 'VERIFY FAIL one or more status checks'
}
Write-LabLog 'VERIFY PASS lab-status'
