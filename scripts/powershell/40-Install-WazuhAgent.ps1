# REQUIRES WINDOWS VALIDATION
# Purpose: Install Wazuh agent 4.14.9, check the MSI hash, and merge the 12B snippet.
#          The MSI URL returned HTTP 200 on 2026-10-26. VERIFY it again on install day.
# Run on: both
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ManagerIp = '10.10.10.40'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogDir = 'C:\SentinelForge\logs'
$LogFile = Join-Path $LogDir '40-Install-WazuhAgent.log'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Snippet = Join-Path $Root 'configs\wazuh\agent-windows\ossec.conf.snippet'
$HashFile = Join-Path $PSScriptRoot 'WAZUH_AGENT_MSI_SHA256.txt'
$DownloadUrl = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi'
$Cache = 'C:\SentinelForge\cache'
$Msi = Join-Path $Cache 'wazuh-agent-4.14.9-1.msi'
$AgentConfig = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$ServiceName = 'WazuhSvc'

function Write-LabLog {
    param([Parameter(Mandatory = $true)][string]$Message)
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $Message
    if (Test-Path -LiteralPath $LogDir) {
        Add-Content -LiteralPath $LogFile -Value $line -Encoding utf8
    }
    Write-Output $line
}

function Get-ExpectedHash {
    $expected = $null
    foreach ($line in Get-Content -LiteralPath $HashFile) {
        $text = $line.Trim()
        if ($text.Length -eq 0 -or $text.StartsWith('#')) {
            continue
        }
        $expected = $text
        break
    }
    if ($null -eq $expected -or $expected -eq '<WAZUH_AGENT_MSI_SHA256>') {
        throw "Write the lab MSI SHA256 into $HashFile before installing."
    }
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'WAZUH_AGENT_MSI_SHA256.txt must contain one 64-character hex digest.'
    }
    return $expected
}

function Merge-OssecSnippet {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$AgentPath,
        [Parameter(Mandatory = $true)][string]$SnippetPath,
        [Parameter(Mandatory = $true)][string]$Address
    )
    $agent = New-Object System.Xml.XmlDocument
    $agent.PreserveWhitespace = $true
    $agent.Load($AgentPath)
    $snippet = New-Object System.Xml.XmlDocument
    $snippet.Load($SnippetPath)
    $node = $agent.SelectSingleNode('//client/server/address')
    if (-not $node) {
        throw "No client/server/address in $AgentPath"
    }
    $config = $agent.SelectSingleNode('//ossec_config')
    if (-not $config) {
        throw "No ossec_config in $AgentPath"
    }
    $changed = $false
    if ($node.InnerText -ne $Address) {
        $node.InnerText = $Address
        $changed = $true
    }
    foreach ($localfile in $snippet.SelectNodes('//localfile')) {
        $locationNode = $localfile.SelectSingleNode('location')
        if (-not $locationNode) {
            throw 'Snippet localfile has no location'
        }
        $location = $locationNode.InnerText
        $existing = $null
        foreach ($have in $agent.SelectNodes('//localfile')) {
            $haveLocation = $have.SelectSingleNode('location')
            if ($haveLocation -and $haveLocation.InnerText -eq $location) {
                $existing = $have
                break
            }
        }
        if ($existing -and $existing.InnerXml -eq $localfile.InnerXml) {
            continue
        }
        $imported = $agent.ImportNode($localfile, $true)
        if ($existing) {
            $null = $existing.ParentNode.ReplaceChild($imported, $existing)
        }
        else {
            $null = $config.AppendChild($imported)
        }
        $changed = $true
    }
    if (-not $changed) {
        return
    }
    if ($PSCmdlet.ShouldProcess($AgentPath, 'Save merged ossec.conf')) {
        $backup = '{0}.bak-{1}' -f $AgentPath, (Get-Date -Format 'yyyyMMddTHHmmss')
        Copy-Item -LiteralPath $AgentPath -Destination $backup
        $agent.Save($AgentPath)
        Write-LabLog "Backed up ossec.conf to $backup"
    }
}

if (-not (Test-Path -LiteralPath $LogDir)) {
    if ($PSCmdlet.ShouldProcess($LogDir, 'Create log directory')) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
}
if (-not (Test-Path -LiteralPath $Snippet)) {
    throw "Missing $Snippet"
}
$active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
if ($active -ne 'DC01' -and $active -ne 'WS01') {
    throw "Active computer name is $active. Reboot after rename before installing the agent."
}

if ($WhatIfPreference) {
    Write-LabLog "VERIFY SKIP agent WhatIf would install $DownloadUrl as $active manager $ManagerIp if the MSI hash is recorded"
    exit 0
}
$expectedHash = Get-ExpectedHash

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    if (-not (Test-Path -LiteralPath $Cache)) {
        New-Item -ItemType Directory -Path $Cache -Force | Out-Null
    }
    $download = $true
    if (Test-Path -LiteralPath $Msi) {
        $cached = (Get-FileHash -Algorithm SHA256 -LiteralPath $Msi).Hash
        if ($cached.ToLowerInvariant() -eq $expectedHash.ToLowerInvariant()) {
            $download = $false
        }
    }
    if ($download -and $PSCmdlet.ShouldProcess($DownloadUrl, 'Download Wazuh agent MSI')) {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $Msi
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Msi).Hash
    if ($actual.ToLowerInvariant() -ne $expectedHash.ToLowerInvariant()) {
        Remove-Item -LiteralPath $Msi -Force
        throw "MSI SHA256 is $actual, expected $expectedHash. Do not install."
    }
    if ($PSCmdlet.ShouldProcess($Msi, "msiexec WAZUH_MANAGER=$ManagerIp WAZUH_AGENT_NAME=$active")) {
        $install = Start-Process -FilePath msiexec.exe -ArgumentList @(
            '/i', $Msi, '/qn',
            "WAZUH_MANAGER=`"$ManagerIp`"",
            "WAZUH_AGENT_NAME=`"$active`""
        ) -Wait -PassThru
        if ($install.ExitCode -eq 3010) {
            Write-LabLog 'VERIFY FAIL agent msiexec 3010. Reboot, then run this script again to merge and start.'
            throw 'VERIFY FAIL reboot required'
        }
        if ($install.ExitCode -ne 0) {
            throw "msiexec exited $($install.ExitCode)"
        }
    }
}

if (-not (Test-Path -LiteralPath $AgentConfig)) {
    throw "Missing $AgentConfig"
}
Merge-OssecSnippet -AgentPath $AgentConfig -SnippetPath $Snippet -Address $ManagerIp
if ($PSCmdlet.ShouldProcess($ServiceName, 'Start-Service')) {
    Set-Service -Name $ServiceName -StartupType Automatic
    Restart-Service -Name $ServiceName -Force
}
$service = Get-Service -Name $ServiceName
if ($service.Status -ne 'Running') {
    Write-LabLog "VERIFY FAIL agent status $($service.Status)"
    throw 'VERIFY FAIL agent'
}
$address = (Select-Xml -LiteralPath $AgentConfig -XPath '//client/server/address').Node.InnerText
if ($address -ne $ManagerIp) {
    Write-LabLog "VERIFY FAIL agent address $address"
    throw 'VERIFY FAIL agent address'
}
Write-LabLog "VERIFY PASS agent $ServiceName running name $active manager $ManagerIp"
