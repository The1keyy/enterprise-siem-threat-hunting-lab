# REQUIRES WINDOWS VALIDATION
# Purpose: Run the Step 12A audit, PowerShell logging, and Sysmon scripts, in that order.
#          Sysmon refuses to install until SYSMON_ZIP_SHA256.txt has a real hash.
# Run on: both
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogDir = 'C:\SentinelForge\logs'
$LogFile = Join-Path $LogDir '30-Apply-Telemetry.log'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Steps = @(
    (Join-Path $Root 'configs\windows\audit-policy\apply-audit-policy.ps1'),
    (Join-Path $Root 'configs\windows\powershell-logging\enable-ps-logging.ps1'),
    (Join-Path $Root 'configs\sysmon\install-sysmon.ps1')
)

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

foreach ($step in $Steps) {
    if (-not (Test-Path -LiteralPath $step)) {
        throw "Missing $step"
    }
    Write-LabLog "RUN $step"
    if ($WhatIfPreference) {
        & $step -WhatIf
    }
    else {
        & $step
    }
}
if ($WhatIfPreference) {
    Write-LabLog 'VERIFY SKIP telemetry WhatIf'
    exit 0
}
Write-LabLog 'VERIFY PASS telemetry audit, PowerShell logging, and Sysmon scripts returned'
