# REQUIRES WINDOWS VALIDATION
# Purpose: Six failed logons for one account, sf-test-alice. Telemetry only.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# Atomic: T1110.001 Test #1 (SMB IPC$ against one account). The Atomic password
#         file is not used and is not downloaded.
# Expected events: 4625
# Expected rules: 100100
# Source: net use cannot bind. Expect ipAddress 10.10.10.20. 10.10.10.200 is
#         added and removed by cleanup, and is not the SMB source.

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
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01')
Add-LabAttackerAddress -WhatIf:$WhatIfPreference

$commands = @()
foreach ($attempt in 1..6) {
    $result = Invoke-LabNetUse -Share 'IPC$' -Account 'sf-test-alice' -Authentication WrongMarker -WhatIf:$WhatIfPreference
    $commands += $result.RecordedCommand
    if (-not $WhatIfPreference -and $result.Text -match 'System error 53|System error 67|network path was not found') {
        throw "DC01 was not reached on attempt $attempt. This is not a logon failure."
    }
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-001' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands $commands -ExpectedRuleIds @('100100') -CleanupStatus 'pending' -Notes 'Expect 4625 ipAddress 10.10.10.20. Six failures of one account. 100110 may also match the same IP; level 11 is 100100. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-001-FailedLogon-Cleanup.ps1 -IUnderstandLabOnly'
