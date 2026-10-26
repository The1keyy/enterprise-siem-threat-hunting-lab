# REQUIRES WINDOWS VALIDATION
# Purpose: Six failed logons from one host, two each for alice, bob, and carol.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# Atomic: technique T1110.003. Test number VERIFY. No Atomic body is downloaded.
# Expected events: 4625
# Expected rules: 100110
# The rule is six failures from one IP, not six distinct accounts. Only four
# sf-test accounts exist. Two failures each keeps every account under six, so
# 100100 (same account, level 11) should not win. Distinct users are Step 14.
# Source: net use cannot bind. Expect ipAddress 10.10.10.20.

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
foreach ($account in @('sf-test-alice', 'sf-test-bob', 'sf-test-carol')) {
    foreach ($attempt in 1..2) {
        $result = Invoke-LabNetUse -Share 'IPC$' -Account $account -Authentication WrongMarker -WhatIf:$WhatIfPreference
        $commands += $result.RecordedCommand
        if (-not $WhatIfPreference -and $result.Text -match 'System error 53|System error 67|network path was not found') {
            throw "DC01 was not reached for $account. This is not a logon failure."
        }
    }
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-002' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands $commands -ExpectedRuleIds @('100110') -CleanupStatus 'pending' -Notes 'Two failures each for sf-test-alice, sf-test-bob, and sf-test-carol. Expect ipAddress 10.10.10.20. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-002-PasswordSpray-Cleanup.ps1 -IUnderstandLabOnly'
