# REQUIRES WINDOWS VALIDATION
# Purpose: Six failures for sf-test-alice, then one successful IPC$ logon.
#          -SuccessOnly skips the six failures for the attack story.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# Atomic: T1110.001 Test #1 shape, then one correct logon. T1078 on the rule.
#         No Atomic body is downloaded.
# Expected events: 4625, then 4624
# Expected rules: 100100, then 100120. A successful IPC$ map can also emit
#                 5140/5145 (100511) and a type-3 4624 (100512). Those are
#                 side effects. The mapping is deleted immediately.
# Source: net use cannot bind. The failure IP and the success IP are both
#         expected to be 10.10.10.20, which is what 100120 compares.
# The real password is typed at the net use prompt. It is not stored.

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$IUnderstandLabOnly,
    [string]$SnapshotText,
    [switch]$SuccessOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SentinelForge.LabGuard.psm1') -Force

$started = [datetime]::UtcNow
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01')
Add-LabAttackerAddress -WhatIf:$WhatIfPreference

$commands = @()
if (-not $SuccessOnly) {
    foreach ($attempt in 1..6) {
        $failed = Invoke-LabNetUse -Share 'IPC$' -Account 'sf-test-alice' -Authentication WrongMarker -WhatIf:$WhatIfPreference
        $commands += $failed.RecordedCommand
        if (-not $WhatIfPreference -and $failed.Text -match 'System error 53|System error 67|network path was not found') {
            throw "DC01 was not reached on attempt $attempt. This is not a logon failure."
        }
    }
}

Write-Output 'Type the sf-test-alice password at the net use prompt. It is not written to the run record.'
$success = Invoke-LabNetUse -Share 'IPC$' -Account 'sf-test-alice' -Authentication Prompt -WhatIf:$WhatIfPreference
$commands += $success.RecordedCommand
if (-not $WhatIfPreference -and $success.ExitCode -ne 0) {
    throw "The successful logon did not complete (exit $($success.ExitCode))."
}
Remove-LabSmbMapping -Share 'IPC$' -WhatIf:$WhatIfPreference
$commands += 'net use \\DC01\IPC$ /delete'

$recordPath = Write-LabRunRecord -DetectionId 'SF-003' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands $commands -ExpectedRuleIds @('100100', '100120') -CleanupStatus 'pending' -Notes 'Expect the same ipAddress, 10.10.10.20, on the 4625 burst and the 4624. Keep this inside 120 seconds of rule 100100. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-003-FailureThenSuccess-Cleanup.ps1 -IUnderstandLabOnly'
