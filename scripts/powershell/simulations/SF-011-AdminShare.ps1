# REQUIRES WINDOWS VALIDATION
# Purpose: Map \\DC01\C$ with the current logon, then leave removal to cleanup.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+. The current user must be allowed
#           to open the C$ admin share. sf-test-alice is a standard user and
#           is expected to be denied. This script does not put a password on
#           the command line.
# Status: NOT TESTED
# Atomic: technique T1021.002. Test number VERIFY. No Atomic body is downloaded.
# Expected events: 5140 or 5145 for C$, and 4624 type 3
# Expected rules: 100510 and 100512
# net use cannot bind. Expect ipAddress 10.10.10.20.

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
$result = Invoke-LabNetUse -Share 'C$' -Authentication CurrentSession -WhatIf:$WhatIfPreference
if (-not $WhatIfPreference -and $result.ExitCode -ne 0) {
    throw "net use \\DC01\C$ failed ($($result.ExitCode)). The current user could not open the admin share."
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-011' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @($result.RecordedCommand) -ExpectedRuleIds @('100510', '100512') -CleanupStatus 'pending' -Notes 'Expect source 10.10.10.20. IPC$ is 100511 and is not this test. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-011-AdminShare-Cleanup.ps1 -IUnderstandLabOnly'
