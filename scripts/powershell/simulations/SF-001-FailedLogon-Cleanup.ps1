# REQUIRES WINDOWS VALIDATION
# Purpose: Drop any IPC$ mapping, try to unlock sf-test-alice, remove .200.
# Run on: WS01. Unlock-ADAccount runs only when the AD module is installed.
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# This script does not reset the password. The simulation did not change it.

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
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01', 'DC01')
Remove-LabSmbMapping -Share 'IPC$' -WhatIf:$WhatIfPreference
Remove-LabAttackerAddress -WhatIf:$WhatIfPreference

$unlock = 'manual'
$module = Get-Module -ListAvailable -Name ActiveDirectory
if (-not $module) {
    Write-Output 'On DC01, if the account locked: Unlock-ADAccount -Identity sf-test-alice'
}
elseif (-not $WhatIfPreference) {
    Import-Module ActiveDirectory
    try {
        Unlock-ADAccount -Identity 'sf-test-alice' -ErrorAction Stop
        $unlock = 'unlocked'
    }
    catch {
        $unlock = 'unlock-not-confirmed'
        Write-Output "Unlock-ADAccount did not confirm: $($_.Exception.Message)"
        Write-Output 'On DC01: Unlock-ADAccount -Identity sf-test-alice'
    }
}
else {
    $unlock = 'whatif'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-001' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('net use \\DC01\IPC$ /delete', 'Remove-NetIPAddress 10.10.10.200', 'Unlock-ADAccount sf-test-alice') -ExpectedRuleIds @('100100') -CleanupStatus $unlock -Notes 'Cleanup does not reset the password.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
