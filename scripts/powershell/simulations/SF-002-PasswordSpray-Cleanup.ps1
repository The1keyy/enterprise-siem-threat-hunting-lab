# REQUIRES WINDOWS VALIDATION
# Purpose: Drop IPC$, try to unlock alice, bob, and carol, remove .200.
# Run on: WS01. Unlock runs only when the AD module is installed.
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# This script does not reset passwords.

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
    Write-Output 'On DC01, if an account locked: Unlock-ADAccount -Identity sf-test-alice'
    Write-Output 'Repeat for sf-test-bob and sf-test-carol.'
}
elseif (-not $WhatIfPreference) {
    Import-Module ActiveDirectory
    $unlock = 'unlocked'
    foreach ($account in @('sf-test-alice', 'sf-test-bob', 'sf-test-carol')) {
        try {
            Unlock-ADAccount -Identity $account -ErrorAction Stop
        }
        catch {
            $unlock = 'unlock-not-confirmed'
            Write-Output "Unlock-ADAccount $account did not confirm: $($_.Exception.Message)"
        }
    }
}
else {
    $unlock = 'whatif'
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-002' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('net use \\DC01\IPC$ /delete', 'Unlock-ADAccount sf-test-alice', 'Unlock-ADAccount sf-test-bob', 'Unlock-ADAccount sf-test-carol', 'Remove-NetIPAddress 10.10.10.200') -ExpectedRuleIds @('100110') -CleanupStatus $unlock -Notes 'Cleanup does not reset passwords.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
