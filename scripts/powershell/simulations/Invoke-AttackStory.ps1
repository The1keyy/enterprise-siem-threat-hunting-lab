# REQUIRES WINDOWS VALIDATION
# Purpose: One lab story. Failed logons, one success, a suspicious script
#          block, local admin add, then a remote connection to DC01.
#          Cleanup runs in finally, including after a failed stage.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# Default remote stage is the C$ map (SF-011). -RemoteStage WinRM runs SF-012
# and does not enable WinRM. Step 14 correlation is not started here.
# Expected rules for the default story: 100100, 100120, 100200, 100300, 100510.
# PauseSeconds must stay inside the 120 second window after the sixth failure
# if 100120 is going to chain. The default is 15.

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$IUnderstandLabOnly,
    [string]$SnapshotText,
    [ValidateRange(0, 90)][int]$PauseSeconds = 15,
    [ValidateSet('Share', 'WinRM')][string]$RemoteStage = 'Share'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SentinelForge.LabGuard.psm1') -Force

$started = [datetime]::UtcNow
if (-not $IUnderstandLabOnly) {
    throw 'Refusing to run: -IUnderstandLabOnly was not passed. These scripts are LAB ONLY.'
}
if ([string]::IsNullOrWhiteSpace($SnapshotText)) {
    $SnapshotText = Read-Host 'Type "I have a snapshot" to continue'
}
Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01')
if ($PauseSeconds -gt 60) {
    Write-Warning 'PauseSeconds is over 60. Rule 100120 uses a 120 second window after SF-001. Type the success password promptly.'
}

$remoteFile = 'SF-011-AdminShare.ps1'
$remoteRules = @('100510', '100512')
if ($RemoteStage -eq 'WinRM') {
    $remoteFile = 'SF-012-WinRm.ps1'
    $remoteRules = @('100520', '100521')
    Write-Output 'WinRM must already be enabled on DC01. This story does not call Enable-PSRemoting.'
}

$storyError = ''
$cleanupStatus = 'completed'
try {
    Write-Output ("{0} START SF-001-FailedLogon.ps1" -f ([datetime]::UtcNow.ToString('o')))
    if ($WhatIfPreference) {
        & (Join-Path $PSScriptRoot 'SF-001-FailedLogon.ps1') -IUnderstandLabOnly -SnapshotText $SnapshotText -WhatIf
    }
    else {
        & (Join-Path $PSScriptRoot 'SF-001-FailedLogon.ps1') -IUnderstandLabOnly -SnapshotText $SnapshotText
    }
    Write-Output ("{0} PAUSE {1}s" -f ([datetime]::UtcNow.ToString('o')), $PauseSeconds)
    if (-not $WhatIfPreference -and $PauseSeconds -gt 0) { Start-Sleep -Seconds $PauseSeconds }

    Write-Output ("{0} START SF-003-FailureThenSuccess.ps1 -SuccessOnly" -f ([datetime]::UtcNow.ToString('o')))
    if ($WhatIfPreference) {
        & (Join-Path $PSScriptRoot 'SF-003-FailureThenSuccess.ps1') -IUnderstandLabOnly -SnapshotText $SnapshotText -SuccessOnly -WhatIf
    }
    else {
        & (Join-Path $PSScriptRoot 'SF-003-FailureThenSuccess.ps1') -IUnderstandLabOnly -SnapshotText $SnapshotText -SuccessOnly
    }
    Write-Output ("{0} PAUSE {1}s" -f ([datetime]::UtcNow.ToString('o')), $PauseSeconds)
    if (-not $WhatIfPreference -and $PauseSeconds -gt 0) { Start-Sleep -Seconds $PauseSeconds }

    Write-Output ("{0} START SF-004-ScriptBlockMarkers.ps1" -f ([datetime]::UtcNow.ToString('o')))
    if ($WhatIfPreference) {
        & (Join-Path $PSScriptRoot 'SF-004-ScriptBlockMarkers.ps1') -IUnderstandLabOnly -SnapshotText $SnapshotText -WhatIf
    }
    else {
        & (Join-Path $PSScriptRoot 'SF-004-ScriptBlockMarkers.ps1') -IUnderstandLabOnly -SnapshotText $SnapshotText
    }
    Write-Output ("{0} PAUSE {1}s" -f ([datetime]::UtcNow.ToString('o')), $PauseSeconds)
    if (-not $WhatIfPreference -and $PauseSeconds -gt 0) { Start-Sleep -Seconds $PauseSeconds }

    Write-Output ("{0} START SF-007-LocalAdmins.ps1" -f ([datetime]::UtcNow.ToString('o')))
    if ($WhatIfPreference) {
        & (Join-Path $PSScriptRoot 'SF-007-LocalAdmins.ps1') -IUnderstandLabOnly -SnapshotText $SnapshotText -WhatIf
    }
    else {
        & (Join-Path $PSScriptRoot 'SF-007-LocalAdmins.ps1') -IUnderstandLabOnly -SnapshotText $SnapshotText
    }
    Write-Output ("{0} PAUSE {1}s" -f ([datetime]::UtcNow.ToString('o')), $PauseSeconds)
    if (-not $WhatIfPreference -and $PauseSeconds -gt 0) { Start-Sleep -Seconds $PauseSeconds }

    Write-Output ("{0} START $remoteFile" -f ([datetime]::UtcNow.ToString('o')))
    if ($WhatIfPreference) {
        & (Join-Path $PSScriptRoot $remoteFile) -IUnderstandLabOnly -SnapshotText $SnapshotText -WhatIf
    }
    else {
        & (Join-Path $PSScriptRoot $remoteFile) -IUnderstandLabOnly -SnapshotText $SnapshotText
    }
    Write-Output ("{0} END story stages" -f ([datetime]::UtcNow.ToString('o')))
}
catch {
    $storyError = $_.Exception.Message
    Write-Output "STAGE FAILED $storyError"
}
finally {
    $cleanupFiles = @(
        'SF-007-LocalAdmins-Cleanup.ps1',
        'SF-011-AdminShare-Cleanup.ps1',
        'SF-003-FailureThenSuccess-Cleanup.ps1',
        'SF-001-FailedLogon-Cleanup.ps1',
        'SF-004-ScriptBlockMarkers-Cleanup.ps1',
        'SF-012-WinRm-Cleanup.ps1'
    )
    foreach ($file in $cleanupFiles) {
        Write-Output ("{0} CLEANUP {1}" -f ([datetime]::UtcNow.ToString('o')), $file)
        try {
            if ($WhatIfPreference) {
                & (Join-Path $PSScriptRoot $file) -IUnderstandLabOnly -SnapshotText $SnapshotText -WhatIf
            }
            else {
                & (Join-Path $PSScriptRoot $file) -IUnderstandLabOnly -SnapshotText $SnapshotText
            }
        }
        catch {
            $cleanupStatus = 'incomplete'
            Write-Output "CLEANUP FAILED $file $($_.Exception.Message)"
        }
    }
    if ($storyError) { $cleanupStatus = 'incomplete' }
    $expected = @('100100', '100120', '100200', '100300') + $remoteRules
    $notes = 'Step 14 should merge these alerts into one incident. This script does not correlate. Default remote stage is Share (SF-011).'
    if ($storyError) { $notes = "$notes Stage error: $storyError" }
    $recordPath = Write-LabRunRecord -DetectionId 'STORY' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('SF-001', 'SF-003 success', 'SF-004', 'SF-007', $RemoteStage) -ExpectedRuleIds $expected -CleanupStatus $cleanupStatus -Notes $notes -WhatIf:$WhatIfPreference
    if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
}

if ($storyError) {
    throw "Attack story failed. Cleanup was attempted. $storyError"
}
