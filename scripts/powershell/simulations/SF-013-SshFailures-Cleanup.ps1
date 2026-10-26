# REQUIRES WINDOWS VALIDATION
# Purpose: Reset faillock or pam_tally2 for sf-test-alice only if that PAM
#          module is referenced under /etc/pam.d. Then remove .200.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+, Windows OpenSSH Client
# Status: NOT TESTED
# A reset that needs root is reported as manual. This script does not use sudo
# and does not send a root password.

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

$cleanup = 'not-enabled'
if ($WhatIfPreference) {
    $cleanup = 'whatif'
}
else {
    Add-LabAttackerAddress
    $secret = Read-Host -AsSecureString -Prompt 'UBU01 password for sf-test-alice (not stored)'
    if ($secret.Length -lt 1) {
        throw 'Password was empty.'
    }
    try {
        $inspect = Invoke-LabOpenSsh -Purpose FaillockInspect -Secret $secret
        if ($inspect.Text -match 'LOCKOUT_TOOL_NOT_ENABLED') {
            $cleanup = 'not-enabled'
            Write-Output 'faillock and pam_tally are not enabled. No reset.'
        }
        elseif ($inspect.Text -match 'FAILLOCK_PRESENT') {
            $reset = Invoke-LabOpenSsh -Purpose FaillockReset -Secret $secret
            if ($reset.Text -match 'RESET_DONE') {
                $cleanup = 'reset'
            }
            else {
                $cleanup = 'manual'
                Write-Output $reset.Text
                Write-Output 'On UBU01 as root, if faillock is enabled: faillock --user sf-test-alice --reset'
            }
        }
        elseif ($inspect.Text -match 'PAM_TALLY2_PRESENT') {
            $reset = Invoke-LabOpenSsh -Purpose PamTallyReset -Secret $secret
            if ($reset.Text -match 'RESET_DONE') {
                $cleanup = 'reset'
            }
            else {
                $cleanup = 'manual'
                Write-Output $reset.Text
                Write-Output 'On UBU01 as root, if pam_tally2 is enabled: pam_tally2 --user sf-test-alice --reset'
            }
        }
        else {
            $cleanup = 'manual'
            Write-Output $inspect.Text
        }
    }
    finally {
        $secret = $null
    }
}
Remove-LabAttackerAddress -WhatIf:$WhatIfPreference

$recordPath = Write-LabRunRecord -DetectionId 'SF-013' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('ssh FaillockInspect', 'ssh reset only if enabled', 'Remove-NetIPAddress 10.10.10.200') -ExpectedRuleIds @('100701', '100702') -CleanupStatus $cleanup -Notes 'No reset when the PAM module is absent.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
