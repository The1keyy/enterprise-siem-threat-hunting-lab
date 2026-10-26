# REQUIRES WINDOWS VALIDATION
# Purpose: Six failed SSH attempts, then one successful login, from 10.10.10.200.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+, Windows OpenSSH Client
# Status: NOT TESTED
# Same client choice as SF-013. The success password is prompted and is not
# put on the ssh.exe command line. VERIFY BindAddress and SSH_ASKPASS_REQUIRE.
# Atomic: technique T1078 after T1110.001. No Atomic body is downloaded.
# Expected events: six sshd failures, then Accepted password
# Expected rules: 100701 or 100702, then 100710 or 100711
# Keep the success inside 120 seconds of the SF-013 alert. Same source IP.
# ubu01-setup.sh does not create sf-test-alice.

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
    $failed = Invoke-LabOpenSsh -Purpose AuthFailure -WhatIf:$WhatIfPreference
    $commands += $failed.RecordedCommand
    if ($WhatIfPreference) { continue }
    if ($failed.ExitCode -eq 0) {
        throw "Attempt $attempt authenticated. The wrong marker must not succeed."
    }
    if ($failed.Text -match 'Connection refused|No route to host|Connection timed out|Could not resolve') {
        throw "UBU01 was not reached on attempt $attempt. $($failed.Text)"
    }
}

$secret = $null
if ($WhatIfPreference) {
    $success = Invoke-LabOpenSsh -Purpose AuthSuccess -WhatIf
    $commands += $success.RecordedCommand
}
else {
    $secret = Read-Host -AsSecureString -Prompt 'UBU01 password for sf-test-alice (not stored)'
    if ($secret.Length -lt 1) {
        throw 'Password was empty.'
    }
    try {
        $success = Invoke-LabOpenSsh -Purpose AuthSuccess -Secret $secret
        $commands += $success.RecordedCommand
        if ($success.ExitCode -ne 0) {
            throw "The successful SSH login did not complete (exit $($success.ExitCode))."
        }
    }
    finally {
        $secret = $null
    }
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-014' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands $commands -ExpectedRuleIds @('100701', '100702', '100710', '100711') -CleanupStatus 'pending' -Notes 'Source is BindAddress 10.10.10.200 for the failures and the success. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-014-SshSuccess-Cleanup.ps1 -IUnderstandLabOnly'
