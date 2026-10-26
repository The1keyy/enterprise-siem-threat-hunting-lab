# REQUIRES WINDOWS VALIDATION
# Purpose: Six failed SSH password attempts from 10.10.10.200 to UBU01.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+, Windows OpenSSH Client
# Status: NOT TESTED
# Client: Windows OpenSSH ssh.exe. It is a Windows feature, so there is no
#         third-party binary and no hash to invent. plink -pw puts the
#         password on the command line and cannot set BindAddress. Python is
#         not installed on WS01. ssh.exe -o BindAddress=10.10.10.200 is the
#         source. SSH_ASKPASS keeps the marker off the command line.
#         VERIFY BindAddress and SSH_ASKPASS_REQUIRE on this WS01 build.
#         If BindAddress fails, the script stops. It does not use 10.10.10.20.
# Atomic: technique T1110.001 against SSH. Test number VERIFY. No download.
# Expected events: sshd invalid-user or Failed password in /var/log/auth.log
# Expected rules: 100701 or 100702
# ubu01-setup.sh does not create sf-test-alice. Create that local user first.
# This script does not edit sshd_config. Password authentication must already
# be enabled. VERIFY that on UBU01.

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
    $result = Invoke-LabOpenSsh -Purpose AuthFailure -WhatIf:$WhatIfPreference
    $commands += $result.RecordedCommand
    if ($WhatIfPreference) { continue }
    if ($result.ExitCode -eq 0) {
        throw "Attempt $attempt authenticated. The wrong marker must not succeed."
    }
    if ($result.Text -match 'Connection refused|No route to host|Connection timed out|Could not resolve') {
        throw "UBU01 was not reached on attempt $attempt. $($result.Text)"
    }
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-013' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands $commands -ExpectedRuleIds @('100701', '100702') -CleanupStatus 'pending' -Notes 'Source is BindAddress 10.10.10.200. Six failures, no success. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-013-SshFailures-Cleanup.ps1 -IUnderstandLabOnly'
