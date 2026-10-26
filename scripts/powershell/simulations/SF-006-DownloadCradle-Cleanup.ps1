# REQUIRES WINDOWS VALIDATION
# Purpose: Stop the lab HTTP server if it is still up, then remove .200.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+, Windows OpenSSH Client
# Status: NOT TESTED
# Resets nothing on UBU01 except that one python process.

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

$cleanup = 'removed'
if ($WhatIfPreference) {
    $cleanup = 'whatif'
}
else {
    $present = Get-NetIPAddress -IPAddress '10.10.10.200' -ErrorAction SilentlyContinue
    if ($present) {
        $secret = Read-Host -AsSecureString -Prompt 'UBU01 password for sf-test-alice (not stored)'
        if ($secret.Length -lt 1) {
            throw 'Password was empty.'
        }
        try {
            $stopped = Invoke-LabOpenSsh -Purpose HttpStop -Secret $secret
            if ($stopped.Text -notmatch 'STOPPED') {
                $cleanup = 'http-stop-failed'
                Write-Output $stopped.Text
            }
        }
        finally {
            $secret = $null
        }
    }
    else {
        Write-Output '10.10.10.200 is absent, so this cleanup will not open SSH. If the HTTP server is still up, stop it on UBU01.'
        $cleanup = 'address-already-absent'
    }
}
Remove-LabAttackerAddress -WhatIf:$WhatIfPreference

$recordPath = Write-LabRunRecord -DetectionId 'SF-006' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('ssh HttpStop', 'Remove-NetIPAddress 10.10.10.200') -ExpectedRuleIds @('100220', '100221') -CleanupStatus $cleanup -Notes 'On UBU01, if needed: kill the pid in /tmp/sentinelforge-lab-http/server.pid' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
