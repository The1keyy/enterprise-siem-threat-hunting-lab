# REQUIRES WINDOWS VALIDATION
# Purpose: Download one harmless text file from the lab HTTP server on UBU01.
#          The script starts and stops that server. It listens on 10.10.10.30
#          only, port 8080.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+, Windows OpenSSH Client, Script
#           Block Logging, Sysmon network connect
# Status: NOT TESTED
# Atomic: T1105 Test #29 is the Invoke-WebRequest shape. The Atomic URL is
#         not used. No Atomic body is downloaded.
# Expected events: 4104, and Sysmon 3 from powershell.exe
# Expected rules: 100220 and 100221
# SSH to UBU01 binds to 10.10.10.200. Invoke-WebRequest in Windows PowerShell
# 5.1 cannot bind a source address. Expect Sysmon source 10.10.10.20.
# VERIFY: ssh.exe BindAddress and SSH_ASKPASS_REQUIRE on this WS01 build.
# ubu01-setup.sh does not create sf-test-alice. Create that local user first.
# python3 must already be on UBU01. This script does not install it.

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
$cleanup = 'pending'
$secret = $null
try {
    if ($WhatIfPreference) {
        $commands = @(
            'ssh.exe -o BindAddress=10.10.10.200 sf-test-alice@10.10.10.30 HttpStart',
            'Invoke-WebRequest http://10.10.10.30:8080/sentinelforge-lab.txt',
            'ssh.exe -o BindAddress=10.10.10.200 sf-test-alice@10.10.10.30 HttpStop'
        )
        $cleanup = 'whatif'
    }
    else {
        $secret = Read-Host -AsSecureString -Prompt 'UBU01 password for sf-test-alice (not stored)'
        if ($secret.Length -lt 1) {
            throw 'Password was empty.'
        }
        $server = Invoke-LabOpenSsh -Purpose HttpStart -Secret $secret
        $commands += $server.RecordedCommand
        if ($server.ExitCode -ne 0 -or $server.Text -notmatch 'STARTED|ALREADY') {
            throw "Lab HTTP server did not start. $($server.Text)"
        }
        $uri = [Uri]'http://10.10.10.30:8080/sentinelforge-lab.txt'
        if ($uri.Scheme -ne 'http' -or $uri.Host -ne '10.10.10.30' -or $uri.Port -ne 8080) {
            throw 'Refusing a URL that is not the lab HTTP server.'
        }
        $destination = Join-Path $env:TEMP 'sentinelforge-lab.txt'
        Invoke-WebRequest -Uri $uri.AbsoluteUri -UseBasicParsing -OutFile $destination
        $body = Get-Content -LiteralPath $destination -Raw
        Remove-Item -LiteralPath $destination -Force
        if ($body -notmatch 'sentinelforge-lab') {
            throw 'The downloaded file was not the lab marker.'
        }
        $commands += 'Invoke-WebRequest http://10.10.10.30:8080/sentinelforge-lab.txt'
        $cleanup = 'server-stopped'
    }
}
finally {
    if ($secret) {
        try {
            Invoke-LabOpenSsh -Purpose HttpStop -Secret $secret | Out-Null
        }
        catch {
            $cleanup = 'http-stop-failed'
            Write-Output "HTTP stop failed: $($_.Exception.Message)"
            Write-Output 'On UBU01: kill the pid in /tmp/sentinelforge-lab-http/server.pid'
        }
        $secret = $null
    }
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-006' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands $commands -ExpectedRuleIds @('100220', '100221') -CleanupStatus $cleanup -Notes 'HTTP bind is 10.10.10.30:8080. Sysmon source is expected to be 10.10.10.20. SSH source is 10.10.10.200. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-006-DownloadCradle-Cleanup.ps1 -IUnderstandLabOnly'
