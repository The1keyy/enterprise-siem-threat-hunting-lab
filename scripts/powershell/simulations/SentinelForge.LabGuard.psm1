# REQUIRES WINDOWS VALIDATION
# Purpose: Refuse lab simulations unless this host is sentinelforge.lab, on the
#          allowlist, and inside 10.10.10.0/24. Also the shared run-record,
#          secondary-address, SMB, and OpenSSH helpers.
# Run on: DC01 or WS01. Imported by the simulation scripts. Pester mocks
#         Get-LabEnvironment, so the tests do not touch a NIC.
# Requires: PowerShell 5.1+. The scripts that import this also require an
#           elevated session. This module does not.
# Status: NOT TESTED
#
# Simulations produce telemetry. They do not install malware, dump credentials,
# or leave 10.10.10.0/24. A wrong-password marker is not a real password.
# Real passwords are Read-Host -AsSecureString and are not written to the
# run record.

#Requires -Version 5.1

Set-StrictMode -Version Latest

$script:LabDomain = 'sentinelforge.lab'
$script:SnapshotPhrase = 'I have a snapshot'
$script:AttackerAddress = '10.10.10.200'
$script:PrimaryAddress = '10.10.10.20'
$script:SshTarget = 'sf-test-alice@10.10.10.30'
$script:HttpBind = '10.10.10.30'
$script:HttpPort = 8080
$script:WrongMarker = 'SentinelForge-Wrong-1'

function Test-LabIPv4Address {
    param(
        [Parameter(Mandatory = $true)][string]$Address
    )
    $parsed = [System.Net.IPAddress]::Parse('0.0.0.0')
    $ok = [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)
    if (-not $ok) {
        return $false
    }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $bytes = $parsed.GetAddressBytes()
    if ($bytes.Length -ne 4) {
        return $false
    }
    return ($bytes[0] -eq 10 -and $bytes[1] -eq 10 -and $bytes[2] -eq 10)
}

function Get-LabEnvironment {
    <#
    .SYNOPSIS
    Read domain, hostname, IPv4 addresses, and default routes.
    #>
    [CmdletBinding()]
    param()

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $addresses = @(
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' } |
            ForEach-Object { [string]$_.IPAddress }
    )
    $routes = @(
        Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            ForEach-Object { [string]$_.NextHop }
    )
    [pscustomobject]@{
        ComputerName         = [string]$env:COMPUTERNAME
        Domain               = [string]$computer.Domain
        PartOfDomain         = [bool]$computer.PartOfDomain
        IPv4Addresses        = $addresses
        DefaultRouteNextHops = $routes
    }
}

function Assert-SentinelForgeLab {
    <#
    .SYNOPSIS
    Refuse to continue unless this host is in the lab.
    #>
    [CmdletBinding()]
    param(
        [switch]$IUnderstandLabOnly,
        [string]$SnapshotText,
        [string[]]$AllowedHosts = @('DC01', 'WS01')
    )

    if (-not $IUnderstandLabOnly) {
        throw 'Refusing to run: -IUnderstandLabOnly was not passed. These scripts are LAB ONLY.'
    }
    if ([string]::IsNullOrWhiteSpace($SnapshotText)) {
        $SnapshotText = Read-Host 'Type "I have a snapshot" to continue'
    }
    if ($SnapshotText -cne $script:SnapshotPhrase) {
        throw 'Refusing to run: snapshot confirmation was not "I have a snapshot".'
    }
    if (-not $AllowedHosts -or $AllowedHosts.Count -eq 0) {
        throw 'Refusing to run: the host allowlist is empty.'
    }

    $facts = Get-LabEnvironment
    $domain = [string]$facts.Domain
    if (-not $facts.PartOfDomain -or $domain -ne $script:LabDomain) {
        throw "Refusing to run: computer is not joined to sentinelforge.lab (domain='$domain')."
    }

    $short = [string]$facts.ComputerName
    if ($short.Contains('.')) {
        $short = $short.Split('.')[0]
    }
    $allowed = $false
    foreach ($name in $AllowedHosts) {
        if ($short -eq $name) {
            $allowed = $true
        }
    }
    if (-not $allowed) {
        $list = $AllowedHosts -join ', '
        throw "Refusing to run: hostname '$short' is not in the allowlist ($list)."
    }

    $addresses = @($facts.IPv4Addresses)
    if ($addresses.Count -eq 0) {
        throw 'Refusing to run: no IPv4 addresses were reported.'
    }
    foreach ($address in $addresses) {
        if ($address -eq '127.0.0.1') {
            continue
        }
        if (-not (Test-LabIPv4Address -Address $address)) {
            throw "Refusing to run: address $address is outside 10.10.10.0/24."
        }
    }

    $hops = @()
    foreach ($hop in @($facts.DefaultRouteNextHops)) {
        if ($hop -and $hop -ne '0.0.0.0') {
            $hops += $hop
        }
    }
    if ($hops.Count -gt 0) {
        $listed = $hops -join ', '
        $message = "LAB WARNING: a default route exists via $listed. This lab is host-only. Stop if that route can reach the internet."
        Write-Warning $message
        Write-Output $message
    }
}

function Get-LabWrongMarker {
    $secret = New-Object System.Security.SecureString
    foreach ($char in $script:WrongMarker.ToCharArray()) {
        $secret.AppendChar($char)
    }
    $secret.MakeReadOnly()
    return $secret
}

function ConvertFrom-LabSecureString {
    param(
        [Parameter(Mandatory = $true)][System.Security.SecureString]$Secret
    )
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Write-LabRunRecord {
    <#
    .SYNOPSIS
    Write a redacted JSON run record. Passwords are rejected.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$DetectionId,
        [Parameter(Mandatory = $true)][datetime]$StartedUtc,
        [Parameter(Mandatory = $true)][datetime]$EndedUtc,
        [Parameter(Mandatory = $true)][string[]]$Commands,
        [Parameter(Mandatory = $true)][string[]]$ExpectedRuleIds,
        [Parameter(Mandatory = $true)][string]$CleanupStatus,
        [string]$Notes = '',
        [string]$EvidenceDirectory = 'C:\SentinelForge\evidence\runs'
    )

    if ($DetectionId -notmatch '^(SF-\d{3}|STORY)$') {
        throw "Refusing run record id '$DetectionId'."
    }
    foreach ($command in $Commands) {
        if ($command -like "*$script:WrongMarker*") {
            throw 'Refusing to record the lab wrong-password marker. Pass a redacted command.'
        }
        if ($command -match '(?i)password|passwd|secret=') {
            throw 'Refusing to record a command that contains a password field.'
        }
    }

    $record = [ordered]@{
        host             = [string]$env:COMPUTERNAME
        user             = [string]$env:USERNAME
        startedUtc       = $StartedUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        endedUtc         = $EndedUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        commands         = @($Commands)
        expectedRuleIds  = @($ExpectedRuleIds)
        cleanupStatus    = $CleanupStatus
        detectionId      = $DetectionId
        notes            = $Notes
    }
    $stamp = $StartedUtc.ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $fileName = '{0}_{1}.json' -f $stamp, $DetectionId
    $fullPath = Join-Path $EvidenceDirectory $fileName
    if ($PSCmdlet.ShouldProcess($fullPath, 'Write run record')) {
        if (-not (Test-Path -LiteralPath $EvidenceDirectory)) {
            New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null
        }
        $json = $record | ConvertTo-Json -Depth 4
        Set-Content -LiteralPath $fullPath -Value $json -Encoding utf8
        return $fullPath
    }
    return $null
}

function Add-LabAttackerAddress {
    <#
    .SYNOPSIS
    Add 10.10.10.200 on the NIC that has 10.10.10.20.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $existing = Get-NetIPAddress -IPAddress $script:AttackerAddress -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Output "PASS attacker address $script:AttackerAddress already present"
        return
    }
    $primary = @(
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -eq $script:PrimaryAddress }
    )
    if ($primary.Count -eq 0) {
        throw "Refusing to add $script:AttackerAddress because $script:PrimaryAddress is not on this host."
    }
    $index = $primary[0].InterfaceIndex
    if ($PSCmdlet.ShouldProcess($script:AttackerAddress, 'Add secondary lab address')) {
        try {
            New-NetIPAddress -InterfaceIndex $index -IPAddress $script:AttackerAddress -PrefixLength 24 -SkipAsSource $false -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
        }
        catch {
            $check = Get-NetIPAddress -IPAddress $script:AttackerAddress -ErrorAction SilentlyContinue
            if (-not $check) {
                throw
            }
        }
        Write-Output "PASS added $script:AttackerAddress on interface $index"
    }
}

function Remove-LabAttackerAddress {
    <#
    .SYNOPSIS
    Remove 10.10.10.200 when that address is present.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $existing = Get-NetIPAddress -IPAddress $script:AttackerAddress -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-Output "PASS attacker address $script:AttackerAddress already absent"
        return
    }
    if ($PSCmdlet.ShouldProcess($script:AttackerAddress, 'Remove secondary lab address')) {
        Remove-NetIPAddress -IPAddress $script:AttackerAddress -Confirm:$false -ErrorAction Stop
        Write-Output "PASS removed $script:AttackerAddress"
    }
}

function Remove-LabSmbMapping {
    <#
    .SYNOPSIS
    Delete one SMB mapping to DC01.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('IPC$', 'C$')]
        [string]$Share
    )

    $target = "\\DC01\$Share"
    $net = Join-Path $env:SystemRoot 'System32\net.exe'
    if (-not (Test-Path -LiteralPath $net)) {
        throw "net.exe was not found at $net."
    }
    if ($PSCmdlet.ShouldProcess($target, 'Delete SMB mapping')) {
        $captured = & $net @('use', $target, '/delete') 2>&1 | Out-String
        $code = $LASTEXITCODE
        if ($code -ne 0 -and $captured -notmatch 'not found|2250|network connection could not be found') {
            throw "net use /delete $target failed ($code): $captured"
        }
        Write-Output "PASS removed $target"
    }
}

function Invoke-LabNetUse {
    <#
    .SYNOPSIS
    Run net use against DC01 without recording a password.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('IPC$', 'C$')]
        [string]$Share,
        [ValidatePattern('^sf-test-[a-z0-9-]+$')]
        [string]$Account = 'sf-test-alice',
        [Parameter(Mandatory = $true)]
        [ValidateSet('WrongMarker', 'Prompt', 'CurrentSession')]
        [string]$Authentication
    )

    $target = "\\DC01\$Share"
    $recorded = "net use $target"
    if ($Authentication -eq 'CurrentSession') {
        $argList = @('use', $target)
    }
    elseif ($Authentication -eq 'Prompt') {
        $recorded = "net use $target /user:SENTINELFORGE\$Account *"
        $argList = @('use', $target, "/user:SENTINELFORGE\$Account", '*')
    }
    else {
        $recorded = "net use $target /user:SENTINELFORGE\$Account ***"
        $argList = @('use', $target, "/user:SENTINELFORGE\$Account")
    }

    if (-not $PSCmdlet.ShouldProcess($target, "net use $Authentication")) {
        return [pscustomobject]@{
            ExitCode        = 0
            Text            = 'whatif'
            RecordedCommand = $recorded
        }
    }

    $net = Join-Path $env:SystemRoot 'System32\net.exe'
    if (-not (Test-Path -LiteralPath $net)) {
        throw "net.exe was not found at $net."
    }

    $plain = $null
    try {
        if ($Authentication -eq 'WrongMarker') {
            $plain = ConvertFrom-LabSecureString -Secret (Get-LabWrongMarker)
            $argList += $plain
            $captured = & $net @argList 2>&1 | Out-String
            $code = $LASTEXITCODE
        }
        else {
            & $net @argList | Out-Null
            $captured = ''
            $code = $LASTEXITCODE
        }
    }
    finally {
        $plain = $null
    }

    if ($captured.Contains($script:WrongMarker)) {
        $captured = $captured.Replace($script:WrongMarker, '***')
    }
    if ($Authentication -eq 'WrongMarker' -and $code -eq 0) {
        Remove-LabSmbMapping -Share $Share
        throw "The wrong marker authenticated to $target. The mapping was removed. Stop."
    }
    return [pscustomobject]@{
        ExitCode        = $code
        Text            = $captured.Trim()
        RecordedCommand = $recorded
    }
}

function Get-LabSshExecutable {
    $candidate = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw 'Windows OpenSSH Client is not installed. Install the Windows capability OpenSSH.Client. This script does not download a client.'
    }
    return $candidate
}

function Get-LabRemoteText {
    <#
    .SYNOPSIS
    Return the fixed remote command for one lab SSH action.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('AuthFailure', 'AuthSuccess', 'HttpStart', 'HttpStop', 'FaillockInspect', 'FaillockReset', 'PamTallyReset')]
        [string]$Purpose
    )

    if ($Purpose -eq 'AuthFailure' -or $Purpose -eq 'AuthSuccess') {
        return 'exit'
    }
    if ($Purpose -eq 'HttpStart') {
        $lines = @(
            'mkdir -p /tmp/sentinelforge-lab-http',
            'printf ''%s\n'' ''sentinelforge-lab harmless file'' > /tmp/sentinelforge-lab-http/sentinelforge-lab.txt',
            'if [ -f /tmp/sentinelforge-lab-http/server.pid ] && kill -0 "$(cat /tmp/sentinelforge-lab-http/server.pid)" 2>/dev/null; then echo ALREADY; exit 0; fi',
            'nohup python3 -m http.server 8080 --bind 10.10.10.30 --directory /tmp/sentinelforge-lab-http >/tmp/sentinelforge-lab-http/server.log 2>&1 &',
            'echo $! > /tmp/sentinelforge-lab-http/server.pid',
            'echo STARTED'
        )
        return ($lines -join "`n")
    }
    if ($Purpose -eq 'HttpStop') {
        return 'if [ -f /tmp/sentinelforge-lab-http/server.pid ]; then kill "$(cat /tmp/sentinelforge-lab-http/server.pid)" 2>/dev/null || true; rm -f /tmp/sentinelforge-lab-http/server.pid; fi; echo STOPPED'
    }
    if ($Purpose -eq 'FaillockInspect') {
        return 'if grep -Rqs pam_faillock /etc/pam.d 2>/dev/null; then echo FAILLOCK_PRESENT; elif grep -Rqs pam_tally /etc/pam.d 2>/dev/null; then echo PAM_TALLY2_PRESENT; else echo LOCKOUT_TOOL_NOT_ENABLED; fi'
    }
    if ($Purpose -eq 'FaillockReset') {
        return 'if grep -Rqs pam_faillock /etc/pam.d 2>/dev/null; then faillock --user sf-test-alice --reset; echo RESET_DONE; else echo LOCKOUT_TOOL_NOT_ENABLED; fi'
    }
    return 'if grep -Rqs pam_tally /etc/pam.d 2>/dev/null; then pam_tally2 --user sf-test-alice --reset; echo RESET_DONE; else echo LOCKOUT_TOOL_NOT_ENABLED; fi'
}

function Invoke-LabOpenSsh {
    <#
    .SYNOPSIS
    Run ssh.exe bound to 10.10.10.200. The password is not an argument.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('AuthFailure', 'AuthSuccess', 'HttpStart', 'HttpStop', 'FaillockInspect', 'FaillockReset', 'PamTallyReset')]
        [string]$Purpose,
        [System.Security.SecureString]$Secret
    )

    $recorded = "ssh.exe -o BindAddress=$script:AttackerAddress $script:SshTarget $Purpose"
    $remote = Get-LabRemoteText -Purpose $Purpose
    if ($remote -notlike "*$script:HttpBind*" -and $Purpose -eq 'HttpStart') {
        throw 'Refusing an HTTP server command that does not bind to 10.10.10.30.'
    }
    if ($remote -like '*0.0.0.0*') {
        throw 'Refusing a remote command that listens on 0.0.0.0.'
    }
    if (-not $PSCmdlet.ShouldProcess($script:SshTarget, $Purpose)) {
        return [pscustomobject]@{
            ExitCode        = 0
            Text            = 'whatif'
            RecordedCommand = $recorded
        }
    }

    $present = Get-NetIPAddress -IPAddress $script:AttackerAddress -ErrorAction SilentlyContinue
    if (-not $present) {
        throw "10.10.10.200 is not local. Run Add-AttackerIP.ps1. This script will not fall back to $script:PrimaryAddress."
    }
    $sshExe = Get-LabSshExecutable
    $knownHostsDir = 'C:\SentinelForge\evidence\ssh'
    if (-not (Test-Path -LiteralPath $knownHostsDir)) {
        New-Item -ItemType Directory -Path $knownHostsDir -Force | Out-Null
    }
    $knownHosts = Join-Path $knownHostsDir 'known_hosts'
    $askpass = Join-Path $env:TEMP ('sentinelforge-askpass-' + [guid]::NewGuid().ToString('N') + '.cmd')
    $previousAsk = $env:SSH_ASKPASS
    $previousRequire = $env:SSH_ASKPASS_REQUIRE
    $previousDisplay = $env:DISPLAY
    $previousSecret = $env:SF_LAB_ASKPASS
    $plain = $null
    try {
        $usingSecret = $Secret
        if ($Purpose -eq 'AuthFailure') {
            $usingSecret = Get-LabWrongMarker
        }
        elseif (-not $usingSecret -or $usingSecret.Length -lt 1) {
            throw 'A prompted password is required for this SSH action.'
        }
        $plain = ConvertFrom-LabSecureString -Secret $usingSecret
        $askpassBody = "@echo off`r`necho %SF_LAB_ASKPASS%`r`n"
        Set-Content -LiteralPath $askpass -Value $askpassBody -Encoding Ascii
        $env:SSH_ASKPASS = $askpass
        $env:SSH_ASKPASS_REQUIRE = 'force'
        $env:DISPLAY = 'lab-askpass'
        $env:SF_LAB_ASKPASS = $plain
        $optionList = @(
            '-o', 'PreferredAuthentications=password',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'PasswordAuthentication=yes',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', "UserKnownHostsFile=$knownHosts",
            '-o', "BindAddress=$script:AttackerAddress",
            '-o', 'ConnectTimeout=8'
        )
        $captured = & $sshExe @optionList $script:SshTarget $remote 2>&1 | Out-String
        $code = $LASTEXITCODE
    }
    finally {
        $plain = $null
        $env:SF_LAB_ASKPASS = $null
        if ($null -eq $previousAsk) { $env:SSH_ASKPASS = $null } else { $env:SSH_ASKPASS = $previousAsk }
        if ($null -eq $previousRequire) { $env:SSH_ASKPASS_REQUIRE = $null } else { $env:SSH_ASKPASS_REQUIRE = $previousRequire }
        if ($null -eq $previousDisplay) { $env:DISPLAY = $null } else { $env:DISPLAY = $previousDisplay }
        if ($null -ne $previousSecret) { $env:SF_LAB_ASKPASS = $previousSecret }
        Remove-Item -LiteralPath $askpass -Force -ErrorAction SilentlyContinue
    }

    if ($captured.Contains($script:WrongMarker)) {
        $captured = $captured.Replace($script:WrongMarker, '***')
    }
    if ($captured -match 'Cannot assign requested address|bind \[|BindAddress') {
        throw "BindAddress $script:AttackerAddress failed. Not retrying on $script:PrimaryAddress. $captured"
    }
    return [pscustomobject]@{
        ExitCode        = $code
        Text            = $captured.Trim()
        RecordedCommand = $recorded
    }
}

Export-ModuleMember -Function @(
    'Assert-SentinelForgeLab',
    'Get-LabEnvironment',
    'Write-LabRunRecord',
    'Add-LabAttackerAddress',
    'Remove-LabAttackerAddress',
    'Invoke-LabNetUse',
    'Remove-LabSmbMapping',
    'Invoke-LabOpenSsh',
    'Get-LabRemoteText'
)
