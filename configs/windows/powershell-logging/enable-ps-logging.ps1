# REQUIRES WINDOWS VALIDATION
# Purpose: Turn on Script Block Logging (4104) and Module Logging.
#          Transcription stays off.
# Run on: both
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PolicyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$ScriptBlockKey = Join-Path $PolicyRoot 'ScriptBlockLogging'
$ModuleKey = Join-Path $PolicyRoot 'ModuleLogging'
$ModuleNamesKey = Join-Path $ModuleKey 'ModuleNames'
$TranscriptionKey = Join-Path $PolicyRoot 'Transcription'
$OperationalLog = 'Microsoft-Windows-PowerShell/Operational'
# Default maximum is about 15 MB. 256 MB keeps a lab script-block burst.
$OperationalLogBytes = 256MB

function Set-DwordValue {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [int]$Value
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'New-Item')) {
            New-Item -Path $Path -Force | Out-Null
        }
    }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set DWORD $Value")) {
        New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    }
}

# 4104. Invocation logging is a second, noisier switch and is not set.
Set-DwordValue -Path $ScriptBlockKey -Name 'EnableScriptBlockLogging' -Value 1

# Module Logging records pipeline events for imported modules. '*' is the
# Microsoft policy value for every module. It is noisy. Narrow the value
# later if the lab disk or the agent queue fills up. SF-004 and SF-006 match
# 4104 script text, not this module log.
Set-DwordValue -Path $ModuleKey -Name 'EnableModuleLogging' -Value 1
if (-not (Test-Path -LiteralPath $ModuleNamesKey)) {
    if ($PSCmdlet.ShouldProcess($ModuleNamesKey, 'New-Item')) {
        New-Item -Path $ModuleNamesKey -Force | Out-Null
    }
}
if ($PSCmdlet.ShouldProcess("$ModuleNamesKey\*", 'Set *')) {
    New-ItemProperty -Path $ModuleNamesKey -Name '*' -PropertyType String -Value '*' -Force | Out-Null
}

# Transcription writes a text file of the session. That file can contain
# passwords typed at the prompt, and it grows without a channel to collect.
# Off unless a later lab task turns it on for one host and deletes the files.
Set-DwordValue -Path $TranscriptionKey -Name 'EnableTranscripting' -Value 0

if ($PSCmdlet.ShouldProcess($OperationalLog, "wevtutil sl /ms:$OperationalLogBytes")) {
    & wevtutil.exe sl $OperationalLog "/ms:$OperationalLogBytes"
    if ($LASTEXITCODE -ne 0) {
        throw "wevtutil sl $OperationalLog exited $LASTEXITCODE"
    }
}
