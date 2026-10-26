# REQUIRES WINDOWS VALIDATION
# Purpose: Event 4104 whose text contains IEX, Invoke-Expression, and
#          FromBase64String as Write-Output strings. Nothing is invoked.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+, Script Block Logging
# Status: NOT TESTED
# Atomic: technique T1059.001. Atomic Test #1 is Mimikatz and is not used.
#         No Atomic body is downloaded.
# Expected events: 4104
# Expected rules: 100200

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

$markerOne = -join @('I', 'EX')
$markerTwo = -join @('Invoke-', 'Expression')
$markerThree = -join @('FromBase64', 'String')
$blockText = "Write-Output 'sentinelforge-lab'; Write-Output '$markerOne'; Write-Output '$markerTwo'; Write-Output '$markerThree'"
if ($blockText -notmatch '\bIEX\b' -or $blockText -notmatch 'Invoke-' -or $blockText -notmatch 'FromBase64') {
    throw 'The script block markers were not built.'
}
if ($PSCmdlet.ShouldProcess('4104 markers', 'Invoke harmless script block')) {
    $block = [scriptblock]::Create($blockText)
    & $block | Out-Null
}

$recordPath = Write-LabRunRecord -DetectionId 'SF-004' -StartedUtc $started -EndedUtc ([datetime]::UtcNow) -Commands @('Write-Output lab markers for IEX, Invoke-Expression, and FromBase64String') -ExpectedRuleIds @('100200') -CleanupStatus 'nothing-to-remove' -Notes 'The strings are data. No command by those names is called. REQUIRES WINDOWS VALIDATION.' -WhatIf:$WhatIfPreference
if ($recordPath) { Write-Output "RUN RECORD $recordPath" }
Write-Output 'Next: SF-004-ScriptBlockMarkers-Cleanup.ps1 -IUnderstandLabOnly'
