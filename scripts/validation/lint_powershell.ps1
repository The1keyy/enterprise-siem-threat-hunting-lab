# Purpose: PSScriptAnalyzer plus a parse check for the lab PowerShell.
# Run on: Mac and GitHub Actions. Not a Windows host change.
# Requires: PowerShell 7 (pwsh) and PSScriptAnalyzer
# Status: SYNTAX VALID when this script reports 0 findings

#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root

Import-Module PSScriptAnalyzer

$roots = @('scripts/powershell', 'configs/windows', 'configs/sysmon')
$results = foreach ($root in $roots) {
    Invoke-ScriptAnalyzer -Path $root -Recurse -Severity Error,Warning,Information
}
if ($results) {
    $results | Format-Table -AutoSize Severity, RuleName, ScriptName, Line, Message | Out-String -Width 220 | Write-Output
    Write-Output ('COUNT=' + @($results).Count)
    exit 1
}
Write-Output 'PSScriptAnalyzer: 0 findings'

Get-ChildItem -Path $roots -Recurse -Filter *.ps1 | ForEach-Object {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        Write-Output ('PARSE FAIL ' + $_.FullName)
        $parseErrors | ForEach-Object { Write-Output $_.ToString() }
        exit 1
    }
    Write-Output ('PARSE OK ' + $_.FullName)
}
