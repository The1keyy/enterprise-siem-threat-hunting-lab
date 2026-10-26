# Purpose: Run the lab-guard Pester tests and exit non-zero on failure.
# Run on: Mac and GitHub Actions.
# Requires: PowerShell 5.1+ and Pester 5.6.1 or newer
# Status: SYNTAX VALID when the tests pass

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installed = @(Get-Module -ListAvailable -Name Pester | Sort-Object Version -Descending)
if ($installed.Count -eq 0 -or $installed[0].Version -lt [version]'5.6.1') {
    throw 'Install Pester 5.6.1 or newer for the current user. CI installs 5.6.1.'
}

Import-Module Pester -MinimumVersion 5.6.1
$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'LabGuard.Tests.ps1'
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
