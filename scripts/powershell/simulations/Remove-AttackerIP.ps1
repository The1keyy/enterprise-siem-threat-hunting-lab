# REQUIRES WINDOWS VALIDATION
# Purpose: Remove 10.10.10.200 if it is present. Idempotent.
# Run on: WS01 or DC01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED

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

Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('DC01', 'WS01')
Remove-LabAttackerAddress -WhatIf:$WhatIfPreference
