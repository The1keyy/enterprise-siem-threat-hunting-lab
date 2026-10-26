# REQUIRES WINDOWS VALIDATION
# Purpose: Add 10.10.10.200 as a secondary address on the NIC that has 10.10.10.20.
# Run on: WS01
# Requires: Administrator, PowerShell 5.1+
# Status: NOT TESTED
# There is no 10.10.10.200 VM. Cleanup is Remove-AttackerIP.ps1.

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

Assert-SentinelForgeLab -IUnderstandLabOnly:$IUnderstandLabOnly -SnapshotText $SnapshotText -AllowedHosts @('WS01')
Add-LabAttackerAddress -WhatIf:$WhatIfPreference
