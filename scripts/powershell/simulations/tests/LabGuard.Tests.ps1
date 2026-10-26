# Purpose: Pester tests for the lab guard. The host is mocked.
# Run on: Mac, GitHub Actions, or Windows. No NIC changes.
# Requires: PowerShell 5.1+ and Pester 5.6.1 or newer
# Status: SYNTAX VALID when Pester passes. Not a lab simulation.

#Requires -Version 5.1

Set-StrictMode -Version Latest

BeforeAll {
    $simRoot = Split-Path -Parent $PSScriptRoot
    $modulePath = Join-Path $simRoot 'SentinelForge.LabGuard.psm1'
    Import-Module $modulePath -Force
}

Describe 'Assert-SentinelForgeLab' {
    BeforeEach {
        Mock Get-LabEnvironment -ModuleName SentinelForge.LabGuard {
            [pscustomobject]@{
                ComputerName         = 'WS01'
                Domain               = 'sentinelforge.lab'
                PartOfDomain         = $true
                IPv4Addresses        = @('10.10.10.20')
                DefaultRouteNextHops = @()
            }
        }
    }

    It 'refuses a wrong domain' {
        Mock Get-LabEnvironment -ModuleName SentinelForge.LabGuard {
            [pscustomobject]@{
                ComputerName         = 'WS01'
                Domain               = 'contoso.example'
                PartOfDomain         = $true
                IPv4Addresses        = @('10.10.10.20')
                DefaultRouteNextHops = @()
            }
        }
        {
            Assert-SentinelForgeLab -IUnderstandLabOnly -SnapshotText 'I have a snapshot'
        } | Should -Throw -ExpectedMessage '*sentinelforge.lab*'
    }

    It 'refuses a wrong host' {
        Mock Get-LabEnvironment -ModuleName SentinelForge.LabGuard {
            [pscustomobject]@{
                ComputerName         = 'UBU01'
                Domain               = 'sentinelforge.lab'
                PartOfDomain         = $true
                IPv4Addresses        = @('10.10.10.30')
                DefaultRouteNextHops = @()
            }
        }
        {
            Assert-SentinelForgeLab -IUnderstandLabOnly -SnapshotText 'I have a snapshot'
        } | Should -Throw -ExpectedMessage '*UBU01*'
    }

    It 'refuses a missing switch' {
        {
            Assert-SentinelForgeLab -SnapshotText 'I have a snapshot'
        } | Should -Throw -ExpectedMessage '*IUnderstandLabOnly*'
    }

    It 'allows a lab host when every check passes' {
        {
            Assert-SentinelForgeLab -IUnderstandLabOnly -SnapshotText 'I have a snapshot'
        } | Should -Not -Throw
    }

    It 'refuses an address outside the lab subnet' {
        Mock Get-LabEnvironment -ModuleName SentinelForge.LabGuard {
            [pscustomobject]@{
                ComputerName         = 'WS01'
                Domain               = 'sentinelforge.lab'
                PartOfDomain         = $true
                IPv4Addresses        = @('10.10.10.20', '192.168.1.20')
                DefaultRouteNextHops = @()
            }
        }
        {
            Assert-SentinelForgeLab -IUnderstandLabOnly -SnapshotText 'I have a snapshot'
        } | Should -Throw -ExpectedMessage '*192.168.1.20*'
    }

    It 'warns and still allows a default route' {
        Mock Get-LabEnvironment -ModuleName SentinelForge.LabGuard {
            [pscustomobject]@{
                ComputerName         = 'WS01'
                Domain               = 'sentinelforge.lab'
                PartOfDomain         = $true
                IPv4Addresses        = @('10.10.10.20')
                DefaultRouteNextHops = @('10.10.10.1')
            }
        }
        $warnings = @()
        $result = Assert-SentinelForgeLab -IUnderstandLabOnly -SnapshotText 'I have a snapshot' -WarningVariable warnings
        @($warnings).Count | Should -BeGreaterThan 0
        $result | Should -Match 'LAB WARNING'
    }
}

Describe 'lab command safety' {
    It 'refuses to record the wrong-password marker' {
        $evidence = Join-Path ([System.IO.Path]::GetTempPath()) ('sf-evidence-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $evidence | Out-Null
        try {
            {
                Write-LabRunRecord -DetectionId 'SF-001' -StartedUtc ([datetime]::UtcNow) -EndedUtc ([datetime]::UtcNow) -Commands @('net use \\DC01\IPC$ SentinelForge-Wrong-1') -ExpectedRuleIds @('100100') -CleanupStatus 'pending' -EvidenceDirectory $evidence
            } | Should -Throw -ExpectedMessage '*wrong-password marker*'
        }
        finally {
            Remove-Item -LiteralPath $evidence -Recurse -Force
        }
    }

    It 'keeps the lab HTTP server on 10.10.10.30' {
        $text = Get-LabRemoteText -Purpose 'HttpStart'
        $text | Should -Match '--bind 10.10.10.30'
        $text | Should -Not -Match '0\.0\.0\.0'
        $text | Should -Match 'sentinelforge-lab harmless file'
    }
}
