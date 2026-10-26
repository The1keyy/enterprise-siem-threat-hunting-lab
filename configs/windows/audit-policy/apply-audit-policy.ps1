# REQUIRES WINDOWS VALIDATION
# Purpose: Set the advanced audit subcategories in docs/TELEMETRY_MATRIX.md,
#          include the command line on Security 4688, and raise the Security log to 1 GB.
# Run on: both
# Requires: Administrator, PowerShell 5.1+
# Status: SYNTAX VALID

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# GUIDs are from MS-GPAC (SubcategoryGUID). English names are comments only.
# auditpol /set /subcategory:Logon fails on a non-English Windows install.
# Confirm on the host with: auditpol /list /subcategory:* /v
$Subcategories = @(
    @{ Name = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Success = 'enable'; Failure = 'enable' }
    @{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Success = 'enable'; Failure = $null }
    @{ Name = 'User Account Management'; Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Success = 'enable'; Failure = $null }
    @{ Name = 'Process Creation'; Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Success = 'enable'; Failure = $null }
    @{ Name = 'File Share'; Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Success = 'enable'; Failure = $null }
    @{ Name = 'Detailed File Share'; Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Success = 'enable'; Failure = $null }
)

$CommandLineKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$SecurityLogBytes = 1GB

function Write-AuditPolicy {
    Write-Output 'auditpol /get /category:*'
    & auditpol.exe /get /category:*
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol /get exited $LASTEXITCODE"
    }
}

function Invoke-AuditPolSet {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )
    $shown = 'auditpol ' + ($ArgumentList -join ' ')
    if ($PSCmdlet.ShouldProcess($Name, $shown)) {
        & auditpol.exe @ArgumentList
        if ($LASTEXITCODE -ne 0) {
            throw "$shown exited $LASTEXITCODE"
        }
    }
}

Write-Output 'BEFORE'
Write-AuditPolicy

foreach ($item in $Subcategories) {
    $auditArguments = @('/set', "/subcategory:$($item.Guid)", "/success:$($item.Success)")
    if ($null -ne $item.Failure) {
        $auditArguments += "/failure:$($item.Failure)"
    }
    Invoke-AuditPolSet -Name $item.Name -ArgumentList $auditArguments
}

if (-not (Test-Path -LiteralPath $CommandLineKey)) {
    if ($PSCmdlet.ShouldProcess($CommandLineKey, 'New-Item')) {
        New-Item -Path $CommandLineKey -Force | Out-Null
    }
}
if ($PSCmdlet.ShouldProcess('ProcessCreationIncludeCmdLine_Enabled', 'Set DWORD 1')) {
    New-ItemProperty -Path $CommandLineKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -PropertyType DWord -Value 1 -Force | Out-Null
}

if ($PSCmdlet.ShouldProcess('Security', "wevtutil sl Security /ms:$SecurityLogBytes")) {
    & wevtutil.exe sl Security "/ms:$SecurityLogBytes"
    if ($LASTEXITCODE -ne 0) {
        throw "wevtutil sl Security exited $LASTEXITCODE"
    }
}

Write-Output 'AFTER'
Write-AuditPolicy
