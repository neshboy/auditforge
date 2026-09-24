#Requires -Version 5.1
<#
.SYNOPSIS
    One-click launcher for AuditForge on Windows.
.DESCRIPTION
    Locates (or bootstraps) a Python environment, installs AuditForge in
    editable mode if needed, and either launches the interactive menu or
    forwards arguments straight to the CLI.
.EXAMPLE
    .\Run-AuditForge.ps1
    .\Run-AuditForge.ps1 audit --profile audit_only
    .\Run-AuditForge.ps1 harden --dry-run
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$venvPath = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Warning "Not running as Administrator. AUDIT mode will still work for most read-only checks, but many probes (BitLocker, secedit, Defender, firewall) and ALL of harden/rollback require an elevated PowerShell session."
}

if (-not (Test-Path $venvPython)) {
    Write-Host "Setting up AuditForge's Python environment (first run only)..." -ForegroundColor Cyan
    $systemPython = Get-Command python -ErrorAction SilentlyContinue
    if (-not $systemPython) {
        throw "Python 3.9+ is required and was not found on PATH. Install it from https://www.python.org/downloads/ and re-run this script."
    }
    & $systemPython.Source -m venv $venvPath
    & $venvPython -m pip install -q --upgrade pip
    & $venvPython -m pip install -q -e $repoRoot
}

if ($Args.Count -eq 0) {
    & $venvPython -m auditforge.cli
} else {
    & $venvPython -m auditforge.cli @Args
}
exit $LASTEXITCODE
