<#
.SYNOPSIS
  Installs Sentro DSPM from this offline package as two Windows services.

.DESCRIPTION
  Checks the package (checksums, and its signature when signed), then places the pinned
  Python, the wheels and the application under -InstallRoot, writes the configuration and
  generates keys under -DataRoot (Administrators and the services only), migrates the
  database, and registers <Prefix>Backend and <Prefix>Worker to start automatically. It
  finishes when /api/ready answers on 127.0.0.1:<Port>.

  A production install runs on PostgreSQL: -DatabaseUrlFile names a file holding the
  application role's URL (it is copied into the protected secrets folder; the URL itself
  never appears on a command line). -Mode evaluation uses SQLite in the data root.

  Installing again over a kept data root (after uninstall.ps1 without -RemoveData) reuses
  its database, keys and configuration.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -PublicHostName sentro.corp.example -DatabaseUrlFile C:\secure\sentro-db-url.txt -AllowUnsigned
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'Sentro'),
    [string]$DataRoot = (Join-Path $env:ProgramData 'Sentro'),
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{1,30}$')][string]$ServicePrefix = 'Sentro',
    [ValidateRange(1024, 65535)][int]$Port = 8000,
    [ValidateSet('production', 'evaluation')][string]$Mode = 'production',
    [string]$DatabaseUrlFile,
    [string]$PublicHostName,
    [string]$PublisherKeyFile,
    [switch]$TrustPackagePublisher,
    [switch]$AllowUnsigned
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\SentroPackage.psm1') -Force
Assert-SentroAdministrator
$manifest = Test-SentroPackage -PackageDir $PSScriptRoot -AllowUnsigned:$AllowUnsigned
$python = Expand-SentroRuntime -PackageDir $PSScriptRoot -Manifest $manifest
try {
    $arguments = @('install', '--package', $PSScriptRoot, '--install-root', $InstallRoot, '--data-root', $DataRoot,
                   '--prefix', $ServicePrefix, '--port', [string]$Port, '--mode', $Mode)
    if ($PublicHostName) { $arguments += @('--public-host', $PublicHostName) }
    if ($DatabaseUrlFile) { $arguments += @('--db-url-file', (Resolve-Path -LiteralPath $DatabaseUrlFile).Path) }
    if ($PublisherKeyFile) { $arguments += @('--publisher-key-file', (Resolve-Path -LiteralPath $PublisherKeyFile).Path) }
    if ($TrustPackagePublisher) { $arguments += '--trust-package-publisher' }
    if ($AllowUnsigned) { $arguments += '--allow-unsigned' }
    $code = Invoke-SentroInstaller -Python $python -Script (Join-Path $PSScriptRoot 'installer\sentro_installer.py') `
        -Arguments $arguments -DataRoot $DataRoot -Action 'install'
} finally {
    Remove-SentroRuntime -Python $python
}
exit $code
