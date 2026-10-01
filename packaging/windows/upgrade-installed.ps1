<#
.SYNOPSIS
  Upgrades this Sentro install to the release in -Package. Run THIS copy, the one inside
  the install (<InstallRoot>\current\installer\upgrade.ps1), not the package's own script.

.DESCRIPTION
  Everything that runs before the package is verified is code this install already
  verified: this script, the installer and the package checks beside it, and the Python of
  the running release. The installer copies the package to a folder only administrators can
  write, checks every file against SHA256SUMS and the publisher's signature against this
  install's pinned key (with the running release's verifier), and only then places the new
  release and runs its maintenance commands. A package that fails any check is refused
  before any of its code runs.

  The package's own upgrade.ps1 is for an install made before this launcher existed: there
  the first upgrade necessarily runs the package's code, so check the package's SHA-256
  against the value published with the release first.

.EXAMPLE
  & "$env:ProgramFiles\Sentro\current\installer\upgrade.ps1" -Package D:\sentro-r28-202610011200-abc1234-win64
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Package,
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'Sentro'),
    [string]$DataRoot = (Join-Path $env:ProgramData 'Sentro'),
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{1,30}$')][string]$ServicePrefix = 'Sentro',
    [string]$RestoreBackup,
    [string]$PublisherKeyFile,
    [switch]$AllowDowngrade,
    [switch]$AllowUnsigned
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SentroPackage.psm1') -Force
Assert-SentroAdministrator
$python = Join-Path $InstallRoot 'current\python\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw "No installed release at $InstallRoot (no current\python\python.exe)." }
$packageDir = (Resolve-Path -LiteralPath $Package).Path
$arguments = @('upgrade', '--package', $packageDir, '--install-root', $InstallRoot, '--data-root', $DataRoot,
               '--prefix', $ServicePrefix)
if ($RestoreBackup) { $arguments += @('--restore-backup', (Resolve-Path -LiteralPath $RestoreBackup).Path) }
if ($PublisherKeyFile) { $arguments += @('--publisher-key-file', (Resolve-Path -LiteralPath $PublisherKeyFile).Path) }
if ($AllowDowngrade) { $arguments += '--allow-downgrade' }
if ($AllowUnsigned) { $arguments += '--allow-unsigned' }
$code = Invoke-SentroInstaller -Python $python -Script (Join-Path $PSScriptRoot 'sentro_installer.py') `
    -Arguments $arguments -DataRoot $DataRoot -Action 'upgrade'
exit $code
