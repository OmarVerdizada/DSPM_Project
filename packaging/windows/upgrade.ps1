<#
.SYNOPSIS
  Upgrades (or downgrades) an installed Sentro to the release in this package.

.DESCRIPTION
  Places the new release beside the running one and checks its configuration; then stops
  the worker and the backend, takes and verifies an encrypted backup, migrates the
  database, switches to the new release, starts both services and waits for /api/ready.
  A failure before the switch restarts the old release on the unchanged database; a
  failure after it rolls back to the old release and restores the backup.

  A package that expects an older database schema than the install holds is refused: code
  that old cannot run on it. Going back is -RestoreBackup with the backup taken before the
  upgrade (named in <DataRoot>\install.json), which must be at this package's schema.

  THIS SCRIPT RUNS THE PACKAGE'S OWN CODE, so it is only for an install made before the
  installed launcher existed. Every later upgrade starts from the install:
    & "$env:ProgramFiles\Sentro\current\installer\upgrade.ps1" -Package <this folder>
  which verifies the package with code the install already trusts before any of it runs.
  This script refuses to run where that launcher exists. Before using it, check the
  package's SHA-256 against the value published with the release. An install from before
  D10 pins its publisher key here with -PublisherKeyFile.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\upgrade.ps1 -AllowUnsigned
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'Sentro'),
    [string]$DataRoot = (Join-Path $env:ProgramData 'Sentro'),
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{1,30}$')][string]$ServicePrefix = 'Sentro',
    [string]$RestoreBackup,
    [string]$PublisherKeyFile,
    [switch]$AllowDowngrade,
    [switch]$AllowUnsigned
)
$ErrorActionPreference = 'Stop'
$launcher = Join-Path $InstallRoot 'current\installer\upgrade.ps1'
if (Test-Path -LiteralPath $launcher) {
    throw ("This install upgrades from its own launcher, which verifies the package before running any of it: " +
           "& `"$launcher`" -Package `"$PSScriptRoot`"")
}
Write-Warning ("Running the PACKAGE'S OWN upgrade code (an install without the installed launcher). Check this " +
               "package's SHA-256 against the value published with the release before going on.")
Import-Module (Join-Path $PSScriptRoot 'lib\SentroPackage.psm1') -Force
Assert-SentroAdministrator
$manifest = Test-SentroPackage -PackageDir $PSScriptRoot -AllowUnsigned:$AllowUnsigned
$python = Expand-SentroRuntime -PackageDir $PSScriptRoot -Manifest $manifest
try {
    $arguments = @('upgrade', '--package', $PSScriptRoot, '--install-root', $InstallRoot, '--data-root', $DataRoot,
                   '--prefix', $ServicePrefix)
    if ($RestoreBackup) { $arguments += @('--restore-backup', (Resolve-Path -LiteralPath $RestoreBackup).Path) }
    if ($PublisherKeyFile) { $arguments += @('--publisher-key-file', (Resolve-Path -LiteralPath $PublisherKeyFile).Path) }
    if ($AllowDowngrade) { $arguments += '--allow-downgrade' }
    if ($AllowUnsigned) { $arguments += '--allow-unsigned' }
    $code = Invoke-SentroInstaller -Python $python -Script (Join-Path $PSScriptRoot 'installer\sentro_installer.py') `
        -Arguments $arguments -DataRoot $DataRoot -Action 'upgrade'
} finally {
    Remove-SentroRuntime -Python $python
}
exit $code
