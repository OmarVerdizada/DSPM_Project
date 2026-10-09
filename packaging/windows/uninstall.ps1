<#
.SYNOPSIS
  Removes the Sentro services and program files. Keeps the data unless told twice.

.DESCRIPTION
  Stops and deletes <Prefix>Backend and <Prefix>Worker and removes -InstallRoot. The data
  root - the database, the keys that decrypt it, the configuration, every backup and the
  logs - is KEPT, so installing again continues from it. Deleting it needs both
  -RemoveData and -ConfirmRemoveData with the service prefix typed back; there is no
  undo, and a backup without its keys cannot be restored.

  Run it from the package folder, or from <InstallRoot>\current\installer.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -AllowUnsigned
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 -RemoveData -ConfirmRemoveData Sentro -AllowUnsigned
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = (Join-Path $env:ProgramFiles 'Sentro'),
    [string]$DataRoot = (Join-Path $env:ProgramData 'Sentro'),
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{1,30}$')][string]$ServicePrefix = 'Sentro',
    [switch]$RemoveData,
    [string]$ConfirmRemoveData = '',
    [switch]$AllowUnsigned
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\SentroPackage.psm1') -Force
Assert-SentroAdministrator
$manifest = Test-SentroPackage -PackageDir $PSScriptRoot -AllowUnsigned:$AllowUnsigned
# The runtime is unpacked to a temporary folder, so removing the install root never
# pulls the interpreter out from under the uninstaller.
$python = Expand-SentroRuntime -PackageDir $PSScriptRoot -Manifest $manifest
try {
    $arguments = @('uninstall', '--install-root', $InstallRoot, '--data-root', $DataRoot, '--prefix', $ServicePrefix)
    if ($RemoveData) { $arguments += @('--remove-data', '--confirm-remove-data', $ConfirmRemoveData) }
    $script = Join-Path $env:TEMP ('sentro-uninstall-' + [guid]::NewGuid().ToString('N') + '.py')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'installer\sentro_installer.py') -Destination $script
    $code = Invoke-SentroInstaller -Python $python -Script $script -Arguments $arguments -DataRoot $DataRoot -Action 'uninstall'
    Remove-Item -LiteralPath $script -Force -ErrorAction SilentlyContinue
} finally {
    Remove-SentroRuntime -Python $python
}
exit $code
