<#
.SYNOPSIS
  Stops the Sentro processes scripts\start.ps1 started: the scan worker, then the backend.

.DESCRIPTION
  Only the processes recorded in <DataRoot>\run whose command line is this install's
  main.py with this configuration are stopped - never another Python process, and never a
  Sentro installed as Windows services (stop those with Stop-Service). A scan that was
  running is resumed from its last finished partition when Sentro starts again.

.PARAMETER ConfigFile
  Default: data\config\sentro.toml in this folder.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
#>
[CmdletBinding()]
param([string]$ConfigFile)

$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
if (-not $ConfigFile) {
    $ConfigFile = if ($env:DSPM_CONFIG_FILE) { $env:DSPM_CONFIG_FILE } else { Join-Path $Root 'data\config\sentro.toml' }
}
$ConfigFile = [IO.Path]::GetFullPath($ConfigFile)
$runDir = Join-Path (Split-Path (Split-Path $ConfigFile -Parent) -Parent) 'run'

$stopped = 0
foreach ($name in @('worker', 'backend')) {
    $pidFile = Join-Path $runDir "$name.pid"
    if (-not (Test-Path -LiteralPath $pidFile)) { continue }
    $id = (Get-Content -LiteralPath $pidFile -Raw).Trim()
    $process = $null
    if ($id -match '^\d+$') { $process = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue }
    if ($process -and $process.CommandLine -and $process.CommandLine.Contains('main.py') -and
        $process.CommandLine.Contains($ConfigFile)) {
        # The whole tree: .venv's python.exe is a launcher whose child is the interpreter, and
        # a scan's detector processes are children too.
        $null = & cmd.exe /c "taskkill /PID $id /T /F >nul 2>&1"
        Write-Host "[stop] Stopped the $name (process $id)" -ForegroundColor Cyan
        $stopped++
    } else {
        Write-Host "[stop] The $name recorded in $pidFile is no longer running" -ForegroundColor Gray
    }
    Remove-Item -LiteralPath $pidFile -Force
}
if ($stopped -eq 0) { Write-Host '[stop] Sentro was not running from this folder.' -ForegroundColor Gray }
exit 0
