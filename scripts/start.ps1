<#
.SYNOPSIS
  Starts Sentro from this folder: the backend (API and console), then the scan worker.

.DESCRIPTION
  Before anything starts it checks, and refuses with the reason when one fails:
    - .venv exists (scripts\setup.ps1 creates it) and the configuration file exists;
    - main.py config check accepts the configuration (production refuses weak settings);
    - the database is at the schema revision this build supports (it is never upgraded here:
      run scripts\setup.ps1 or main.py migrate upgrade, with Sentro stopped);
    - the port is free and Sentro is not already running from this data root.
  The backend starts hidden, its console output in <logs>\backend.console.log; /api/ready is
  waited for; then the worker starts. Process ids go to <DataRoot>\run for scripts\stop.ps1.
  The application logs are in the DSPM_LOG_DIR the configuration names.

  This runs Sentro as the signed-in account, for evaluation and source installs. Windows
  services (start with the machine, virtual service accounts) come from the offline package:
  docs\DEPLOYMENT_WINDOWS.md.

.PARAMETER ConfigFile
  Default: data\config\sentro.toml in this folder (scripts\setup.ps1 writes it).

.PARAMETER BindHost
  The address the backend listens on. Default 127.0.0.1: publish it to other machines through
  the HTTPS reverse proxy (deploy\reverse-proxy), not by listening on every address.

.PARAMETER Port
  Default 8000.

.PARAMETER NoWorker
  Start the backend only (scans then run inside the backend).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigFile,
    [string]$BindHost = '127.0.0.1',
    [ValidateRange(1, 65535)][int]$Port = 8000,
    [switch]$NoWorker,
    [ValidateRange(10, 900)][int]$ReadyTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 turns every line a native program writes to stderr (a Python
# warning, a pip notice) into an error record, which 'Stop' makes fatal. A native command
# is judged by its exit code instead.
function Invoke-Native([scriptblock]$NativeCall) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $NativeCall } finally { $ErrorActionPreference = $previous }
}
$Root = Split-Path $PSScriptRoot -Parent
if (-not $ConfigFile) {
    $ConfigFile = if ($env:DSPM_CONFIG_FILE) { $env:DSPM_CONFIG_FILE } else { Join-Path $Root 'data\config\sentro.toml' }
}
$ConfigFile = [IO.Path]::GetFullPath($ConfigFile)

function Say([string]$Message) { Write-Host "[start] $Message" -ForegroundColor Cyan }
function Stop-Start([string]$Message) { Write-Host "[start] NOT STARTED: $Message" -ForegroundColor Red; exit 1 }

function Get-TomlValue([string]$Path, [string]$Name) {
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match "^\s*$Name\s*=\s*([""'])(.*)\1\s*$") { return $Matches[2] }
    }
    return $null
}

function Start-Detached([string[]]$Arguments, [string]$Log) {
    # cmd.exe redirects the output itself and the process starts through the shell, so it
    # inherits none of this script's handles: a caller that captures this script's output
    # (a scheduled task, a remote session) is not held open for as long as Sentro runs.
    $line = '"' + $python + '" ' + (($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    $command = '/d /c "' + $line + ' 1>"' + $Log + '" 2>&1"'
    return Start-Process -FilePath $env:ComSpec -ArgumentList $command -WorkingDirectory $Root -WindowStyle Hidden -PassThru
}

function Get-SentroProcess([string]$PidFile) {
    if (-not (Test-Path -LiteralPath $PidFile)) { return $null }
    $id = (Get-Content -LiteralPath $PidFile -Raw).Trim()
    if ($id -notmatch '^\d+$') { return $null }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
    # A recycled process id is not Sentro: it must be this folder's main.py.
    if ($process -and $process.CommandLine -and $process.CommandLine.Contains('main.py') -and
        $process.CommandLine.Contains($ConfigFile)) { return $process }
    return $null
}

$python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { Stop-Start '.venv is missing: run scripts\setup.ps1 first.' }
if (-not (Test-Path -LiteralPath $ConfigFile)) { Stop-Start "$ConfigFile does not exist: run scripts\setup.ps1 first." }

$dataRoot = Split-Path (Split-Path $ConfigFile -Parent) -Parent
$runDir = Join-Path $dataRoot 'run'
$logDir = Get-TomlValue $ConfigFile 'DSPM_LOG_DIR'
if (-not $logDir) { $logDir = Join-Path $dataRoot 'logs' }
New-Item -ItemType Directory -Force -Path $runDir, $logDir | Out-Null
$backendPid = Join-Path $runDir 'backend.pid'
$workerPid = Join-Path $runDir 'worker.pid'

if (Get-SentroProcess $backendPid) { Stop-Start "Sentro is already running from $dataRoot (scripts\stop.ps1 stops it)." }

$env:DSPM_CONFIG_FILE = $ConfigFile
Push-Location $Root
try {
    $check = Invoke-Native { & $python main.py --config $ConfigFile config check }
    if ($LASTEXITCODE -ne 0) {
        $check | Where-Object { $_ -match 'REFUSED|NOT valid' } | ForEach-Object { Write-Host "  $_" }
        Stop-Start "the configuration is refused ($ConfigFile)."
    }
    $env:DSPM_MIGRATIONS_CLI = '1'
    try {
        $raw = Invoke-Native { & $python main.py --config $ConfigFile migrate status --json 2>$null }
        $code = $LASTEXITCODE
    } finally { Remove-Item Env:\DSPM_MIGRATIONS_CLI -ErrorAction SilentlyContinue }
    if ($code -ne 0 -or -not $raw) { Stop-Start 'the database cannot be read (main.py migrate status).' }
    $status = ($raw | Out-String | ConvertFrom-Json)
    if ([int]$status.applied_revision -ne [int]$status.expected_revision) {
        if ([int]$status.applied_revision -lt [int]$status.expected_revision) {
            Stop-Start ("the database is at schema revision $($status.applied_revision) and this build needs " +
                        "$($status.expected_revision): take a backup, then run scripts\setup.ps1 (or main.py migrate upgrade).")
        }
        Stop-Start "the database is at revision $($status.applied_revision), newer than this build ($($status.expected_revision)): run the newer build."
    }
} finally { Pop-Location }

if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    Stop-Start "port $Port is already in use: stop what uses it, or pass -Port."
}

Say "Starting the backend on ${BindHost}:$Port (schema revision $($status.applied_revision))"
$backendLog = Join-Path $logDir 'backend.console.log'
$backend = Start-Detached @('main.py', '--config', $ConfigFile, 'serve', '--host', $BindHost, '--port', "$Port") $backendLog
Set-Content -LiteralPath $backendPid -Value $backend.Id -Encoding ascii

$probeHost = if ($BindHost -in @('0.0.0.0', '::', '')) { '127.0.0.1' } else { $BindHost }
$readyUrl = "http://${probeHost}:$Port/api/ready"
$deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds)
$ready = $null
$last = 'no answer'
while ((Get-Date) -lt $deadline) {
    if ($backend.HasExited) { break }
    try {
        $ready = Invoke-RestMethod -Uri $readyUrl -TimeoutSec 5 -UseBasicParsing
        if ($ready.ready) { break }
    } catch {
        $last = $_.Exception.Message
        if ($_.ErrorDetails.Message) { $last = $_.ErrorDetails.Message }
    }
    $ready = $null
    Start-Sleep -Seconds 2
}
if (-not $ready) {
    if ($backend.HasExited) { Say "The backend exited (code $($backend.ExitCode)). Its last lines:" }
    else { Say "The backend did not become ready within $ReadyTimeoutSeconds s ($last). It is still running; its last lines:" }
    Get-Content -LiteralPath $backendLog -Tail 25 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "  $_" }
    Stop-Start 'see above, and scripts\preflight.ps1.'
}
foreach ($warning in @($ready.warnings)) { if ($warning) { Say "warning: $warning" } }

if (-not $NoWorker) {
    $worker = Start-Detached @('main.py', '--config', $ConfigFile, 'worker') (Join-Path $logDir 'worker.console.log')
    Set-Content -LiteralPath $workerPid -Value $worker.Id -Encoding ascii
    Say "Scan worker started (process $($worker.Id))"
}

Say "Sentro is ready: http://${probeHost}:$Port/"
Say "  Health: http://${probeHost}:$Port/api/health   Readiness: $readyUrl"
Say "  Logs:   $logDir"
Say "  Stop:   powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1"
exit 0
