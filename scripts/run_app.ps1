<#
.SYNOPSIS
  Development launcher: runs `main.py serve` in this console against the PostgreSQL
  cluster scripts\setup_postgres.ps1 installed.

.DESCRIPTION
  Ensures the cluster's service is running and points this process (only) at the
  application URL file setup_postgres.ps1 wrote (DSPM_DB_URL_FILE), so the database
  password is never on a command line or in the machine environment. For an install
  with a configuration file, use scripts\start.ps1 instead.

  Extra arguments pass through to `main.py serve`.

.EXAMPLE
  ./scripts/run_app.ps1 --host 127.0.0.1 --port 8000
#>
[CmdletBinding()]
param(
    [string]$ServiceName = 'SentroPostgres',
    [string]$UrlFile = 'C:\SentroPostgres\db_url',
    [Parameter(ValueFromRemainingArguments = $true)]
    $ServeArgs
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent

$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) { throw "Service '$ServiceName' not found. Run scripts/setup_postgres.ps1 install first." }
if ($svc.Status -ne 'Running') { Write-Host "starting $ServiceName"; Start-Service $ServiceName }

if (-not (Test-Path -LiteralPath $UrlFile)) { throw "Application URL file not found: $UrlFile (scripts/setup_postgres.ps1 install writes it)" }
$env:DSPM_DB_URL_FILE = $UrlFile
$url = [uri]((Get-Content -LiteralPath $UrlFile -Raw).Trim())

if (-not $ServeArgs -or $ServeArgs.Count -eq 0) { $ServeArgs = @('--host', '127.0.0.1', '--port', '8000') }

$python = Join-Path $RepoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { $python = 'python' }
Write-Host "Starting Sentro on PostgreSQL ($($url.Host):$($url.Port)$($url.AbsolutePath))"
Push-Location $RepoRoot
try { & $python main.py serve @ServeArgs }
finally { Pop-Location }
