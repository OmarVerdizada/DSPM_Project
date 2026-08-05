<#
.SYNOPSIS
  Launch the Sentro DSPM app against the persistent PostgreSQL backend
  (roadmap Phase 2, M2).

.DESCRIPTION
  Ensures the SentroPostgres service is running, loads DSPM_DB_URL from the
  admin-only credentials file, and starts the app with that env set for THIS
  process only - so the database password never lands in the global machine
  environment (a security-product-appropriate alternative to `setx /M`).

  Extra arguments pass through to `main.py serve`.

.EXAMPLE
  ./scripts/run_app.ps1 --host 127.0.0.1 --port 8000
#>
[CmdletBinding()]
param(
    [string]$ServiceName = 'SentroPostgres',
    [string]$CredFile = 'C:\SentroPostgres\credentials.env',
    [Parameter(ValueFromRemainingArguments = $true)]
    $ServeArgs
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent

$svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) { throw "Service '$ServiceName' not found. Run scripts/setup_postgres.ps1 install first." }
if ($svc.Status -ne 'Running') { Write-Host "starting $ServiceName"; Start-Service $ServiceName }

if (-not (Test-Path $CredFile)) { throw "Credentials file not found: $CredFile" }
$url = ((Get-Content $CredFile | Where-Object { $_ -match '^DSPM_DB_URL=' }) -replace '^DSPM_DB_URL=', '').Trim()
if (-not $url) { throw "DSPM_DB_URL missing from $CredFile" }
$env:DSPM_DB_URL = $url

if (-not $ServeArgs -or $ServeArgs.Count -eq 0) { $ServeArgs = @('--host', '127.0.0.1', '--port', '8000') }

Write-Host "Starting Sentro DSPM on PostgreSQL (DB host: $((([uri]$url).Host)):$((([uri]$url).Port)))"
Push-Location $RepoRoot
try { & python main.py serve @ServeArgs }
finally { Pop-Location }
