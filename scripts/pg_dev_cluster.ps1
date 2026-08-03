<#
.SYNOPSIS
  Stand up / tear down a LOCAL throwaway PostgreSQL cluster for developing and
  testing the Sentro DSPM Postgres backend (roadmap Phase 2, M2).

.DESCRIPTION
  Automates the manual initdb + pg_ctl dance so the whole "run the suite on
  Postgres" flow is reproducible on a Windows dev box. Uses trust auth on
  localhost only (a disposable dev cluster - NOT a production posture) and a
  spare port so it never collides with an installed PostgreSQL service.

  This is a DEV convenience. For a real deployment, run an installed/managed
  PostgreSQL and provision it with scripts/provision_postgres.py instead.

.PARAMETER Command
  up       initdb (first run) + start the cluster, then print the next steps.
  down     stop the cluster (data preserved).
  status   report whether the cluster is accepting connections.
  destroy  stop the cluster and delete its data directory.
  url      print the admin DSN for provisioning.

.PARAMETER Port     Spare TCP port (default 5441).
.PARAMETER DataDir  Cluster data directory (default %LOCALAPPDATA%\Sentro\pg-dev).
.PARAMETER PgBin    PostgreSQL bin dir (auto-detected from Program Files if omitted).

.EXAMPLE
  ./scripts/pg_dev_cluster.ps1 up
  python -m scripts.provision_postgres --admin-url postgresql://postgres@127.0.0.1:5441/postgres --port 5441
  $env:DSPM_DB_URL = 'postgresql://sentro_app:<pw>@127.0.0.1:5441/sentro_dev'
  python -m pytest tests/ -q
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('up', 'down', 'status', 'destroy', 'url')]
    [string]$Command = 'status',
    [int]$Port = 5441,
    [string]$DataDir = "$env:LOCALAPPDATA\Sentro\pg-dev",
    [string]$PgBin = ''
)

$ErrorActionPreference = 'Stop'

function Resolve-PgBin {
    param([string]$Explicit)
    if ($Explicit) {
        if (-not (Test-Path (Join-Path $Explicit 'pg_ctl.exe'))) { throw "pg_ctl.exe not found in $Explicit" }
        return $Explicit
    }
    $root = 'C:\Program Files\PostgreSQL'
    if (-not (Test-Path $root)) { throw "PostgreSQL not found under $root; pass -PgBin explicitly." }
    $ver = Get-ChildItem $root -Directory | Sort-Object { [int]($_.Name) } -Descending | Select-Object -First 1
    $bin = Join-Path $ver.FullName 'bin'
    if (-not (Test-Path (Join-Path $bin 'pg_ctl.exe'))) { throw "pg_ctl.exe not found in $bin" }
    return $bin
}

$bin = Resolve-PgBin -Explicit $PgBin
$pgctl = Join-Path $bin 'pg_ctl.exe'
$initdb = Join-Path $bin 'initdb.exe'
$isready = Join-Path $bin 'pg_isready.exe'
$adminUrl = "postgresql://postgres@127.0.0.1:$Port/postgres"

switch ($Command) {
    'url' { Write-Output $adminUrl; break }

    'status' {
        & $isready -h 127.0.0.1 -p $Port
        break
    }

    'up' {
        if (-not (Test-Path (Join-Path $DataDir 'PG_VERSION'))) {
            New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
            Write-Host "initdb -> $DataDir (trust auth, localhost only)"
            & $initdb -D $DataDir -U postgres --auth-local=trust --auth-host=trust -E UTF8 | Out-Null
        }
        # -w waits until the server accepts connections, then returns.
        & $pgctl -D $DataDir -o "-p $Port -c listen_addresses=127.0.0.1" -l (Join-Path $DataDir 'server.log') -w start
        Write-Host ""
        Write-Host "Cluster up on 127.0.0.1:$Port. Next:"
        Write-Host "  python -m scripts.provision_postgres --admin-url $adminUrl --port $Port"
        Write-Host "  # then export the printed DSPM_DB_URL and run: python -m pytest tests/ -q"
        break
    }

    'down' {
        & $pgctl -D $DataDir -m fast stop
        break
    }

    'destroy' {
        try { & $pgctl -D $DataDir -m immediate stop } catch { }
        if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir }
        Write-Host "Destroyed cluster data dir: $DataDir"
        break
    }
}
