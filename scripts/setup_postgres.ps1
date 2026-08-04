<#
.SYNOPSIS
  Install / manage a PERSISTENT, auto-starting Sentro DSPM PostgreSQL backend as a
  Windows service (roadmap Phase 2, M2). One command sets up everything: an
  initialized cluster (scram auth), a Windows service that auto-starts on boot, a
  least-privilege application role + database, the app schema, and the DSPM_DB_URL
  the app reads.

.DESCRIPTION
  Unlike scripts/pg_dev_cluster.ps1 (a disposable dev cluster), this stands up a
  durable install the running product uses. It is idempotent - re-running
  `install` converges rather than duplicating. Generated superuser/app passwords
  are stored in a credentials file readable only by Administrators + SYSTEM.

  Security posture: the cluster listens on 127.0.0.1 only, uses scram-sha-256, and
  the app connects as a NON-superuser role. Off-host exposure, TLS, and encrypted
  volumes/backups remain deployment choices (see the Phase 2 roadmap runbook).

.PARAMETER Command
  install    Create + start the service, provision, init the schema, print DSPM_DB_URL.
  status     Service state + connectivity.
  url        Print the app DSPM_DB_URL (from the credentials file).
  uninstall  Stop + remove the service (add -RemoveData to also delete the cluster).

.PARAMETER RemoveData  With uninstall, delete the data directory + credentials.

.EXAMPLE
  ./scripts/setup_postgres.ps1 install
  # then persist the printed URL for the app:  setx DSPM_DB_URL "<url>" /M
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'status', 'url', 'uninstall')]
    [string]$Command = 'install',
    [int]$Port = 5442,
    [string]$DataDir = 'C:\SentroPostgres\data',
    [string]$ServiceName = 'SentroPostgres',
    [string]$Database = 'sentro_dev',
    [string]$Role = 'sentro_app',
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent
$CredFile = Join-Path (Split-Path $DataDir -Parent) 'credentials.env'

function Resolve-PgBin {
    $root = 'C:\Program Files\PostgreSQL'
    if (-not (Test-Path $root)) { throw "PostgreSQL not found under $root." }
    $ver = Get-ChildItem $root -Directory | Sort-Object { [int]($_.Name) } -Descending | Select-Object -First 1
    return Join-Path $ver.FullName 'bin'
}

function New-Password {
    # 28 chars, letters+digits (satisfies typical policies, URL-safe).
    -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 28 | ForEach-Object { [char]$_ })
}

function Read-Creds {
    if (-not (Test-Path $CredFile)) { return @{} }
    $h = @{}
    Get-Content $CredFile | ForEach-Object {
        if ($_ -match '^\s*([A-Z_]+)=(.*)$') { $h[$Matches[1]] = $Matches[2] }
    }
    return $h
}

$bin = Resolve-PgBin
$pgctl = Join-Path $bin 'pg_ctl.exe'
$initdb = Join-Path $bin 'initdb.exe'
$isready = Join-Path $bin 'pg_isready.exe'

switch ($Command) {

    'status' {
        $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
        Write-Host ("service " + $ServiceName + ": " + $(if ($svc) { $svc.Status } else { 'not installed' }))
        & $isready -h 127.0.0.1 -p $Port
        break
    }

    'url' {
        $c = Read-Creds
        if ($c.DSPM_DB_URL) { Write-Output $c.DSPM_DB_URL } else { Write-Error "No credentials file at $CredFile" }
        break
    }

    'uninstall' {
        $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -ne 'Stopped') { Stop-Service $ServiceName -Force }
            & sc.exe delete $ServiceName | Out-Null
            Write-Host "removed service $ServiceName"
        }
        if ($RemoveData) {
            Start-Sleep 2
            if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir }
            if (Test-Path $CredFile) { Remove-Item -Force $CredFile }
            Write-Host "removed data + credentials"
        }
        break
    }

    'install' {
        $initialized = Test-Path (Join-Path $DataDir 'PG_VERSION')

        if (-not $initialized) {
            Write-Host "initdb -> $DataDir (scram, 127.0.0.1 only)"
            $superPw = New-Password
            $appPw = New-Password
            $pwFile = Join-Path $env:TEMP ("sentro_pw_" + [guid]::NewGuid().ToString('N') + ".txt")
            try {
                # NOTE: do NOT pre-create $DataDir - initdb creates it; a pre-made
                # dir with fresh ACLs breaks initdb's permission fix-up.
                Set-Content -Path $pwFile -Value $superPw -NoNewline -Encoding ascii
                & $initdb -D $DataDir -U postgres --auth-local=scram-sha-256 --auth-host=scram-sha-256 --pwfile=$pwFile -E UTF8 | Out-Null
                if (-not (Test-Path (Join-Path $DataDir 'PG_VERSION'))) { throw "initdb failed" }
            }
            finally {
                if (Test-Path $pwFile) { Remove-Item -Force $pwFile }
            }
            $appUrl = "postgresql://$Role`:$appPw@127.0.0.1:$Port/$Database"
            Set-Content -Path $CredFile -Encoding ascii -Value @(
                "DSPM_PG_SUPERUSER_PASSWORD=$superPw",
                "DSPM_PG_APP_PASSWORD=$appPw",
                "DSPM_DB_URL=$appUrl"
            )
            & icacls $CredFile /inheritance:r /grant "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F" | Out-Null
            & icacls $DataDir /grant "NT AUTHORITY\NetworkService:(OI)(CI)F" /T /Q | Select-Object -Last 1
        }
        else {
            Write-Host "cluster already initialized at $DataDir (reusing)"
        }

        if (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
            Write-Host "registering service $ServiceName (auto-start, NetworkService)"
            & $pgctl register -N $ServiceName -U "NT AUTHORITY\NetworkService" -D $DataDir -S auto `
                -o "-p $Port -c listen_addresses=127.0.0.1" | Out-Null
        }
        if ((Get-Service $ServiceName).Status -ne 'Running') { Start-Service $ServiceName }
        for ($i = 0; $i -lt 30; $i++) { & $isready -h 127.0.0.1 -p $Port -q; if ($LASTEXITCODE -eq 0) { break }; Start-Sleep 1 }
        Write-Host ("service " + $ServiceName + ": " + (Get-Service $ServiceName).Status)

        $c = Read-Creds
        if (-not $c.DSPM_PG_APP_PASSWORD) { throw "credentials file missing app password: $CredFile" }
        $adminUrl = "postgresql://postgres:$($c.DSPM_PG_SUPERUSER_PASSWORD)@127.0.0.1:$Port/postgres"

        Push-Location $RepoRoot
        try {
            Write-Host "provisioning least-privilege role + database"
            & python -m scripts.provision_postgres --admin-url $adminUrl --db $Database --role $Role `
                --password $c.DSPM_PG_APP_PASSWORD --host 127.0.0.1 --port $Port | Where-Object { $_ -match '^\+|^=' }

            Write-Host "initializing app schema"
            $env:DSPM_DB_URL = $c.DSPM_DB_URL
            & python -c "import backend.store; print('schema ready')"
        }
        finally { Pop-Location }

        Write-Host ""
        Write-Host "Sentro PostgreSQL is installed and running (auto-starts on boot)."
        Write-Host "Point the app at it (persist machine-wide):"
        Write-Host ("    setx DSPM_DB_URL `"" + $c.DSPM_DB_URL + "`" /M")
        Write-Host "Credentials (admin-only): $CredFile"
        break
    }
}
