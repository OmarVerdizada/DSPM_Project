<#
.SYNOPSIS
  Install / manage a dedicated, auto-starting PostgreSQL cluster for Sentro as a Windows
  service: an initialized cluster (scram auth, 127.0.0.1 only), a least-privilege
  application role and database with the extensions Sentro needs, and the schema.

.DESCRIPTION
  Uses the PostgreSQL binaries already installed under C:\Program Files\PostgreSQL\<version>
  (install PostgreSQL first; see docs\DATABASE_SETUP.md). It creates its OWN cluster in
  -DataDir as service -ServiceName on -Port (5442 by default, so it can sit beside the cluster
  the PostgreSQL installer creates on 5432). Idempotent: re-running `install` converges.

  Secrets: the superuser and application passwords are generated with a cryptographic RNG
  and written to <DataDir>\..\credentials.env; the application's connection URL is written to
  <DataDir>\..\db_url. Both are readable by Administrators and SYSTEM only. No password is
  passed on a command line or printed: give the db_url file to scripts\setup.ps1
  -DatabaseUrlFile (source install) or packaging\windows\install.ps1 -DatabaseUrlFile.

  Security posture: listens on 127.0.0.1 only, scram-sha-256, and Sentro connects as a role
  that is not a superuser and cannot create databases or roles. A PostgreSQL server on another
  host is provisioned with scripts\provision_postgres.py instead (docs\DATABASE_SETUP.md).

.PARAMETER Command
  install    Create and start the service, provision the role and database, create the schema.
  status     Service state and connectivity.
  url        Where the application URL file is, and the URL with its password hidden.
  uninstall  Stop and remove the service (add -RemoveData to also delete the cluster).

.PARAMETER RemoveData  With uninstall, delete the data directory and the credential files.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\setup_postgres.ps1 install
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('install', 'status', 'url', 'uninstall')]
    [string]$Command = 'install',
    [int]$Port = 5442,
    [string]$DataDir = 'C:\SentroPostgres\data',
    [string]$ServiceName = 'SentroPostgres',
    [string]$Database = 'sentro',
    [string]$Role = 'sentro_app',
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent
$CredFile = Join-Path (Split-Path $DataDir -Parent) 'credentials.env'
$UrlFile = Join-Path (Split-Path $DataDir -Parent) 'db_url'

function Resolve-PgBin {
    $root = 'C:\Program Files\PostgreSQL'
    if (-not (Test-Path $root)) { throw "PostgreSQL is not installed under $root (docs\DATABASE_SETUP.md)." }
    $ver = Get-ChildItem $root -Directory | Where-Object { $_.Name -match '^\d+$' } |
        Sort-Object { [int]($_.Name) } -Descending | Select-Object -First 1
    if (-not $ver) { throw "No PostgreSQL version folder under $root." }
    return Join-Path $ver.FullName 'bin'
}

function New-Password {
    # 32 letters and digits from a cryptographic RNG (URL-safe, satisfies typical policies).
    $alphabet = [char[]](48..57 + 65..90 + 97..122)
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

function Read-Creds {
    if (-not (Test-Path $CredFile)) { return @{} }
    $h = @{}
    Get-Content $CredFile | ForEach-Object {
        if ($_ -match '^\s*([A-Z_]+)=(.*)$') { $h[$Matches[1]] = $Matches[2] }
    }
    return $h
}

function Hide-Password([string]$Url) { return ($Url -replace '(://[^:/@]+):[^@]*@', '$1:***@') }

function Get-Python {
    $venv = Join-Path $RepoRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $venv) { return $venv }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) { return $python.Source }
    throw 'Python is not available: run scripts\setup.ps1 first (it creates .venv).'
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
        if (Test-Path -LiteralPath $UrlFile) {
            Write-Output "Application URL file: $UrlFile"
            Write-Output ("DSPM_DB_URL: " + (Hide-Password (Get-Content -LiteralPath $UrlFile -Raw).Trim()))
        } else { Write-Error "No application URL file at $UrlFile (run install)." }
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
            foreach ($file in @($CredFile, $UrlFile)) { if (Test-Path $file) { Remove-Item -Force $file } }
            Write-Host "removed data and credentials"
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
            Set-Content -Path $CredFile -Encoding ascii -Value @(
                "DSPM_PG_SUPERUSER_PASSWORD=$superPw",
                "DSPM_PG_APP_PASSWORD=$appPw"
            )
            & icacls $CredFile /inheritance:r /grant "*S-1-5-32-544:F" "*S-1-5-18:F" | Out-Null
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
        $python = Get-Python

        Push-Location $RepoRoot
        try {
            # The secrets travel in this process's environment, never on a command line.
            $env:DSPM_PG_ADMIN_URL = "postgresql://postgres:$($c.DSPM_PG_SUPERUSER_PASSWORD)@127.0.0.1:$Port/postgres"
            $env:DSPM_PG_APP_PASSWORD = $c.DSPM_PG_APP_PASSWORD
            Write-Host "provisioning the least-privilege role, the database and its extensions"
            & $python -m scripts.provision_postgres --db $Database --role $Role --host 127.0.0.1 --port $Port --url-file $UrlFile |
                Where-Object { $_ -match '^\+|^=|^!' }
            if ($LASTEXITCODE -ne 0) { throw 'provisioning failed (see above)' }
        }
        finally {
            Remove-Item Env:\DSPM_PG_ADMIN_URL, Env:\DSPM_PG_APP_PASSWORD -ErrorAction SilentlyContinue
            Pop-Location
        }

        Push-Location $RepoRoot
        try {
            Write-Host "creating the schema (main.py migrate upgrade)"
            $env:DSPM_DB_URL_FILE = $UrlFile
            & $python main.py migrate upgrade
            if ($LASTEXITCODE -ne 0) { throw 'the schema could not be created (see above)' }
        }
        finally {
            Remove-Item Env:\DSPM_DB_URL_FILE -ErrorAction SilentlyContinue
            Pop-Location
        }

        Write-Host ""
        Write-Host "Sentro's PostgreSQL is installed and running (starts with Windows)."
        Write-Host "  Application URL file (DSPM_DB_URL_FILE): $UrlFile   (Administrators and SYSTEM only)"
        Write-Host "  Superuser credentials:                   $CredFile"
        Write-Host "Next: scripts\setup.ps1 -Mode production -DatabaseUrlFile `"$UrlFile`" -PublicHostName <name>"
        break
    }
}
