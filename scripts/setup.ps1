<#
.SYNOPSIS
  Sets Sentro up from this folder: a virtual environment with the pinned packages, the
  runtime folders, generated secrets, the configuration file and the database schema.

.DESCRIPTION
  Steps, in order (each prints what it did; a failure stops the script with the reason):
    1. Find Python 3.12 or newer (-Python, else the py launcher, else python on PATH).
    2. Create .venv in this folder (once) and install the hash-locked packages:
       requirements.lock, requirements-postgres.lock and requirements-connectors.lock
       (-Minimal: requirements.lock only). -WheelDirectory installs from a local folder of
       wheels instead of the package index (an offline machine).
    3. scripts\init_install.py: the data folders, the secrets (generated once, never printed,
       never replaced) and <DataRoot>\config\sentro.toml (written once, never replaced).
       The config and secrets folders are limited to Administrators, SYSTEM and you.
    4. main.py config check.
    5. main.py migrate upgrade: an empty database is created at the current schema revision;
       an existing one is upgraded (stop Sentro and take a backup first).
    6. main.py admin ensure: the built-in administrator is created with the password in the
       secrets folder (an existing administrator is left as it is).
    7. scripts\preflight.ps1.

  It does not install Python or PostgreSQL, open firewall ports, register services, or change
  any Windows, domain or Group Policy setting. For Windows services, use the offline package
  (docs\DEPLOYMENT_WINDOWS.md).

.PARAMETER Mode
  local (default): SQLite, for evaluation and development.
  production: PostgreSQL (-DatabaseUrlFile) behind an HTTPS reverse proxy (-PublicHostName).

.PARAMETER DataRoot
  Where the database, keys, configuration, artifacts, backups, reports and logs live.
  Default: the data folder in this folder.

.PARAMETER DatabaseUrlFile
  production: a file holding the PostgreSQL application role's URL. It is copied into the
  secrets folder; delete the original afterwards. See docs\DATABASE_SETUP.md.

.PARAMETER PublicHostName
  production: the name users type, served by the reverse proxy (sentro.corp.example).

.PARAMETER Python
  The Python interpreter to build .venv from.

.PARAMETER WheelDirectory
  Install the packages from this folder of wheels (pip --no-index --find-links).

.PARAMETER Minimal
  Install requirements.lock only: no PostgreSQL driver, no SMB3/SFTP connectors.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Mode production `
      -DatabaseUrlFile C:\temp\sentro_db_url.txt -PublicHostName sentro.corp.example
#>
[CmdletBinding()]
param(
    [ValidateSet('local', 'production')][string]$Mode = 'local',
    [string]$DataRoot,
    [string]$DatabaseUrlFile,
    [string]$PublicHostName,
    [string]$Python,
    [string]$WheelDirectory,
    [switch]$Minimal,
    [ValidateRange(1, 65535)][int]$Port = 8000
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
if (-not $DataRoot) { $DataRoot = Join-Path $Root 'data' }
$DataRoot = [IO.Path]::GetFullPath($DataRoot)
$ConfigFile = Join-Path $DataRoot 'config\sentro.toml'

function Say([string]$Message) { Write-Host "[setup] $Message" -ForegroundColor Cyan }
function Stop-Setup([string]$Message) { Write-Host "[setup] FAILED: $Message" -ForegroundColor Red; exit 1 }

function Invoke-Checked([string]$What, [scriptblock]$Command) {
    Invoke-Native { & $Command 2>&1 | ForEach-Object { "$_" } }
    if ($LASTEXITCODE -ne 0) { Stop-Setup "$What (exit code $LASTEXITCODE)" }
}

function Get-PythonVersion([string[]]$Interpreter) {
    $exe = $Interpreter[0]
    $rest = @($Interpreter | Select-Object -Skip 1)
    $text = Invoke-Native { & $exe @rest -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null }
    if ($LASTEXITCODE -ne 0 -or -not $text) { return $null }
    return [version]("$text".Trim())
}

Say "Sentro folder: $Root"
Say "Data root:     $DataRoot ($Mode)"

# --- 1. Python --------------------------------------------------------------------------------
$venvPython = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    $candidates = @()
    if ($Python) { $candidates += , @($Python) }
    if (Get-Command py -ErrorAction SilentlyContinue) { $candidates += , @('py', '-3') }
    if (Get-Command python -ErrorAction SilentlyContinue) { $candidates += , @((Get-Command python).Source) }
    $base = $null
    foreach ($candidate in $candidates) {
        $version = Get-PythonVersion $candidate
        if ($version -and $version -ge [version]'3.12') { $base = $candidate; break }
    }
    if (-not $base) {
        Stop-Setup 'Python 3.12 or newer was not found. Install it (python.org, x64, "Add to PATH"), or pass -Python <path to python.exe>.'
    }
    Say "Creating .venv with $($base -join ' ') (Python $(Get-PythonVersion $base))"
    $exe = $base[0]; $rest = @($base | Select-Object -Skip 1)
    Invoke-Checked 'creating the virtual environment' { & $exe @rest -m venv (Join-Path $Root '.venv') }
}
$version = Get-PythonVersion @($venvPython)
if (-not $version -or $version -lt [version]'3.12') { Stop-Setup ".venv holds Python $version; delete .venv and run this again with Python 3.12 or newer." }
Say "Python $version in .venv"

# --- 2. packages ------------------------------------------------------------------------------
$locks = @('requirements.lock')
if (-not $Minimal) { $locks += 'requirements-postgres.lock', 'requirements-connectors.lock' }
# pysmb is published as a source archive only: pip builds it here (pure Python; pip fetches
# setuptools for the build, or finds it in -WheelDirectory).
$pipArgs =@('-m', 'pip', 'install', '--disable-pip-version-check', '--require-hashes')
if ($WheelDirectory) { $pipArgs += '--no-index', '--find-links', ([IO.Path]::GetFullPath($WheelDirectory)) }
foreach ($lock in $locks) { $pipArgs += '-r', (Join-Path $Root $lock) }
Say "Installing the hash-locked packages: $($locks -join ', ')"
Push-Location $Root
try {
    Invoke-Checked 'installing the packages' { & $venvPython @pipArgs }
} finally { Pop-Location }

# --- 3. folders, secrets, configuration ---------------------------------------------------------
$initArgs = @((Join-Path $Root 'scripts\init_install.py'), '--data-root', $DataRoot, '--mode', $Mode)
if ($DatabaseUrlFile) { $initArgs += '--db-url-file', ([IO.Path]::GetFullPath($DatabaseUrlFile)) }
if ($PublicHostName) { $initArgs += '--public-host', $PublicHostName }
$summaryText = Invoke-Native { & $venvPython @initArgs }
if ($LASTEXITCODE -ne 0) { Stop-Setup 'preparing the data root (see the message above)' }
$summary = ($summaryText | Out-String | ConvertFrom-Json)
if ($summary.created_folders.Count) { Say "Created folders under ${DataRoot}: $($summary.created_folders -join ', ')" }
if ($summary.created_secrets.Count) { Say "Generated secrets in $($summary.secrets): $($summary.created_secrets -join ', ')" }
else { Say "Reusing the secrets in $($summary.secrets)" }
if ($summary.config_written) { Say "Wrote $ConfigFile" } else { Say "Reusing $ConfigFile (not changed)" }

# Every later step reads the same configuration.
$env:DSPM_CONFIG_FILE = $ConfigFile
Push-Location $Root
try {
    # --- 4. configuration check ---------------------------------------------------------------
    $check = Invoke-Native { & $venvPython main.py --config $ConfigFile config check }
    if ($LASTEXITCODE -ne 0) {
        $check | Where-Object { $_ -match 'REFUSED|warning|NOT valid' } | ForEach-Object { Write-Host "  $_" }
        Stop-Setup "the configuration is refused: fix $ConfigFile (main.py --config `"$ConfigFile`" config check)"
    }
    Say 'Configuration is valid'

    # --- 5. database schema -------------------------------------------------------------------
    $migrated = Invoke-Native { & $venvPython main.py --config $ConfigFile migrate upgrade --json }
    if ($LASTEXITCODE -ne 0) { Stop-Setup 'the database could not be migrated (see the message above)' }
    $state = ($migrated | Select-Object -Last 1 | ConvertFrom-Json)
    Say "Database at schema revision $($state.applied_revision) (this build: $($state.expected_revision))"

    # --- 6. the built-in administrator ----------------------------------------------------------
    Invoke-Checked 'creating the built-in administrator' { & $venvPython main.py --config $ConfigFile admin ensure }
} finally { Pop-Location }

# --- 7. preflight -------------------------------------------------------------------------------
& (Join-Path $PSScriptRoot 'preflight.ps1') -ConfigFile $ConfigFile -Port $Port
$preflight = $LASTEXITCODE

Write-Host ''
Say 'Setup finished.'
Say "  Start:   powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1"
Say "  Sign in: user admin - the password is in $($summary.admin_password_file) (readable by Administrators only)."
Say "           Change it with: .venv\Scripts\python.exe main.py --config `"$ConfigFile`" admin set-password"
if ($preflight -ne 0) { Say 'Preflight reported FAIL items above: fix them before starting.'; exit 1 }
exit 0
