<#
.SYNOPSIS
  Checks that this machine and this Sentro folder are ready to run Sentro. Changes nothing.

.DESCRIPTION
  Every check prints PASS, WARN or FAIL and one line of why. Nothing is installed, created,
  migrated or started, and no secret is ever printed: secrets are reported only as present or
  missing.

  Checked: Windows and PowerShell versions, the Python interpreter (the folder's .venv when it
  exists), the Python packages of requirements.txt, CPU, memory and free disk, the runtime
  folders (writable), the configuration file and the secrets it points to, the TCP port, the
  PostgreSQL server when one is configured (reachability only), and the database's schema
  revision against the one this code supports.

  Exit code: 0 when nothing FAILed, 1 otherwise.

.PARAMETER ConfigFile
  The Sentro configuration file (TOML). Default: data\config\sentro.toml in this folder, as
  scripts\setup.ps1 writes it. The DSPM_CONFIG_FILE environment variable wins when set.

.PARAMETER Port
  The port Sentro will listen on (default 8000).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\preflight.ps1
#>
[CmdletBinding()]
param(
    [string]$ConfigFile,
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
$script:Failures = 0
$script:Warnings = 0

function Write-Check([string]$State, [string]$Name, [string]$Detail) {
    $color = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }[$State]
    Write-Host ("[{0}] {1,-34} {2}" -f $State, $Name, $Detail) -ForegroundColor $color
    if ($State -eq 'FAIL') { $script:Failures++ }
    if ($State -eq 'WARN') { $script:Warnings++ }
}

function Get-TomlSettings([string]$Path) {
    # The [settings] table of a Sentro configuration file: NAME = "value" or 'value'.
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\s*(DSPM_[A-Z0-9_]+)\s*=\s*(["''])(.*)\2\s*$') { $values[$Matches[1]] = $Matches[3] }
        elseif ($line -match '^\s*(DSPM_[A-Z0-9_]+)\s*=\s*([^#\s]+)') { $values[$Matches[1]] = $Matches[2] }
    }
    return $values
}

function Resolve-Setting([hashtable]$Settings, [string]$Name) {
    $fromEnv = [Environment]::GetEnvironmentVariable($Name)
    if ($fromEnv) { return $fromEnv }
    if ($Settings.ContainsKey($Name)) { return $Settings[$Name] }
    return $null
}

function Resolve-InRoot([string]$Path) {
    if (-not $Path) { return $null }
    if ([IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $Root $Path)
}

Write-Host "Sentro preflight - $Root" -ForegroundColor Cyan
Write-Host ""

# --- the machine ---------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$build = [int]$os.BuildNumber
if ($build -ge 17763) { Write-Check PASS 'Windows' "$($os.Caption) (build $build)" }
elseif ($build -ge 14393) { Write-Check WARN 'Windows' "$($os.Caption) (build $build): tested on Windows Server 2019 (17763) and later" }
else { Write-Check FAIL 'Windows' "$($os.Caption) (build $build): Windows Server 2016 or later is required" }

$ps = $PSVersionTable.PSVersion
if ($ps.Major -ge 5 -and ($ps.Major -gt 5 -or $ps.Minor -ge 1)) { Write-Check PASS 'PowerShell' "$ps" }
else { Write-Check FAIL 'PowerShell' "${ps}: Windows PowerShell 5.1 or later is required" }

$cpus = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$ramGb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
if ($cpus -ge 8) { Write-Check PASS 'CPU' "$cpus logical processors" }
elseif ($cpus -ge 4) { Write-Check WARN 'CPU' "$cpus logical processors: 8 or more recommended for production scans" }
else { Write-Check FAIL 'CPU' "$cpus logical processors: at least 4 are required" }
if ($ramGb -ge 16) { Write-Check PASS 'Memory' "$ramGb GB" }
elseif ($ramGb -ge 8) { Write-Check WARN 'Memory' "$ramGb GB: 16 GB recommended (32 GB for large estates)" }
else { Write-Check FAIL 'Memory' "$ramGb GB: at least 8 GB is required" }

# --- Python ---------------------------------------------------------------------------------
$venvPython = Join-Path $Root '.venv\Scripts\python.exe'
$python = $null
if (Test-Path -LiteralPath $venvPython) { $python = $venvPython }
else {
    $candidate = Get-Command python -ErrorAction SilentlyContinue
    if ($candidate) { $python = $candidate.Source }
}
if (-not $python) {
    Write-Check FAIL 'Python' 'not found: install Python 3.12 or newer, then run scripts\setup.ps1'
} else {
    $version = Invoke-Native { & $python -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null }
    $parts = "$version" -split '\.'
    if (-not $version) {
        Write-Check FAIL 'Python' "$python does not run"
    } elseif ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 12) {
        $where = if ($python -eq $venvPython) { '.venv' } else { "$python (no .venv yet: run scripts\setup.ps1)" }
        Write-Check PASS 'Python' "$version - $where"
    } else {
        Write-Check FAIL 'Python' "$version at ${python}: Python 3.12 or newer is required"
    }
    # Every package requirements.txt names, importable by this interpreter.
    $missing = Invoke-Native { & $python -c @"
import importlib.metadata as md, re, sys
missing = []
for line in open(sys.argv[1], encoding='utf-8'):
    line = line.split('#', 1)[0].strip()
    if not line or line.startswith('-'):
        continue
    name = re.split(r'[<>=!~;\[ ]', line, maxsplit=1)[0]
    try:
        md.version(name)
    except md.PackageNotFoundError:
        missing.append(name)
print(' '.join(missing))
"@ (Join-Path $Root 'requirements.txt') 2>$null }
    if ($LASTEXITCODE -ne 0) { Write-Check FAIL 'Python packages' 'could not be checked' }
    elseif ($missing) { Write-Check FAIL 'Python packages' "missing: $missing (run scripts\setup.ps1)" }
    else { Write-Check PASS 'Python packages' 'every package in requirements.txt is installed' }
}

# --- configuration ------------------------------------------------------------------------
if (-not $ConfigFile) {
    $ConfigFile = if ($env:DSPM_CONFIG_FILE) { $env:DSPM_CONFIG_FILE } else { Join-Path $Root 'data\config\sentro.toml' }
}
$settings = @{}
if (Test-Path -LiteralPath $ConfigFile) {
    $settings = Get-TomlSettings $ConfigFile
    Write-Check PASS 'Configuration file' $ConfigFile
} else {
    Write-Check FAIL 'Configuration file' "$ConfigFile not found (run scripts\setup.ps1)"
}
$mode = Resolve-Setting $settings 'DSPM_ENV'
if (-not $mode) { $mode = 'local' }
Write-Check INFO 'Mode' "DSPM_ENV=$mode"

$secretNames = @('DSPM_SECRET_KEY', 'DSPM_VAULT_KEY', 'DSPM_ARTIFACT_KEY', 'DSPM_BACKUP_KEY',
                 'DSPM_EVIDENCE_HMAC_KEY', 'DSPM_ADMIN_PASSWORD')
if ($mode -in @('prod', 'production')) { $secretNames += 'DSPM_DB_URL' }
foreach ($name in $secretNames) {
    if ($name -eq 'DSPM_ADMIN_PASSWORD' -and $mode -notin @('prod', 'production') -and
        -not (Resolve-Setting $settings $name) -and -not (Resolve-Setting $settings "$($name)_FILE")) {
        $name = 'DSPM_DEV_ADMIN_PASSWORD'  # a local install's administrator password
    }
    $direct = Resolve-Setting $settings $name
    $file = Resolve-InRoot (Resolve-Setting $settings "$($name)_FILE")
    if ($direct) {
        Write-Check WARN $name "set directly: prefer a protected file through $($name)_FILE"
    } elseif ($file -and (Test-Path -LiteralPath $file)) {
        if ((Get-Item -LiteralPath $file).Length -gt 0) { Write-Check PASS $name "present (file)" }
        else { Write-Check FAIL $name "the file named by $($name)_FILE is empty" }
    } elseif ($file) {
        Write-Check FAIL $name "the file named by $($name)_FILE does not exist"
    } elseif ($mode -in @('prod', 'production')) {
        Write-Check FAIL $name 'missing: required in production'
    } else {
        Write-Check WARN $name 'not configured: a local install generates it on first start'
    }
}

# --- runtime folders and disk ---------------------------------------------------------------
$floorMb = [int](Resolve-Setting $settings 'DSPM_MIN_FREE_DISK_MB')
if (-not $floorMb) { $floorMb = 2048 }
# The data root: the folder holding config\sentro.toml when the file is laid out that way.
$dataRoot = Join-Path $Root 'data'
if ((Split-Path (Split-Path $ConfigFile -Parent) -Leaf) -eq 'config') { $dataRoot = Split-Path (Split-Path $ConfigFile -Parent) -Parent }
$folders = [ordered]@{
    'Data root' = $dataRoot
    'DSPM_ARTIFACT_DIR' = (Resolve-InRoot (Resolve-Setting $settings 'DSPM_ARTIFACT_DIR'))
    'DSPM_REPORT_DIR' = (Resolve-InRoot (Resolve-Setting $settings 'DSPM_REPORT_DIR'))
    'DSPM_SCAN_CACHE_DIR' = (Resolve-InRoot (Resolve-Setting $settings 'DSPM_SCAN_CACHE_DIR'))
    'DSPM_BACKUP_DIR' = (Resolve-InRoot (Resolve-Setting $settings 'DSPM_BACKUP_DIR'))
    'DSPM_LOG_DIR' = (Resolve-InRoot (Resolve-Setting $settings 'DSPM_LOG_DIR'))
}
foreach ($entry in $folders.GetEnumerator()) {
    if (-not $entry.Value) { continue }
    $folder = $entry.Value
    $probeBase = $folder
    while ($probeBase -and -not (Test-Path -LiteralPath $probeBase)) { $probeBase = Split-Path $probeBase -Parent }
    if (-not $probeBase) { Write-Check FAIL $entry.Key "${folder}: no existing parent folder"; continue }
    $probe = Join-Path $probeBase ".sentro-preflight-$PID.tmp"
    try {
        [IO.File]::WriteAllText($probe, 'probe')
        Remove-Item -LiteralPath $probe -Force
        $state = if (Test-Path -LiteralPath $folder) { 'writable' } else { 'created on first start (parent writable)' }
        Write-Check PASS $entry.Key "$folder - $state"
    } catch {
        Write-Check FAIL $entry.Key "$folder is not writable by $env:USERNAME"
    }
}
$diskBase = $dataRoot
while ($diskBase -and -not (Test-Path -LiteralPath $diskBase)) { $diskBase = Split-Path $diskBase -Parent }
if (-not $diskBase) { $diskBase = $Root }
$drive = (Get-Item -LiteralPath $diskBase).PSDrive
$freeMb = [math]::Floor($drive.Free / 1MB)
if ($freeMb -ge ($floorMb + 20480)) { Write-Check PASS 'Free disk' "$freeMb MB on $($drive.Name): (floor $floorMb MB)" }
elseif ($freeMb -ge ($floorMb + 2048)) { Write-Check WARN 'Free disk' "$freeMb MB on $($drive.Name): - scans pause below $floorMb MB; 20 GB or more above it recommended" }
else { Write-Check FAIL 'Free disk' "$freeMb MB on $($drive.Name): - scans pause below the $floorMb MB floor (DSPM_MIN_FREE_DISK_MB)" }

# --- network -------------------------------------------------------------------------------
$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    $owner = (Get-Process -Id $listener[0].OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Write-Check WARN "Port $Port" "already listening (process $owner): Sentro itself, or another service?"
} else {
    Write-Check PASS "Port $Port" 'free'
}

$dbUrlFile = Resolve-InRoot (Resolve-Setting $settings 'DSPM_DB_URL_FILE')
$dbUrl = Resolve-Setting $settings 'DSPM_DB_URL'
if (-not $dbUrl -and $dbUrlFile -and (Test-Path -LiteralPath $dbUrlFile)) { $dbUrl = (Get-Content -LiteralPath $dbUrlFile -Raw).Trim() }
if ($dbUrl -and $python) {
    Invoke-Native { & $python -c "import psycopg, psycopg_pool" 2>$null }
    if ($LASTEXITCODE -eq 0) { Write-Check PASS 'PostgreSQL driver' 'psycopg and psycopg_pool are installed' }
    else { Write-Check FAIL 'PostgreSQL driver' 'not installed: run scripts\setup.ps1 without -Minimal' }
}
if ($dbUrl) {
    try {
        $uri = [Uri]$dbUrl
        $pgPort = if ($uri.Port -gt 0) { $uri.Port } else { 5432 }
        $client = New-Object Net.Sockets.TcpClient
        $connect = $client.BeginConnect($uri.Host, $pgPort, $null, $null)
        if ($connect.AsyncWaitHandle.WaitOne(3000) -and $client.Connected) {
            Write-Check PASS 'PostgreSQL' "reachable at $($uri.Host):$pgPort (database $($uri.AbsolutePath.TrimStart('/')))"
        } else {
            Write-Check FAIL 'PostgreSQL' "$($uri.Host):$pgPort does not answer"
        }
        $client.Close()
    } catch {
        Write-Check FAIL 'PostgreSQL' 'DSPM_DB_URL is not a valid URL'
    }
} else {
    $dbPath = Resolve-InRoot (Resolve-Setting $settings 'DSPM_DB_PATH')
    if (-not $dbPath) { $dbPath = Join-Path $Root 'data\dspm.sqlite' }
    if ($mode -in @('prod', 'production')) { Write-Check FAIL 'Database' 'production requires PostgreSQL (DSPM_DB_URL_FILE)' }
    Write-Check INFO 'Database' "SQLite at $dbPath (evaluation; production uses PostgreSQL)"
}

# --- the schema ----------------------------------------------------------------------------
if ($python) {
    $previousCli = $env:DSPM_MIGRATIONS_CLI
    $previousConfig = $env:DSPM_CONFIG_FILE
    try {
        # Read-only: with DSPM_MIGRATIONS_CLI set, importing the store never upgrades a database.
        $env:DSPM_MIGRATIONS_CLI = '1'
        if (Test-Path -LiteralPath $ConfigFile) { $env:DSPM_CONFIG_FILE = $ConfigFile }
        Push-Location $Root
        $raw = Invoke-Native { & $python main.py migrate status --json 2>$null }
        $code = $LASTEXITCODE
        Pop-Location
        if ($code -ne 0 -or -not $raw) {
            Write-Check WARN 'Schema' 'not readable yet (no database, or the configuration is refused - run main.py config check)'
        } else {
            $status = ($raw | Out-String | ConvertFrom-Json)
            $applied = [int]$status.applied_revision
            $expected = [int]$status.expected_revision
            if ($applied -eq $expected) { Write-Check PASS 'Schema' "revision $applied (this build supports $expected)" }
            elseif ($applied -eq 0) { Write-Check WARN 'Schema' "no schema yet: scripts\setup.ps1 (or main.py migrate upgrade) creates revision $expected" }
            elseif ($applied -lt $expected) { Write-Check WARN 'Schema' "revision $applied, this build supports ${expected}: run main.py migrate upgrade with Sentro stopped" }
            else { Write-Check FAIL 'Schema' "revision $applied is newer than this build ($expected): run the newer build" }
        }
    } finally {
        $env:DSPM_MIGRATIONS_CLI = $previousCli
        $env:DSPM_CONFIG_FILE = $previousConfig
    }
}

Write-Host ""
if ($script:Failures -gt 0) {
    Write-Host "preflight: $($script:Failures) FAIL, $($script:Warnings) WARN" -ForegroundColor Red
    exit 1
}
Write-Host "preflight: no FAIL, $($script:Warnings) WARN" -ForegroundColor Green
exit 0
