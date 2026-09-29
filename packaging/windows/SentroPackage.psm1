# Sentro offline package: the checks that run before any code from the package does (C11).
#
# Windows PowerShell 5.1. The install, upgrade and uninstall scripts import this module,
# prove the package is whole (and signed, when it says it is), then hand over to
# installer\sentro_installer.py under the package's own pinned Python.

Set-StrictMode -Version 2.0

function Assert-SentroAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell (Run as administrator): it creates services and sets folder permissions.'
    }
}

function Read-SentroManifest {
    param([Parameter(Mandatory)][string]$PackageDir)
    $path = Join-Path $PackageDir 'manifest.json'
    if (-not (Test-Path -LiteralPath $path)) { throw "$PackageDir is not a Sentro package (no manifest.json)." }
    return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Test-SentroPackage {
    <#
      Every file listed in SHA256SUMS must match, no file may be missing or extra, and
      SHA256SUMS itself must match the digest in lib\PackageDigest.ps1. A signed package
      must carry a valid signature by the certificate its manifest names on every script;
      an unsigned one is refused unless -AllowUnsigned says the operator accepts that.
    #>
    param([Parameter(Mandatory)][string]$PackageDir, [switch]$AllowUnsigned)
    $manifest = Read-SentroManifest -PackageDir $PackageDir
    $sumsPath = Join-Path $PackageDir 'SHA256SUMS'
    $digestPath = Join-Path $PackageDir 'lib\PackageDigest.ps1'
    if (-not (Test-Path -LiteralPath $sumsPath) -or -not (Test-Path -LiteralPath $digestPath)) {
        throw 'The package has no SHA256SUMS or lib\PackageDigest.ps1; it is incomplete.'
    }

    if ($manifest.signing.status -eq 'signed') {
        $expected = [string]$manifest.signing.thumbprint
        $scripts = Get-ChildItem -LiteralPath $PackageDir -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' }
        foreach ($script in $scripts) {
            $signature = Get-AuthenticodeSignature -LiteralPath $script.FullName
            if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $expected) {
                throw ("REFUSED: {0} is not validly signed by {1} ({2})." -f $script.Name, $expected, $signature.Status)
            }
        }
    } elseif (Test-Path -LiteralPath (Join-Path $PackageDir 'SIGNATURE.json')) {
        # D10: signed by its publisher (Ed25519). The installer checks that signature with the
        # installed release's verifier and this install's pinned publisher key before placing
        # anything; the Authenticode signature on the scripts is still HELD.
        Write-Warning ('Publisher-signed package; the installer verifies its signature against the pinned key. ' +
                       'Script Authenticode signature: HELD FOR CODE-SIGNING CERTIFICATE.')
    } elseif (-not $AllowUnsigned) {
        throw ("This package is not code-signed (HELD FOR CODE-SIGNING CERTIFICATE). Its checksums show a damaged " +
               "file but cannot prove who built it. Check the package's SHA-256 against the value published " +
               "with the release, then run again with -AllowUnsigned.")
    } else {
        Write-Warning 'Running an UNSIGNED package (-AllowUnsigned): HELD FOR CODE-SIGNING CERTIFICATE.'
    }

    # Read as text, never run: nothing from the package executes before it is verified.
    $digestText = Get-Content -LiteralPath $digestPath -Raw -Encoding UTF8
    if ($digestText -notmatch "SentroPackageSumsDigest = '([0-9a-f]{64})'") { throw 'REFUSED: lib\PackageDigest.ps1 holds no digest.' }
    $expectedSums = $Matches[1]
    $actualSums = (Get-FileHash -LiteralPath $sumsPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSums -ne $expectedSums) { throw 'REFUSED: SHA256SUMS does not match lib\PackageDigest.ps1.' }

    $listed = @{}
    foreach ($line in (Get-Content -LiteralPath $sumsPath -Encoding UTF8)) {
        if (-not $line.Trim()) { continue }
        $hash, $relative = $line -split '  ', 2
        $listed[$relative] = $true
        $file = Join-Path $PackageDir ($relative -replace '/', '\')
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "REFUSED: $relative is missing from the package." }
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $hash) { throw "REFUSED: $relative does not match SHA256SUMS; the package is damaged or altered." }
    }
    $root = (Resolve-Path -LiteralPath $PackageDir).Path.TrimEnd('\') + '\'
    foreach ($file in (Get-ChildItem -LiteralPath $PackageDir -Recurse -File)) {
        $relative = $file.FullName.Substring($root.Length) -replace '\\', '/'
        if ($relative -in 'SHA256SUMS', 'lib/PackageDigest.ps1', 'SIGNATURE.json', 'publisher.json') { continue }
        if (-not $listed.ContainsKey($relative)) { throw "REFUSED: $relative is in the package folder but not in SHA256SUMS." }
    }
    Write-Host ("[sentro] Package {0}: {1} files verified; signing: {2}." -f $manifest.label, $listed.Count, $manifest.signing.status)
    return $manifest
}

function Expand-SentroRuntime {
    <# The pinned Python, unpacked to a private temporary folder, its signature checked. #>
    param([Parameter(Mandatory)][string]$PackageDir, [Parameter(Mandatory)]$Manifest)
    $target = Join-Path $env:TEMP ('sentro-installer-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $target | Out-Null
    Expand-Archive -LiteralPath (Join-Path $PackageDir ('runtime\' + $Manifest.python.file)) -DestinationPath $target
    $python = Join-Path $target 'python.exe'
    $signature = Get-AuthenticodeSignature -LiteralPath $python
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike ('*' + $Manifest.python.authenticode_signer + '*')) {
        Remove-Item -LiteralPath $target -Recurse -Force
        throw "REFUSED: the package's python.exe is not signed by $($Manifest.python.authenticode_signer)."
    }
    return $python
}

function Invoke-SentroInstaller {
    <# Runs installer\sentro_installer.py; its output goes to the console and to a log in
       <DataRoot>\logs (or %TEMP% when the data root does not exist yet). No secret is ever
       passed on this command line: secrets are files, named by path. #>
    param([Parameter(Mandatory)][string]$Python, [Parameter(Mandatory)][string]$Script,
          [Parameter(Mandatory)][string[]]$Arguments, [Parameter(Mandatory)][string]$DataRoot, [string]$Action = 'install')
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $logDir = Join-Path $DataRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDir)) { $logDir = $env:TEMP }
    $log = Join-Path $logDir ("installer-{0}-{1}.log" -f $Action, $stamp)
    # Windows PowerShell turns a native program's stderr lines into errors, and with
    # ErrorActionPreference=Stop the first warning would abort the install half-way.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Python -X utf8 $Script @Arguments 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $finalDir = Join-Path $DataRoot 'logs'
    if ((Test-Path -LiteralPath $finalDir) -and ((Split-Path $log -Parent) -ne $finalDir)) {
        Move-Item -LiteralPath $log -Destination $finalDir -Force
        $log = Join-Path $finalDir (Split-Path $log -Leaf)
    }
    Write-Host "[sentro] Installer log: $log"
    return $code
}

function Remove-SentroRuntime {
    param([Parameter(Mandatory)][string]$Python)
    $folder = Split-Path -Parent $Python
    if ((Split-Path -Leaf $folder) -like 'sentro-installer-*') { Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue }
}

Export-ModuleMember -Function Assert-SentroAdministrator, Read-SentroManifest, Test-SentroPackage, Expand-SentroRuntime, Invoke-SentroInstaller, Remove-SentroRuntime
