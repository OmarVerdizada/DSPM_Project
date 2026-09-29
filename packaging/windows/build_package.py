"""Build the offline Windows package of Sentro (C11).

    python packaging/windows/build_package.py [--ref HEAD] [--out dist]

Produces dist/sentro-<label>-win64/ and the same as a .zip, holding everything an install
needs with no Internet: the product source at --ref (tracked files only), the pinned
embeddable Python, every wheel of requirements.lock and requirements-postgres.lock, the
WinSW service wrapper, and the installer. Every third-party file is checked against
packaging/windows/pins.json and every wheel against the locks' hashes before it is copied.

The package carries:
  manifest.json   what it is - commit, schema revision, runtime, wheels, signing status
  SHA256SUMS      the digest of every file; the installer refuses a package that differs
  lib/PackageDigest.ps1   the digest of SHA256SUMS - the file a signature makes trustworthy

Signing: with SENTRO_SIGNING_CERT_THUMBPRINT set (a code-signing certificate in the
current user's or machine's store), every script is Authenticode-signed and the manifest
says "signed". Without it the package says "unsigned" and the installer refuses it unless
told -AllowUnsigned: HELD FOR CODE-SIGNING CERTIFICATE. Nothing here makes or uses a
self-signed certificate to look signed.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PRODUCT_PATHS = ("backend", "frontend", "classification", "discovery", "collectors", "permissions", "risk",
                 "scripts", "main.py", "pyproject.toml", "requirements.txt", "requirements.lock",
                 "requirements-postgres.txt", "requirements-postgres.lock", ".env.example", "README.md",
                 "deploy/reverse-proxy")
LOCKS = ("requirements.lock", "requirements-postgres.lock")
INSTALLER_FILES = ("install.ps1", "upgrade.ps1", "uninstall.ps1")
UNSIGNED_NOTE = ("HELD FOR CODE-SIGNING CERTIFICATE: no certificate was configured (SENTRO_SIGNING_CERT_THUMBPRINT). "
                 "SHA256SUMS detects a damaged file, not a deliberate substitution; verify the package's own "
                 "SHA-256 against the value published with the release before installing.")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()


def fetch(pin: dict, cache: Path) -> Path:
    """The pinned file from the cache, downloaded once; refused if its digest differs."""
    path = cache / pin["file"]
    if not path.exists():
        print(f"downloading {pin['url']}")
        with urllib.request.urlopen(pin["url"], timeout=300) as response, open(path, "wb") as out:
            shutil.copyfileobj(response, out)
    actual = sha256(path)
    if actual != pin["sha256"]:
        raise SystemExit(f"REFUSED: {path.name} has SHA-256 {actual}, the pin says {pin['sha256']}.")
    return path


def authenticode(path: Path) -> tuple[str, str]:
    script = (f"$s = Get-AuthenticodeSignature -LiteralPath '{path}'; "
              "Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Subject)")
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                         capture_output=True, text=True, check=True).stdout.strip()
    status, _, subject = out.partition("|")
    return status, subject


def export_source(ref: str, dest: Path) -> list[str]:
    """The tracked product files at `ref` - never the working tree's untracked ones."""
    present = [path for path in PRODUCT_PATHS if git("ls-tree", "--name-only", ref, "--", path)]
    archive = subprocess.run(["git", "archive", "--format=tar", ref, "--", *present], cwd=REPO,
                             capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")
    for leftover in dest.rglob("*.bak"):
        leftover.unlink()
    return present


def schema_revision(app: Path) -> int:
    probe = ("import os, sys, tempfile; os.environ['DSPM_MIGRATIONS_CLI'] = '1'; "
             "os.environ['DSPM_DB_PATH'] = os.path.join(tempfile.mkdtemp(), 'probe.sqlite'); "
             "sys.path.insert(0, os.getcwd()); from backend import migrations; print(migrations.expected_revision())")
    env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
    out = subprocess.run([sys.executable, "-c", probe], cwd=app, capture_output=True, text=True, env=env)
    if out.returncode != 0:
        raise SystemExit(f"Could not read the schema revision of the exported source: {out.stderr[-800:]}")
    return int(out.stdout.strip().splitlines()[-1])


def build_wheelhouse(app: Path, cache: Path, dest: Path, python_version: str) -> list[dict]:
    """Every locked distribution for this runtime, hash-checked by pip against the locks."""
    locks = [app / name for name in LOCKS if (app / name).exists()]
    key = hashlib.sha256(b"".join(path.read_bytes() for path in locks) + python_version.encode()).hexdigest()[:16]
    downloads = cache / f"downloads-{key}"
    downloads.mkdir(parents=True, exist_ok=True)
    major_minor = ".".join(python_version.split(".")[:2])
    abi = "cp" + major_minor.replace(".", "")
    lock_args = [item for lock in locks for item in ("-r", str(lock))]
    subprocess.run([sys.executable, "-m", "pip", "download", "--quiet", "--no-deps", "--require-hashes",
                    "--platform", "win_amd64", "--python-version", major_minor, "--implementation", "cp",
                    "--abi", abi, "-d", str(downloads), *lock_args], check=True)
    dest.mkdir(parents=True, exist_ok=True)
    wheels: list[dict] = []
    for item in sorted(downloads.iterdir()):
        if item.suffix == ".whl":
            shutil.copy2(item, dest / item.name)
            wheels.append({"file": item.name, "sha256": sha256(item), "source": "PyPI wheel; its hash is in the lock"})
            continue
        # A package that publishes no wheel (pysmb 1.2.10): build one from the source
        # archive pip just checked against the lock, and say so.
        built = cache / f"built-{key}"
        built.mkdir(exist_ok=True)
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--quiet", "--no-deps", "-w", str(built), str(item)],
                       check=True)
        stem = item.name.split("-")[0].lower()
        wheel = next(path for path in built.iterdir() if path.name.lower().startswith(stem) and path.suffix == ".whl")
        shutil.copy2(wheel, dest / wheel.name)
        wheels.append({"file": wheel.name, "sha256": sha256(wheel),
                       "source": f"built here from {item.name} (sha256 {sha256(item)}, the hash in the lock); "
                                 "the project publishes no wheel for this version"})
    lines = ["# Generated by build_package.py: the exact files in this wheelhouse, by digest.",
             "# The installer runs pip with --no-index --require-hashes on this list."]
    for wheel in wheels:
        name, version = wheel["file"].split("-")[:2]
        lines.append(f"{name}=={version} --hash=sha256:{wheel['sha256']}")
    (dest / "install-requirements.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return wheels


def sign_scripts(stage: Path, thumbprint: str, only: Path | None = None) -> None:
    scripts = [only] if only else [path for path in stage.rglob("*") if path.suffix in {".ps1", ".psm1"}]
    listing = ",".join(f"'{path}'" for path in scripts)
    command = (r"$c = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My | "
               f"Where-Object {{ $_.Thumbprint -eq '{thumbprint}' -and $_.HasPrivateKey }} | Select-Object -First 1; "
               "if (-not $c) { throw 'No code-signing certificate with that thumbprint and a private key.' }; "
               f"$ts = $env:SENTRO_SIGNING_TIMESTAMP_URL; foreach ($f in @({listing})) {{ "
               "if ($ts) { $r = Set-AuthenticodeSignature -FilePath $f -Certificate $c -TimestampServer $ts -HashAlgorithm SHA256 } "
               "else { $r = Set-AuthenticodeSignature -FilePath $f -Certificate $c -HashAlgorithm SHA256 }; "
               "if ($r.Status -ne 'Valid') { throw ('Signing failed for ' + $f + ': ' + $r.StatusMessage) } }")
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], check=True)


def write_sums(stage: Path) -> str:
    rows = []
    for path in sorted(stage.rglob("*")):
        relative = path.relative_to(stage).as_posix()
        if path.is_file() and relative not in {"SHA256SUMS", "lib/PackageDigest.ps1"}:
            rows.append(f"{sha256(path)}  {relative}")
    sums = stage / "SHA256SUMS"
    sums.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return sha256(sums)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ref", default="HEAD", help="git ref whose tracked product files are packaged")
    parser.add_argument("--out", type=Path, default=REPO / "dist")
    parser.add_argument("--cache", type=Path, default=Path(tempfile.gettempdir()) / "sentro-build-cache")
    parser.add_argument("--no-zip", action="store_true", help="leave the folder only (a local install test)")
    parser.add_argument("--sign-key", type=Path, default=os.getenv("SENTRO_PACKAGE_SIGNING_KEY") or None,
                        help="the publisher's Ed25519 key (D10); scripts/sentro_sign.py keygen makes one")
    args = parser.parse_args(argv)

    pins = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
    args.cache.mkdir(parents=True, exist_ok=True)
    commit = git("rev-parse", args.ref)
    commit_time = int(git("show", "-s", "--format=%ct", commit))
    staging = Path(tempfile.mkdtemp(prefix="sentro-package-"))
    try:
        app = staging / "app"
        app.mkdir()
        paths = export_source(commit, app)
        revision = schema_revision(app)
        label = f"r{revision}-{datetime.fromtimestamp(commit_time, timezone.utc):%Y%m%d%H%M}-{commit[:10]}"
        (app / "BUILD.json").write_text(json.dumps({"label": label, "commit": commit, "commit_time": commit_time,
                                                    "schema_revision": revision}, indent=2) + "\n", encoding="utf-8")

        runtime = fetch(pins["python"], args.cache)
        with tempfile.TemporaryDirectory() as check:
            with zipfile.ZipFile(runtime) as archive:
                archive.extract("python.exe", check)
            status, subject = authenticode(Path(check) / "python.exe")
            if status != "Valid" or pins["python"]["authenticode_signer"] not in subject:
                raise SystemExit(f"REFUSED: python.exe in {runtime.name} is {status} ({subject}).")
        (staging / "runtime").mkdir()
        shutil.copy2(runtime, staging / "runtime" / runtime.name)
        winsw = fetch(pins["winsw"], args.cache)
        (staging / "bin").mkdir()
        shutil.copy2(winsw, staging / "bin" / "WinSW-x64.exe")
        license_pin = {"file": pins["winsw"]["license_file"], "url": pins["winsw"]["license_url"],
                       "sha256": pins["winsw"]["license_sha256"]}
        (staging / "third_party").mkdir()
        shutil.copy2(fetch(license_pin, args.cache), staging / "third_party" / "WinSW-LICENSE.txt")

        wheels = build_wheelhouse(app, args.cache, staging / "wheelhouse", pins["python"]["version"])
        pip_wheel = staging / "wheelhouse" / pins["pip"]["file"]
        shutil.copy2(fetch({**pins["pip"], "url": f"https://files.pythonhosted.org/packages/py3/p/pip/{pins['pip']['file']}"},
                           args.cache), pip_wheel)

        (staging / "installer").mkdir()
        shutil.copy2(HERE / "sentro_installer.py", staging / "installer" / "sentro_installer.py")
        for name in INSTALLER_FILES:
            shutil.copy2(HERE / name, staging / name)
        (staging / "lib").mkdir()
        shutil.copy2(HERE / "SentroPackage.psm1", staging / "lib" / "SentroPackage.psm1")
        (staging / "docs").mkdir()
        shutil.copy2(REPO / "docs" / "DEPLOYMENT_WINDOWS.md", staging / "docs" / "DEPLOYMENT_WINDOWS.md")

        thumbprint = os.getenv("SENTRO_SIGNING_CERT_THUMBPRINT", "").strip()
        manifest = {
            "product": "Sentro DSPM", "label": label, "commit": commit, "commit_time": commit_time,
            "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "schema_revision": revision,
            "source_paths": paths,
            "python": {key: pins["python"][key] for key in ("version", "file", "sha256", "authenticode_signer")},
            "pip": {key: pins["pip"][key] for key in ("version", "file", "sha256")},
            "winsw": {key: pins["winsw"][key] for key in ("version", "file", "sha256", "license")} | {"signed_upstream": False},
            "wheels": wheels,
            "signing": ({"status": "signed", "thumbprint": thumbprint.upper()} if thumbprint
                        else {"status": "unsigned", "note": UNSIGNED_NOTE}),
        }
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        # Order matters: the scripts are signed, then SHA256SUMS covers every file (signed
        # scripts included), then the digest file names SHA256SUMS and is signed last - so
        # one valid signature vouches for the whole package.
        if thumbprint:
            sign_scripts(staging, thumbprint)
        sums_digest = write_sums(staging)
        digest_script = staging / "lib" / "PackageDigest.ps1"
        digest_script.write_text("# Written by build_package.py. The SHA-256 of SHA256SUMS; a signature on this\n"
                                 "# file is what makes the checksums - and so every file - trustworthy.\n"
                                 f"$SentroPackageSumsDigest = '{sums_digest}'\n", encoding="utf-8")
        if thumbprint:
            sign_scripts(staging, thumbprint, only=digest_script)
        if args.sign_key:
            # D10: the publisher's signature over what the package is and SHA256SUMS - checked by
            # the installer against the key the install pinned, never the key the package carries.
            sys.path.insert(0, str(REPO / "scripts"))
            import sentro_sign

            envelope = sentro_sign.sign_package(sentro_sign.load_private_key(Path(args.sign_key)), staging)
            print(f"publisher signature: key {envelope['key_id']}")

        args.out.mkdir(parents=True, exist_ok=True)
        final = args.out / f"sentro-{label}-win64"
        if final.exists():
            shutil.rmtree(final)
        shutil.move(str(staging), final)
        staging = final
        print(f"package folder: {final}")
        print(f"schema revision {revision}; {len(wheels)} wheels; signing: {manifest['signing']['status']}")
        if not args.no_zip:
            archive = shutil.make_archive(str(final), "zip", root_dir=final.parent, base_dir=final.name)
            digest = sha256(Path(archive))
            Path(archive + ".sha256").write_text(f"{digest}  {Path(archive).name}\n", encoding="utf-8")
            print(f"package: {archive}\nsha256:  {digest}")
    finally:
        if staging.name.startswith("sentro-package-") and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
