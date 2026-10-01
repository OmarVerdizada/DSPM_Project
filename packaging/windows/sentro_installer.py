"""Install, upgrade, downgrade and uninstall Sentro as Windows services (C11).

Runs under the package's own Python (the pinned embeddable runtime) after the PowerShell
entry point has checked the package's checksums and signature. Standard library only:
nothing here may depend on what it is installing.

Layout (every name derives from the install root, data root and service prefix, so a
second, isolated install beside the first is only a different prefix and two paths):

    <InstallRoot>\\releases\\<label>\\{python,app,manifest.json}  one per release, side by side
    <InstallRoot>\\current                                       junction to the running release
    <InstallRoot>\\bin\\<Prefix>Backend.exe|.xml, <Prefix>Worker.exe|.xml   the service wrapper
    <DataRoot>\\config\\sentro.toml     the one configuration file (no secrets in it)
    <DataRoot>\\secrets\\*              keys and passwords, one per file, ACL: service read-only
    <DataRoot>\\{db,artifacts,backups,cache,reports,logs}
    <DataRoot>\\install.json            what is installed, and its history (no secrets)

Upgrade: place the new release beside the old -> check its configuration -> stop the
worker, then the backend -> take and verify an encrypted backup -> migrate -> switch
`current` -> start -> wait for /api/ready -> done. The maintenance steps run the NEW
release's commands, which open the database without converging its schema, so the
release being replaced needs none of them.
Any failure before the switch restarts the old release untouched; a failure after it
rolls back to the old release and restores the backup. Downgrade: refused when the
package expects an older schema than the database holds, unless it is given the backup
that was taken at that schema. Uninstall keeps the data root (database, keys, backups,
logs) unless removal is asked for twice: --remove-data and the prefix typed back.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRODUCT = "Sentro"
PYTHON_PTH = "python314._pth"
READY_TIMEOUT_SECONDS = 180
STOP_TIMEOUT_SECONDS = 60


class InstallError(RuntimeError):
    """Stops the operation; the message says what happened and what to do."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def say(message: str) -> None:
    print(f"[sentro] {message}", flush=True)


# ---- the layout -----------------------------------------------------------------
@dataclass(frozen=True)
class Layout:
    install_root: Path
    data_root: Path
    prefix: str

    @property
    def releases(self) -> Path:
        return self.install_root / "releases"

    @property
    def current(self) -> Path:
        return self.install_root / "current"

    @property
    def bin(self) -> Path:
        return self.install_root / "bin"

    @property
    def config_file(self) -> Path:
        return self.data_root / "config" / "sentro.toml"

    @property
    def secrets(self) -> Path:
        return self.data_root / "secrets"

    @property
    def state_file(self) -> Path:
        return self.data_root / "install.json"

    @property
    def trust_file(self) -> Path:
        """The publisher keys this install trusts (D10). Pinned at install; a package never replaces it."""
        return self.data_root / "trust" / "publishers.json"

    @property
    def backend(self) -> str:
        return f"{self.prefix}Backend"

    @property
    def worker(self) -> str:
        return f"{self.prefix}Worker"

    @property
    def services(self) -> tuple[str, str]:
        return (self.backend, self.worker)

    def service_account(self, service: str) -> str:
        return f"NT SERVICE\\{service}"

    def data_dirs(self) -> list[Path]:
        return [self.data_root / name for name in
                ("config", "secrets", "trust", "db", "artifacts", "backups", "cache", "reports", "logs",
                 "logs/service")]


def read_state(layout: Layout) -> dict | None:
    if not layout.state_file.exists():
        return None
    return json.loads(layout.state_file.read_text(encoding="utf-8"))


def write_state(layout: Layout, state: dict) -> None:
    temporary = layout.state_file.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, layout.state_file)


def read_manifest(folder: Path) -> dict:
    path = folder / "manifest.json"
    if not path.exists():
        raise InstallError(f"{folder} is not a Sentro package or release (no manifest.json).")
    return json.loads(path.read_text(encoding="utf-8"))


# ---- running things ------------------------------------------------------------
class Runner:
    """Every external command goes through here (tests replace it)."""

    def run(self, args: list[str], *, env: dict | None = None, cwd: Path | None = None,
            check: bool = True, timeout: int = 1800) -> subprocess.CompletedProcess:
        completed = subprocess.run([str(arg) for arg in args], env=env, cwd=cwd, capture_output=True,
                                   encoding="utf-8", errors="replace", timeout=timeout)
        if check and completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()[-1500:]
            raise InstallError(f"{Path(str(args[0])).name} {' '.join(str(a) for a in args[1:3])} failed "
                               f"(exit {completed.returncode}): {detail}")
        return completed


class Services:
    """The two Windows services, through the WinSW wrapper and sc.exe."""

    def __init__(self, layout: Layout, runner: Runner) -> None:
        self.layout = layout
        self.runner = runner

    def wrapper(self, name: str) -> Path:
        return self.layout.bin / f"{name}.exe"

    def exists(self, name: str) -> bool:
        return self.runner.run(["sc.exe", "query", name], check=False).returncode == 0

    def state(self, name: str) -> str:
        completed = self.runner.run(["sc.exe", "query", name], check=False)
        for line in completed.stdout.splitlines():
            if "STATE" in line:
                return line.split()[-1]
        return "MISSING"

    def register(self, name: str, xml: str, wrapper_source: Path) -> None:
        self.layout.bin.mkdir(parents=True, exist_ok=True)
        shutil.copy2(wrapper_source, self.wrapper(name))
        (self.layout.bin / f"{name}.xml").write_text(xml, encoding="utf-8")
        self.runner.run([self.wrapper(name), "install"])
        # A virtual account per service: no password, no rights beyond what is granted
        # on the install and data roots.
        self.runner.run(["sc.exe", "config", name, "obj=", self.layout.service_account(name)])

    def unregister(self, name: str) -> None:
        if not self.exists(name):
            return
        self.stop(name)
        if self.wrapper(name).exists():
            self.runner.run([self.wrapper(name), "uninstall"], check=False)
        if self.exists(name):
            self.runner.run(["sc.exe", "delete", name], check=False)
        for suffix in (".exe", ".xml"):
            (self.layout.bin / f"{name}{suffix}").unlink(missing_ok=True)

    def start(self, name: str) -> None:
        self.runner.run(["sc.exe", "start", name], check=False)
        self._wait(name, "RUNNING", 60)

    def stop(self, name: str) -> None:
        if self.state(name) in {"STOPPED", "MISSING"}:
            return
        self.runner.run(["sc.exe", "stop", name], check=False)
        self._wait(name, "STOPPED", STOP_TIMEOUT_SECONDS)

    def _wait(self, name: str, wanted: str, seconds: int) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.state(name) == wanted:
                return
            time.sleep(1)
        raise InstallError(f"The service {name} did not reach {wanted} within {seconds} seconds "
                           f"(it is {self.state(name)}). Its log is in {self.layout.data_root / 'logs'}.")


# ---- the release ----------------------------------------------------------------
def place_release(package: Path, layout: Layout, runner: Runner) -> Path:
    """Unpack the runtime, the application and the wheels into releases/<label>."""
    manifest = read_manifest(package)
    label = manifest["label"]
    release = layout.releases / label
    if release.exists():
        # A release kept for rollback, or one a failed run left: placed again from the package.
        say(f"Replacing the existing copy of {label} with the package's.")
        shutil.rmtree(release)
    python_dir = release / "python"
    python_dir.mkdir(parents=True)
    with zipfile.ZipFile(package / "runtime" / manifest["python"]["file"]) as archive:
        archive.extractall(python_dir)
    # The embeddable runtime reads its whole search path from this file: the standard
    # library, the installed wheels, and the application. Nothing from the host.
    (python_dir / PYTHON_PTH).write_text(
        "python314.zip\n.\nLib\\site-packages\n..\\app\nimport site\n", encoding="ascii")
    shutil.copytree(package / "app", release / "app")
    site_packages = python_dir / "Lib" / "site-packages"
    site_packages.mkdir(parents=True)
    pip_dir = release / "pip-bootstrap"
    with zipfile.ZipFile(package / "wheelhouse" / manifest["pip"]["file"]) as archive:
        archive.extractall(pip_dir)
    bootstrap = (f"import sys; sys.path.insert(0, r'{pip_dir}'); "
                 "from pip._internal.cli.main import main; sys.exit(main())")
    runner.run([python_dir / "python.exe", "-c", bootstrap, "install", "--no-index",
                "--find-links", package / "wheelhouse", "--require-hashes", "--only-binary=:all:",
                "--no-deps", "--target", site_packages, "--disable-pip-version-check",
                "--no-warn-script-location", "-r", package / "wheelhouse" / "install-requirements.txt"])
    shutil.rmtree(pip_dir, ignore_errors=True)
    shutil.copy2(package / "manifest.json", release / "manifest.json")
    # pip builds each package in a folder under the installing administrator's %TEMP% and
    # moves it into place, and a move keeps the source's protected ACL (SYSTEM,
    # Administrators, owner): the service accounts could list site-packages but read none
    # of it ("cannot import name ... (unknown location)"). The release inherits instead.
    runner.run(["icacls", release, "/reset", "/T", "/C", "/Q"])
    return release


# The code that starts the NEXT upgrade, kept inside each release (M4 exit review). An
# upgrade run from the new package's own scripts runs that package's installer and module
# before anything has verified them: someone who can write to the folder a package waits in
# could take the signature check out and regenerate the checksums, which need no key. Run
# from <InstallRoot>\current\installer\upgrade.ps1 instead, the installer, the package
# checks and the Python are the ones this install already verified.
LAUNCHER_DIR = "installer"
LAUNCHER_FILES = (("installer/sentro_installer.py", "sentro_installer.py"),
                  ("lib/SentroPackage.psm1", "SentroPackage.psm1"),
                  ("installer/upgrade-installed.ps1", "upgrade.ps1"))


def place_launcher(package: Path, release: Path) -> Path:
    target = release / LAUNCHER_DIR
    target.mkdir(parents=True, exist_ok=True)
    for source, name in LAUNCHER_FILES:
        if (package / source).is_file():
            shutil.copy2(package / source, target / name)
    return target


def stage_package(package: Path, layout: Layout) -> Path:
    """A copy of the package under the install root, where only administrators can write,
    so what is verified is exactly what is placed: the folder a package arrives in - a share,
    a download folder - can change between the check and the copy."""
    staged = layout.install_root / ".staging" / secrets.token_hex(8)
    staged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(package, staged)
    return staged


def switch_current(layout: Layout, release: Path) -> None:
    import _winapi

    if layout.current.exists() or os.path.lexists(layout.current):
        if not os.path.isjunction(layout.current):
            raise InstallError(f"{layout.current} exists and is not a junction; refusing to replace it.")
        os.rmdir(layout.current)  # removes the link, never the release it points to
    _winapi.CreateJunction(str(release), str(layout.current))


def current_release(layout: Layout) -> Path | None:
    if not os.path.isjunction(layout.current):
        return None
    return Path(os.path.realpath(layout.current))


def product(layout: Layout, release: Path, runner: Runner, *args: str, check: bool = True,
            timeout: int = 3600) -> subprocess.CompletedProcess:
    """Run `main.py <args>` of a release against this install's configuration."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
    env["DSPM_CONFIG_FILE"] = str(layout.config_file)
    return runner.run([release / "python" / "python.exe", release / "app" / "main.py", *args],
                      env=env, cwd=release / "app", check=check, timeout=timeout)


def product_json(layout: Layout, release: Path, runner: Runner, *args: str) -> dict:
    completed = product(layout, release, runner, *args)
    lines = [line for line in completed.stdout.splitlines() if line.strip().startswith("{")]
    if not lines:
        raise InstallError(f"main.py {' '.join(args)} printed no JSON: {completed.stdout[-500:]}")
    return json.loads(lines[-1])


# ---- configuration and secrets --------------------------------------------------
def fernet_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def admin_password() -> str:
    # Letters and digits in every case, long, random, and never containing "admin".
    while True:
        candidate = "Sn" + secrets.token_urlsafe(18).replace("-", "x").replace("_", "y") + "7q"
        if "admin" not in candidate.lower():
            return candidate


SECRET_FILES = {
    "DSPM_SECRET_KEY": ("secret_key", lambda: secrets.token_urlsafe(48)),
    "DSPM_VAULT_KEY": ("vault_key", fernet_key),
    "DSPM_ARTIFACT_KEY": ("artifact_key", fernet_key),
    "DSPM_BACKUP_KEY": ("backup_key", fernet_key),
    "DSPM_EVIDENCE_HMAC_KEY": ("evidence_hmac_key", lambda: secrets.token_urlsafe(48)),
    "DSPM_ADMIN_PASSWORD": ("admin_password", admin_password),
}


def init_secrets(layout: Layout, db_url_file: Path | None) -> list[str]:
    """Create each missing secret file; never overwrite one. Returns the names created."""
    layout.secrets.mkdir(parents=True, exist_ok=True)
    created = []
    for _setting, (filename, make) in SECRET_FILES.items():
        path = layout.secrets / filename
        if not path.exists():
            path.write_text(make() + "\n", encoding="utf-8")
            created.append(filename)
    if db_url_file is not None:
        target = layout.secrets / "db_url"
        value = Path(db_url_file).read_text(encoding="utf-8").strip()
        if not value.startswith(("postgres://", "postgresql://")):
            raise InstallError(f"{db_url_file} does not hold a PostgreSQL URL.")
        target.write_text(value + "\n", encoding="utf-8")
        created.append("db_url")
    return created


TRUST_SETTING_COMMENT = "# D10: the publisher keys this install trusts for update packages and licences."


def ensure_trust_setting(layout: Layout) -> bool:
    """An install from before D10 has no DSPM_TRUST_FILE in its configuration: add it."""
    text = layout.config_file.read_text(encoding="utf-8") if layout.config_file.exists() else ""
    if not text or "DSPM_TRUST_FILE" in text:
        return False
    addition = f"{TRUST_SETTING_COMMENT}\nDSPM_TRUST_FILE = '{layout.trust_file}'\n"
    layout.config_file.write_text(text.rstrip("\n") + "\n" + addition, encoding="utf-8")
    return True


# ---- the publisher's signature (D10) ------------------------------------------
def load_signing(folder: Path):
    """The verifier (backend/signing.py, standard library only) of a package or release."""
    import types

    source = Path(folder) / "app" / "backend" / "signing.py"
    if not source.is_file():
        return None
    # Compiled here, never through the import system: that would write a __pycache__ .pyc
    # into the package, which its own checksums then (rightly) refuse. A .pyc beside the
    # sources is exactly what verification must not ignore - it can run instead of them.
    module = types.ModuleType(f"sentro_signing_{abs(hash(str(source)))}")
    module.__file__ = str(source)
    exec(compile(source.read_text(encoding="utf-8"), str(source), "exec"), module.__dict__)  # noqa: S102 - the verifier
    return module


def pin_publisher(package: Path, layout: Layout, *, publisher_key_file: Path | None = None,
                  trust_package_publisher: bool = False, signing=None) -> str:
    """At install, record which publisher key this install trusts. The key comes from the
    operator (-PublisherKeyFile, the .pub published with the release) or, when they say so
    after comparing its fingerprint with the published one, from the package itself."""
    signing = signing or load_signing(package)
    if signing is None:
        return ""
    if publisher_key_file is not None:
        text = Path(publisher_key_file).read_text(encoding="utf-8").strip()
        try:
            document = json.loads(text)
            key_text, purposes = document["public_key"], document.get("purposes") or ["package", "licence"]
        except (ValueError, KeyError, TypeError):
            key_text, purposes = text, ["package", "licence"]
        source = f"the publisher key file {publisher_key_file}"
    elif trust_package_publisher:
        publisher = package / signing.PUBLISHER_FILE
        if not publisher.is_file():
            raise InstallError("-TrustPackagePublisher: the package carries no publisher key (it is unsigned).")
        document = json.loads(publisher.read_text(encoding="utf-8"))
        key_text, purposes = document["public_key"], document.get("purposes") or ["package", "licence"]
        source = "the package (-TrustPackagePublisher)"
    else:
        return ""
    try:
        public = signing.decode_public_key(key_text)
    except signing.TrustError as exc:
        raise InstallError(f"The publisher key is not usable: {exc}") from exc
    entry = signing.add_to_trust(layout.trust_file, public, purposes, f"pinned at install from {source}", now())
    say(f"Trusting publisher key {entry['key_id']} (fingerprint {entry['fingerprint']}) for "
        f"{', '.join(entry['purposes'])}. Compare the fingerprint with the one published with the release.")
    return entry["key_id"]


def verify_package(package: Path, layout: Layout, *, installed: dict | None = None, verifier: Path | None = None,
                   allow_unsigned: bool = False, allow_downgrade: bool = False) -> dict:
    """Check the package with the INSTALLED release's verifier and this install's trust file
    when there is one - never with trust the package brings."""
    signing = load_signing(verifier) if verifier is not None else None
    if signing is None:
        signing = load_signing(package)
        if verifier is not None and signing is not None:
            say("The installed release predates package signatures (D10); the new package's verifier is used.")
    if signing is None:
        if allow_unsigned:
            say("WARNING: no package verifier; accepted unsigned (-AllowUnsigned).")
            return {"label": read_manifest(package).get("label"), "signed_by": ""}
        raise InstallError("REFUSED: this package has no verifier (app/backend/signing.py).")
    try:
        result = signing.verify_package(package, signing.load_trust(layout.trust_file), installed=installed,
                                        allow_unsigned=allow_unsigned, allow_downgrade=allow_downgrade)
    except signing.TrustError as exc:
        raise InstallError(f"REFUSED: {exc}") from exc
    say(f"Package {result['label']}: {result['files']} files verified; "
        + (f"signed by publisher key {result['signed_by']}." if result["signed_by"]
           else "NOT signed by its publisher - accepted because -AllowUnsigned was given."))
    return result


def render_config(layout: Layout, mode: str, port: int, public_host: str = "") -> str:
    def q(path: Path) -> str:
        return "'" + str(path) + "'"

    data = layout.data_root
    production = mode == "production"
    lines = [
        "# Sentro configuration (C11). Written by the installer; edit and restart the services.",
        "# Every DSPM_* name is documented in .env.example (in the release's app folder).",
        "# The environment overrides this file; secrets never go in it - each is a file named",
        "# by <NAME>_FILE, readable only by the services and Administrators.",
        "# Check it with:  <InstallRoot>\\current\\python\\python.exe <InstallRoot>\\current\\app\\main.py config check",
        "[settings]",
        f'DSPM_ENV = "{"production" if production else "local"}"',
        f"DSPM_LOG_DIR = {q(data / 'logs')}",
        f"DSPM_ARTIFACT_DIR = {q(data / 'artifacts')}",
        f"DSPM_BACKUP_DIR = {q(data / 'backups')}",
        f"DSPM_REPORT_DIR = {q(data / 'reports')}",
        f"DSPM_SCAN_CACHE_DIR = {q(data / 'cache')}",
        "# Scans run on the worker service; the backend runs one itself if no worker takes it.",
        'DSPM_SCAN_EXECUTION = "queue"',
    ]
    for setting, (filename, _make) in SECRET_FILES.items():
        name = "DSPM_DEV_ADMIN_PASSWORD" if (setting == "DSPM_ADMIN_PASSWORD" and not production) else setting
        lines.append(f"{name}_FILE = {q(layout.secrets / filename)}")
    lines.append("# C12: the vault's versioned key ring. The first `main.py vault rotate` creates it from")
    lines.append("# vault_key; from then on it holds every key a saved credential names.")
    lines.append(f"DSPM_VAULT_KEYRING = {q(layout.secrets / 'vault_keyring.json')}")
    lines.append(TRUST_SETTING_COMMENT)
    lines.append(f"DSPM_TRUST_FILE = {q(layout.trust_file)}")
    if production:
        lines.append(f"DSPM_DB_URL_FILE = {q(layout.secrets / 'db_url')}")
        lines.append("# The name users type, served by the HTTPS reverse proxy on this host (C5).")
        lines.append(f'DSPM_TRUSTED_HOSTS = "{public_host}"')
        lines.append('DSPM_TRUSTED_PROXIES = "127.0.0.1"')
    else:
        lines.append("# Evaluation install: SQLite. Production requires PostgreSQL (DSPM_DB_URL_FILE).")
        lines.append(f"DSPM_DB_PATH = {q(data / 'db' / 'dspm.sqlite')}")
    lines.append(f"# The backend listens on 127.0.0.1:{port} only; publish it through the HTTPS reverse proxy")
    lines.append("# (deploy/reverse-proxy) and set DSPM_TRUSTED_PROXIES / DSPM_TRUSTED_HOSTS for it.")
    return "\n".join(lines) + "\n"


def service_xml(layout: Layout, name: str, description: str, arguments: str) -> str:
    python = layout.current / "python" / "python.exe"
    app = layout.current / "app"
    return f"""<service>
  <id>{name}</id>
  <name>{name}</name>
  <description>{description}</description>
  <executable>{python}</executable>
  <arguments>"{app / 'main.py'}" {arguments}</arguments>
  <workingdirectory>{app}</workingdirectory>
  <env name="DSPM_CONFIG_FILE" value="{layout.config_file}"/>
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="restart" delay="60 sec"/>
  <resetfailure>1 hour</resetfailure>
  <stoptimeout>30 sec</stoptimeout>
  <logpath>{layout.data_root / 'logs' / 'service'}</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>8</keepFiles>
  </log>
</service>
"""


_ADMINS, _SYSTEM, _USERS = "*S-1-5-32-544", "*S-1-5-18", "*S-1-5-32-545"
_OWNERS = [f"{_ADMINS}:(OI)(CI)F", f"{_SYSTEM}:(OI)(CI)F"]


def _grants(entries: list[str]) -> list[str]:
    return [item for entry in entries for item in ("/grant:r", entry)]


# Who may own a folder the installer finds already there: Administrators, SYSTEM,
# TrustedInstaller - or the administrator running the install (Windows gives objects an
# elevated member of Administrators creates to that account on some editions).
_TRUSTED_OWNER_SIDS = {"S-1-5-32-544", "S-1-5-18",
                       "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}


def folder_owner(folder: Path, runner: Runner) -> tuple[str, str]:
    """(the folder's owner SID, the SID running the installer). The path goes through the
    environment, never into the command text."""
    script = ("(Get-Acl -LiteralPath $env:SENTRO_OWNER_OF).GetOwner("
              "[System.Security.Principal.SecurityIdentifier]).Value; "
              "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
    completed = runner.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                           env={**os.environ, "SENTRO_OWNER_OF": str(folder)})
    lines = [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]
    return (lines + ["", ""])[0], (lines + ["", ""])[1]


def refuse_foreign_folders(layout: Layout, runner: Runner) -> None:
    """A standard user may create folders under ProgramData. One who created the data root
    (or the install root) before the install would still own it afterwards - and an owner
    can always change a folder's permissions, then read the secrets or plant a key. Such a
    folder is refused, never adopted (M3 exit review)."""
    for folder in (layout.data_root, layout.install_root):
        if not folder.exists():
            continue
        owner, installing = folder_owner(folder, runner)
        if owner not in _TRUSTED_OWNER_SIDS and owner != installing:
            raise InstallError(
                f"{folder} already exists and is owned by {owner or 'an unknown account'}, not by Administrators "
                f"or SYSTEM: someone other than an administrator created it, and could change its permissions "
                f"after the install. Check what it holds, remove it, and install again.")


def lock_down(layout: Layout, runner: Runner) -> None:
    """Before any secret is written: the data root belongs to Administrators and SYSTEM
    alone - owned by Administrators, nothing inherited from ProgramData, where every user
    may read."""
    runner.run(["icacls", layout.data_root, "/setowner", _ADMINS, "/T", "/C", "/Q"])
    for folder in (layout.data_root, layout.data_root / "config", layout.secrets):
        runner.run(["icacls", folder, "/inheritance:r", *_grants(_OWNERS)])


def grant_services(layout: Layout, runner: Runner) -> None:
    """Once the services (and so their virtual accounts) exist: they may change the data
    root, only read their configuration and secrets, and only read and run the install."""
    accounts = [layout.service_account(name) for name in layout.services]
    runner.run(["icacls", layout.data_root, "/inheritance:r",
                *_grants(_OWNERS + [f"{account}:(OI)(CI)M" for account in accounts])])
    for folder in (layout.data_root / "config", layout.secrets):
        runner.run(["icacls", folder, "/inheritance:r",
                    *_grants(_OWNERS + [f"{account}:(OI)(CI)RX" for account in accounts])])
    runner.run(["icacls", layout.install_root, "/inheritance:r",
                *_grants(_OWNERS + [f"{_USERS}:(OI)(CI)RX"] + [f"{account}:(OI)(CI)RX" for account in accounts])])


def wait_ready(port: int, seconds: int = READY_TIMEOUT_SECONDS) -> dict:
    deadline = time.monotonic() + seconds
    last = "no answer"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ready", timeout=5) as response:
                body = json.loads(response.read().decode("utf-8"))
                if response.status == 200 and body.get("ready") is True:
                    return body
                last = json.dumps(body)[:300]
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:300]}"
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = type(exc).__name__
        time.sleep(2)
    raise InstallError(f"Sentro did not become ready on 127.0.0.1:{port} within {seconds} seconds ({last}).")


# ---- operations -----------------------------------------------------------------
def install(package: Path, layout: Layout, *, port: int, mode: str, db_url_file: Path | None,
            public_host: str = "", runner: Runner | None = None, publisher_key_file: Path | None = None,
            trust_package_publisher: bool = False, allow_unsigned: bool = False) -> dict:
    runner = runner or Runner()
    services = Services(layout, runner)
    manifest = read_manifest(package)
    state = read_state(layout)
    if any(services.exists(name) for name in layout.services):
        raise InstallError(f"Services {layout.backend}/{layout.worker} already exist; use upgrade.ps1, "
                           f"or uninstall.ps1 first.")
    if mode == "production" and not public_host and not layout.config_file.exists():
        raise InstallError("A production install is served through the HTTPS reverse proxy: pass -PublicHostName "
                           "with the name users type (for example sentro.corp.example).")
    if mode == "production" and db_url_file is None and not (layout.secrets / "db_url").exists():
        raise InstallError("A production install needs PostgreSQL: pass -DatabaseUrlFile with a file holding "
                           "the application role's URL (sslmode=verify-full for a remote server).")
    refuse_foreign_folders(layout, runner)
    for folder in [layout.install_root, layout.releases, layout.bin, *layout.data_dirs()]:
        folder.mkdir(parents=True, exist_ok=True)
    lock_down(layout, runner)
    pin_publisher(package, layout, publisher_key_file=publisher_key_file,
                  trust_package_publisher=trust_package_publisher)
    verify_package(package, layout, allow_unsigned=allow_unsigned)
    if state is not None:
        say(f"Reusing the data, keys and configuration in {layout.data_root} (last release there: "
            f"{state.get('release') or state.get('history', [{}])[-1].get('release') or 'none recorded'}).")
    created = init_secrets(layout, db_url_file)
    if created:
        say(f"Created {len(created)} secret file(s) in {layout.secrets}: {', '.join(created)}.")
    if not layout.config_file.exists():
        layout.config_file.write_text(render_config(layout, mode, port, public_host), encoding="utf-8")
        say(f"Wrote {layout.config_file}.")
    say(f"Placing release {manifest['label']} (Python {manifest['python']['version']}, "
        f"{len(manifest['wheels'])} wheels from the package).")
    release = place_release(package, layout, runner)
    place_launcher(package, release)
    product(layout, release, runner, "config", "check")
    switch_current(layout, release)
    migrated = product_json(layout, release, runner, "migrate", "upgrade", "--json")
    say(f"Database at schema revision {migrated['applied_revision']}.")
    services.register(layout.backend, service_xml(layout, layout.backend, "Sentro DSPM backend (API and console)",
                                                  f"serve --host 127.0.0.1 --port {port}"), package / "bin" / "WinSW-x64.exe")
    services.register(layout.worker, service_xml(layout, layout.worker, "Sentro DSPM scan worker", "worker"),
                      package / "bin" / "WinSW-x64.exe")
    grant_services(layout, runner)
    services.start(layout.backend)
    services.start(layout.worker)
    ready = wait_ready(port)
    history = list((state or {}).get("history", []))
    history.append({"at": now(), "action": "install", "release": manifest["label"]})
    write_state(layout, {
        "product": PRODUCT, "prefix": layout.prefix, "install_root": str(layout.install_root),
        "data_root": str(layout.data_root), "port": port, "mode": mode, "release": manifest["label"],
        "commit": manifest["commit"], "commit_time": manifest["commit_time"],
        "schema_revision": migrated["applied_revision"], "history": history[-50:],
    })
    say(f"Installed. {layout.backend} and {layout.worker} are running and set to start automatically; "
        f"/api/ready answers ready at schema revision {migrated['applied_revision']}"
        f"{' with warnings: ' + '; '.join(ready['warnings']) if ready.get('warnings') else ''}.")
    if "admin_password" in created:
        say(f"The first administrator password is in {layout.secrets / 'admin_password'} (Administrators "
            f"only). Sign in as admin, set up two-step sign-in, and change the password.")
    return read_state(layout)


def decide_upgrade(installed: dict, package: dict, db_revision: int, restore_manifest: dict | None,
                   *, allow_downgrade: bool = False) -> str:
    """'upgrade', 'downgrade' or 'restore-downgrade'; raises InstallError when refused.
    D10: an older build is refused unless going back was asked for (-AllowDowngrade, or
    -RestoreBackup with the backup taken before the upgrade) - an old signed package is
    still an old package."""
    if package["commit"] == installed.get("commit"):
        raise InstallError(f"Release {package['label']} is already installed.")
    older = int(package["commit_time"]) < int(installed.get("commit_time") or 0)
    wanted = int(package["schema_revision"])
    if restore_manifest is not None:
        if int(restore_manifest.get("schema_revision") or -1) != wanted:
            raise InstallError(f"The backup is at schema revision {restore_manifest.get('schema_revision')}; "
                               f"this package needs {wanted}. Choose the backup taken before the upgrade.")
        return "restore-downgrade"
    if wanted < db_revision:
        raise InstallError(
            f"Refusing to downgrade: this package expects database schema revision {wanted}, and the database "
            f"is at {db_revision}. Code this old cannot run on it, and running it would lose what the newer "
            f"schema holds. To go back, pass -RestoreBackup with the backup taken before the upgrade "
            f"(its manifest is in {installed.get('data_root', '<DataRoot>')}\\backups and is named in install.json).")
    if older and not allow_downgrade:
        raise InstallError(f"Refusing a downgrade: {package['label']} was built before the installed release "
                           f"{installed.get('release', '')}. To go back on purpose, pass -AllowDowngrade.")
    return "downgrade" if older else "upgrade"


def upgrade(package: Path, layout: Layout, *, restore_backup: Path | None = None,
            runner: Runner | None = None, allow_unsigned: bool = False, allow_downgrade: bool = False,
            publisher_key_file: Path | None = None) -> dict:
    """Upgrade from a staged copy of the package (see stage_package), removed afterwards."""
    if read_state(layout) is None:
        raise InstallError(f"No Sentro install is recorded in {layout.state_file}; use install.ps1.")
    staged = stage_package(package, layout)
    try:
        return _upgrade(staged, layout, restore_backup=restore_backup, runner=runner, allow_unsigned=allow_unsigned,
                        allow_downgrade=allow_downgrade, publisher_key_file=publisher_key_file)
    finally:
        shutil.rmtree(staged, ignore_errors=True)


def _upgrade(package: Path, layout: Layout, *, restore_backup: Path | None, runner: Runner | None,
             allow_unsigned: bool, allow_downgrade: bool, publisher_key_file: Path | None) -> dict:
    runner = runner or Runner()
    services = Services(layout, runner)
    state = read_state(layout)
    manifest = read_manifest(package)
    old_release = current_release(layout)
    if old_release is None:
        raise InstallError(f"{layout.current} is missing; the install is damaged. Reinstall over the kept data.")
    restore_manifest = json.loads(Path(restore_backup).read_text(encoding="utf-8")) if restore_backup else None
    if manifest["commit"] == state.get("commit"):
        raise InstallError(f"Release {manifest['label']} is already installed.")
    if publisher_key_file is not None:
        # An install from before D10 has no pinned key, and install.ps1 refuses an existing
        # install: the key is pinned here, from a file the operator names, with the INSTALLED
        # release's code when it has a verifier - never from the package.
        pin_publisher(package, layout, publisher_key_file=publisher_key_file, signing=load_signing(old_release))
    # D10: nothing from the new package is placed before the installed release's verifier
    # has checked it against this install's trust file.
    verify_package(package, layout, installed=state, verifier=old_release, allow_unsigned=allow_unsigned,
                   allow_downgrade=allow_downgrade or restore_manifest is not None)
    if ensure_trust_setting(layout):
        say(f"Added DSPM_TRUST_FILE to {layout.config_file}.")
    # Maintenance runs with the NEW release: its migrate/backup commands open the
    # database without converging it, and the running release needs none of them.
    existed = (layout.releases / manifest["label"]).exists()
    new_release = place_release(package, layout, runner)
    place_launcher(package, new_release)
    product(layout, new_release, runner, "config", "check")  # nothing is stopped yet
    status = product_json(layout, new_release, runner, "migrate", "status", "--json")
    try:
        kind = decide_upgrade(state, manifest, int(status["applied_revision"]), restore_manifest,
                              allow_downgrade=allow_downgrade)
    except InstallError:
        if not existed:  # never delete a release that was there before this run
            shutil.rmtree(new_release, ignore_errors=True)
        raise
    say(f"{kind}: {state['release']} -> {manifest['label']} (database at revision {status['applied_revision']}).")

    services.stop(layout.worker)
    services.stop(layout.backend)
    say("Services stopped. Taking and verifying an encrypted backup.")
    try:
        backup = product_json(layout, new_release, runner, "backup", "create", "--verify", "--json")
    except InstallError:
        _start(services, layout)
        raise
    say(f"Backup {backup['manifest']} verified (schema revision {backup.get('schema_revision')}).")
    try:
        if kind == "restore-downgrade":
            product(layout, new_release, runner, "backup", "restore", str(restore_backup), "--yes")
        migrated = product_json(layout, new_release, runner, "migrate", "upgrade", "--json")
    except InstallError:
        say("The migration failed; the database is unchanged (revisions apply in one transaction). "
            "Restarting the release that was running.")
        _start(services, layout)
        raise
    switch_current(layout, new_release)
    try:
        _start(services, layout)
        wait_ready(int(state["port"]))
    except InstallError as failure:
        say(f"The new release did not come up ({failure}). Rolling back to {old_release.name}.")
        services.stop(layout.worker)
        services.stop(layout.backend)
        switch_current(layout, old_release)
        product(layout, new_release, runner, "backup", "restore", backup["manifest"], "--yes")
        _start(services, layout)
        wait_ready(int(state["port"]))
        shutil.rmtree(new_release, ignore_errors=True)
        history = list(state.get("history", []))
        history.append({"at": now(), "action": "rollback", "from": state["release"], "to": manifest["label"],
                        "backup": backup["manifest"], "reason": str(failure)[:300]})
        state["history"] = history[-50:]
        write_state(layout, state)
        raise InstallError(f"Upgrade rolled back ({str(failure).rstrip('.')}). {old_release.name} is running "
                           f"on the restored backup.")
    history = list(state.get("history", []))
    history.append({"at": now(), "action": kind, "from": state["release"], "to": manifest["label"],
                    "backup": backup["manifest"]})
    state.update({"release": manifest["label"], "previous_release": state["release"], "commit": manifest["commit"],
                  "commit_time": manifest["commit_time"], "schema_revision": migrated["applied_revision"],
                  "last_backup": backup["manifest"], "history": history[-50:]})
    write_state(layout, state)
    _prune_releases(layout, keep={new_release.name, old_release.name})
    say(f"{kind.capitalize()} complete: {manifest['label']} is running at schema revision "
        f"{migrated['applied_revision']}. The previous release is kept for rollback.")
    return state


def _start(services: Services, layout: Layout) -> None:
    services.start(layout.backend)
    services.start(layout.worker)


def _prune_releases(layout: Layout, keep: set[str]) -> None:
    for release in layout.releases.iterdir():
        if release.is_dir() and release.name not in keep:
            shutil.rmtree(release, ignore_errors=True)


def uninstall(layout: Layout, *, remove_data: bool = False, confirm: str = "",
              runner: Runner | None = None) -> None:
    runner = runner or Runner()
    services = Services(layout, runner)
    if remove_data and confirm != layout.prefix:
        raise InstallError(f"Removing the data deletes the database, the keys and every backup. To do it, pass "
                           f"-RemoveData and -ConfirmRemoveData {layout.prefix}.")
    for name in layout.services:
        services.unregister(name)
    say(f"Services {layout.backend} and {layout.worker} removed.")
    if os.path.isjunction(layout.current):
        os.rmdir(layout.current)
    shutil.rmtree(layout.releases, ignore_errors=True)
    shutil.rmtree(layout.bin, ignore_errors=True)
    try:
        layout.install_root.rmdir()
    except OSError:
        pass
    if remove_data:
        shutil.rmtree(layout.data_root, ignore_errors=True)
        say(f"Removed {layout.data_root} (database, keys, backups and logs), as asked.")
    else:
        state = read_state(layout) or {}
        state.setdefault("history", []).append({"at": now(), "action": "uninstall", "release": state.get("release")})
        state["release"] = None
        if layout.data_root.exists():
            write_state(layout, state)
        say(f"Kept {layout.data_root}: the database, keys, configuration, backups and logs. Installing again "
            f"with the same data root continues from them.")


# ---- command line ---------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentro_installer")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("install", "upgrade", "uninstall"):
        command = sub.add_parser(name)
        command.add_argument("--install-root", required=True, type=Path)
        command.add_argument("--data-root", required=True, type=Path)
        command.add_argument("--prefix", default=PRODUCT)
        if name != "uninstall":
            command.add_argument("--package", required=True, type=Path)
    sub.choices["install"].add_argument("--port", type=int, default=8000)
    sub.choices["install"].add_argument("--mode", choices=("evaluation", "production"), default="production")
    sub.choices["install"].add_argument("--db-url-file", type=Path)
    sub.choices["install"].add_argument("--public-host", default="")
    for name in ("install", "upgrade"):
        sub.choices[name].add_argument("--publisher-key-file", type=Path)
    sub.choices["install"].add_argument("--trust-package-publisher", action="store_true")
    for name in ("install", "upgrade"):
        sub.choices[name].add_argument("--allow-unsigned", action="store_true")
    sub.choices["upgrade"].add_argument("--allow-downgrade", action="store_true")
    sub.choices["upgrade"].add_argument("--restore-backup", type=Path)
    sub.choices["uninstall"].add_argument("--remove-data", action="store_true")
    sub.choices["uninstall"].add_argument("--confirm-remove-data", default="")
    args = parser.parse_args(argv)
    layout = Layout(args.install_root.resolve(), args.data_root.resolve(), args.prefix)
    try:
        if args.command == "install":
            install(args.package.resolve(), layout, port=args.port, mode=args.mode, db_url_file=args.db_url_file,
                    public_host=args.public_host, publisher_key_file=args.publisher_key_file,
                    trust_package_publisher=args.trust_package_publisher, allow_unsigned=args.allow_unsigned)
        elif args.command == "upgrade":
            upgrade(args.package.resolve(), layout, restore_backup=args.restore_backup,
                    allow_unsigned=args.allow_unsigned, allow_downgrade=args.allow_downgrade,
                    publisher_key_file=args.publisher_key_file)
        else:
            uninstall(layout, remove_data=args.remove_data, confirm=args.confirm_remove_data)
    except InstallError as exc:
        say(f"STOPPED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
