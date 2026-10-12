"""Prepare a source install's runtime folders, secrets and configuration (scripts/setup.ps1).

The offline Windows package does this in its installer (packaging/windows/sentro_installer.py),
for services under C:\\ProgramData\\Sentro. A source install - this folder, run with its own
virtual environment - gets the same layout under its data root (default: <this folder>\\data):

    <data>\\config\\sentro.toml        the one configuration file (no secrets in it)
    <data>\\secrets\\*                 keys and passwords, one per file, generated here
    <data>\\{db,artifacts,backups,cache,reports,logs,trust}

Nothing that exists is overwritten: a second run reuses the keys and configuration, so an
install's data stays readable. Secrets are generated with the installer's own generators,
written only to their files, and never printed - the summary names files, not values. On
Windows the config and secrets folders are restricted to Administrators, SYSTEM and the
account that ran this. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging" / "windows"))

from sentro_installer import SECRET_FILES, Layout  # noqa: E402

FOLDERS = ("config", "secrets", "trust", "db", "artifacts", "backups", "cache", "reports", "logs")


def _quoted(path: Path) -> str:
    text = str(path)
    if "'" in text or "\n" in text:
        raise SystemExit(f"{text}: a path with a quote or a line break cannot be written to the configuration.")
    return f"'{text}'"


def render_config(layout: Layout, mode: str, public_host: str) -> str:
    data = layout.data_root
    production = mode == "production"
    lines = [
        "# Sentro configuration (source install). Written by scripts\\setup.ps1; edit it and restart",
        "# Sentro (scripts\\stop.ps1, scripts\\start.ps1). Every DSPM_* setting is described in",
        "# .env.example and docs\\CONFIGURATION.md. The environment overrides this file.",
        "# Secrets never go in it: each is a file named by <NAME>_FILE in the secrets folder.",
        "# Check it with:  .venv\\Scripts\\python.exe main.py --config <this file> config check",
        "[settings]",
        f'DSPM_ENV = "{"production" if production else "local"}"',
        f"DSPM_LOG_DIR = {_quoted(data / 'logs')}",
        f"DSPM_ARTIFACT_DIR = {_quoted(data / 'artifacts')}",
        f"DSPM_BACKUP_DIR = {_quoted(data / 'backups')}",
        f"DSPM_REPORT_DIR = {_quoted(data / 'reports')}",
        f"DSPM_SCAN_CACHE_DIR = {_quoted(data / 'cache')}",
        "# Scans run on the worker (scripts\\start.ps1 starts it); the backend runs one itself if no",
        "# worker takes it.",
        'DSPM_SCAN_EXECUTION = "queue"',
    ]
    for setting, (filename, _make) in SECRET_FILES.items():
        name = "DSPM_DEV_ADMIN_PASSWORD" if (setting == "DSPM_ADMIN_PASSWORD" and not production) else setting
        lines.append(f"{name}_FILE = {_quoted(layout.secrets / filename)}")
    lines.append("# The vault's versioned key ring: the first `main.py vault rotate` creates it from vault_key.")
    lines.append(f"DSPM_VAULT_KEYRING = {_quoted(layout.secrets / 'vault_keyring.json')}")
    lines.append("# The publisher keys this install trusts for update packages and licences.")
    lines.append(f"DSPM_TRUST_FILE = {_quoted(layout.trust_file)}")
    if production:
        lines.append(f"DSPM_DB_URL_FILE = {_quoted(layout.secrets / 'db_url')}")
        lines.append("# The name users type, served by the HTTPS reverse proxy on this host (deploy/reverse-proxy).")
        lines.append(f'DSPM_TRUSTED_HOSTS = "{public_host}"')
        lines.append('DSPM_TRUSTED_PROXIES = "127.0.0.1"')
    else:
        lines.append("# Evaluation install: SQLite. Production requires PostgreSQL (DSPM_DB_URL_FILE).")
        lines.append(f"DSPM_DB_PATH = {_quoted(data / 'db' / 'dspm.sqlite')}")
    return "\n".join(lines) + "\n"


def _restrict(folder: Path) -> None:
    """Administrators, SYSTEM and the account running this; nothing inherited."""
    if os.name != "nt":
        folder.chmod(0o700)
        return
    who =subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True)
    sid = who.stdout.strip().split(",")[-1].strip().strip('"')
    grants = ["*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", f"*{sid}:(OI)(CI)F"]
    args = ["icacls", str(folder), "/inheritance:r"]
    for grant in grants:
        args += ["/grant:r", grant]
    subprocess.run(args, capture_output=True, text=True, check=True)


def prepare(layout: Layout, mode: str, db_url_file: Path | None, public_host: str) -> dict:
    if mode == "production":
        if not public_host:
            raise SystemExit("A production install is served through the HTTPS reverse proxy: give -PublicHostName "
                             "(the name users type, for example sentro.corp.example).")
        if db_url_file is None and not (layout.secrets / "db_url").exists():
            raise SystemExit("A production install needs PostgreSQL: give -DatabaseUrlFile, a file holding the "
                             "application role's URL (see docs\\DATABASE_SETUP.md).")
    created_folders = []
    for name in FOLDERS:
        folder = layout.data_root / name
        if not folder.is_dir():
            folder.mkdir(parents=True, exist_ok=True)
            created_folders.append(name)
    for folder in (layout.data_root / "config", layout.secrets):
        _restrict(folder)

    created_secrets = []
    for _setting, (filename, make) in SECRET_FILES.items():
        path = layout.secrets / filename
        if not path.exists():
            path.write_text(make() + "\n", encoding="utf-8")
            created_secrets.append(filename)
    if db_url_file is not None:
        value = Path(db_url_file).read_text(encoding="utf-8").strip()
        if not value.startswith(("postgres://", "postgresql://")):
            raise SystemExit(f"{db_url_file} does not hold a PostgreSQL URL (postgresql://...).")
        (layout.secrets / "db_url").write_text(value + "\n", encoding="utf-8")
        created_secrets.append("db_url")

    config_written = False
    if not layout.config_file.exists():
        layout.config_file.write_text(render_config(layout, mode, public_host), encoding="utf-8")
        config_written = True
    return {
        "data_root": str(layout.data_root),
        "config": str(layout.config_file),
        "config_written": config_written,
        "secrets": str(layout.secrets),
        "created_secrets": created_secrets,
        "created_folders": created_folders,
        "admin_password_file": str(layout.secrets / "admin_password"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data-root", default=str(ROOT / "data"))
    parser.add_argument("--mode", choices=("local", "production"), default="local")
    parser.add_argument("--db-url-file", default="")
    parser.add_argument("--public-host", default="")
    args = parser.parse_args(argv)
    layout = Layout(install_root=ROOT, data_root=Path(args.data_root).resolve(), prefix="Sentro")
    summary = prepare(layout, args.mode, Path(args.db_url_file) if args.db_url_file else None, args.public_host)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
