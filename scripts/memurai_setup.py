"""B9: install, configure, check and remove the Memurai service Sentro runs on.

Memurai is Redis on Windows - a native service implementing the Redis API, which is the
only route to Redis Streams on Windows Server 2019: Docker Desktop is unsupported there,
Linux containers need WSL2 (Win10 2004 / Server 2022), there is no official Redis Windows
image, and the abandoned MSOpenTech port stopped at Redis 3.2, before Streams existed
(§5 of docs/PLAN_memurai_operational_plane_2026-09.md).

Everything `configure` sets is a decision from that plan, not a default:

``bind 127.0.0.1``
    nothing listens off this host. The backend, its workers and Memurai are one
    deployment, and the acceptance gates include "no Redis listener reachable from
    another host".
``requirepass`` + an ACL user
    a generated secret stored beside ``DSPM_VAULT_KEY``, and a user that may run the
    queue and cache commands on ``dspm:*`` keys and nothing else - no ``CONFIG``, no
    ``FLUSHALL``, no ``KEYS``, no ``DEBUG``.
``maxmemory 256mb`` with ``noeviction``
    about 25x the measured steady state. Small on purpose: Windows has no ``fork``,
    Memurai emulates it for background saves, and its own documentation warns that
    memory can grow during one. Nothing is evicted, because evicting an unacknowledged
    job is data loss; cache keys carry TTLs instead.
``save ""`` and ``appendonly no``
    Memurai holds coordination and derived state only, and all of it is reconstructible
    from PostgreSQL. Persisting it buys nothing and creates a second place for data to
    accumulate - which is exactly what Phase A spent its effort removing.

    python scripts/memurai_setup.py install|configure|health|uninstall [--json]

**Licensing, unchanged by any of this:** Memurai *Developer* is free for development and
testing and cannot be shipped - it is dev/test licensed and restarts itself every few
days. Production needs Memurai Enterprise, which is a commercial conversation with a lead
time (§5).
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SERVICE_NAME = "Memurai"
DEFAULT_PORT = 6379
ACL_USER = "sentro"
KEY_PREFIX = "dspm:"
MAX_MEMORY = "256mb"
SECRET_PATH = Path(os.getenv("DSPM_MEMURAI_PASSWORD_PATH", Path.home() / ".dspm" / "memurai.password"))

# What the product's own user may do, and nothing else. ORDER MATTERS: a later rule
# wins, so this starts from "no commands at all", grants the categories the queue and the
# cache need, takes back the dangerous ones that @read drags in (KEYS would list every
# key in the server, whatever the key pattern says), and re-grants INFO, which the health
# check needs and which Redis classes as dangerous.
ACL_RULES = (
    "resetkeys",
    f"~{KEY_PREFIX}*",
    "-@all",
    "+@read",
    "+@write",
    "+@stream",
    "+@transaction",
    "+@connection",
    "-@dangerous",
    "-@admin",
    "+info",
    "+ping",
)

# The settings `configure` writes and `health` insists on afterwards.
REQUIRED_SETTINGS = {
    "bind": "127.0.0.1",
    "maxmemory-policy": "noeviction",
    "appendonly": "no",
    "save": "",
}


def _print(message: str = "") -> None:
    print(message, flush=True)


def service_present() -> bool:
    if os.name != "nt":
        return False
    try:
        result = subprocess.run(["sc", "query", SERVICE_NAME], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and "SERVICE_NAME" in (result.stdout or "")


def read_secret() -> str:
    return SECRET_PATH.read_text(encoding="utf-8").strip() if SECRET_PATH.exists() else ""


def ensure_secret() -> str:
    """The password, generated once and stored beside the vault key it is kept with."""
    existing = read_secret()
    if existing:
        return existing
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SECRET_PATH.write_text(secret, encoding="utf-8")
    try:
        os.chmod(SECRET_PATH, 0o600)
    except OSError:
        pass
    _print(f"wrote a new Memurai password to {SECRET_PATH}")
    return secret


def _client(password: str = "", user: str = ""):
    import redis  # imported here so `health` can report the package being missing

    return redis.Redis(
        host="127.0.0.1",
        port=int(os.getenv("DSPM_MEMURAI_PORT", DEFAULT_PORT)),
        username=user or None,
        password=password or None,
        decode_responses=True,
        socket_connect_timeout=5,
    )


def connect(password: str = "", user: str = ""):
    """A connection that works whether or not a password has been set yet."""
    import redis

    for attempt_password, attempt_user in ((password, user), ("", ""), (password, "")):
        client = _client(attempt_password, attempt_user)
        try:
            client.ping()
            return client
        except redis.exceptions.RedisError:
            continue
    raise SystemExit("could not reach Memurai on 127.0.0.1 - is the service running?")


def do_install() -> int:
    if service_present():
        _print("Memurai service already present; nothing to install.")
        return 0
    if os.name != "nt":
        _print("Memurai is a Windows service; nothing to install here.")
        return 1
    if not shutil.which("choco"):
        _print(
            "Memurai is not installed and Chocolatey is not available.\n"
            "Install it from the vendor: https://www.memurai.com/get-memurai (Memurai Developer, Windows MSI).\n"
            'Check the signature before running it - the MSI is signed by "Janea Systems, Inc.".\n'
            "Then run: python scripts/memurai_setup.py configure"
        )
        return 1
    _print("Installing Memurai Developer (the vendor's signed MSI, through Chocolatey)...")
    result = subprocess.run(["choco", "install", "memurai-developer", "-y", "--no-progress"],
                            capture_output=True, text=True, timeout=1800)
    if not service_present():
        _print(result.stdout[-2000:] if result.stdout else "")
        _print("the install ran but no Memurai service exists")
        return 1
    _print("Installed.")
    return 0


def do_configure() -> int:
    secret = ensure_secret()
    client = connect(secret)
    client.config_set("requirepass", secret)

    # Re-connect with the password now that one is required.
    client = connect(secret)
    client.config_set("maxmemory", MAX_MEMORY)
    for key, value in REQUIRED_SETTINGS.items():
        if key == "bind":
            continue  # changing bind at runtime drops connections; the MSI default is already loopback
        client.config_set(key, value)

    client.execute_command("ACL", "SETUSER", ACL_USER, "on", f">{secret}", *ACL_RULES)
    client.execute_command("CONFIG", "REWRITE")

    _print("")
    _print("Configured. Point the product at it with:")
    _print(f"  DSPM_REDIS_URL=redis://{ACL_USER}:<password>@127.0.0.1:{DEFAULT_PORT}/0")
    _print("  DSPM_WORK_QUEUE=redis")
    _print(f"The password is in {SECRET_PATH}; it is never printed.")
    return 0


def health(as_user: bool = True) -> dict:
    """What an operator - or a test - needs to know, without ever printing the secret."""
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    secret = read_secret()
    check("the password file exists", bool(secret), str(SECRET_PATH))
    if not service_present() and os.name == "nt":
        check("the service is installed", False, f"no {SERVICE_NAME} service")
        return {"checks": checks, "failures": [c["name"] for c in checks if not c["ok"]]}

    try:
        client = connect(secret, ACL_USER if as_user else "")
    except SystemExit as exc:
        check("the server answers", False, str(exc))
        return {"checks": checks, "failures": [c["name"] for c in checks if not c["ok"]]}

    check("the server answers PING", bool(client.ping()), "PONG")
    try:
        info = client.info("server")
    except Exception as exc:
        # The product's user may be denied INFO on an install configured by hand; ask as
        # the operator rather than failing the whole check.
        check("the product's user may read the server's health", False, type(exc).__name__)
        info = connect(secret).info("server")
    check("it speaks the Redis API this product needs", str(info.get("redis_version", "")) >= "7.0",
          f"memurai {info.get('memurai_version', '?')} / redis {info.get('redis_version', '?')}")

    settings = {}
    for key in ("bind", "requirepass", "maxmemory", "maxmemory-policy", "appendonly", "save"):
        try:
            settings[key] = str((client.config_get(key) or {}).get(key, ""))
        except Exception:
            settings[key] = "<not readable by this user>"

    # Read the security-relevant settings as the operator (the product's user is not
    # allowed to run CONFIG, which is itself the point).
    if any(value == "<not readable by this user>" for value in settings.values()):
        operator = connect(secret)
        for key in list(settings):
            settings[key] = str((operator.config_get(key) or {}).get(key, ""))
        check("the product's user may not read or change the configuration", True,
              "CONFIG is refused for the ACL user")

    check("nothing listens off this host", settings["bind"].strip() in {"127.0.0.1", "127.0.0.1 -::1", "-::1 127.0.0.1"},
          f"bind {settings['bind']}")
    check("a password is required", bool(settings["requirepass"]), "set (not shown)")
    check("memory is capped", settings["maxmemory"] not in ("", "0"),
          f"{int(settings['maxmemory'] or 0) // (1024 * 1024)} MB")
    check("nothing is evicted", settings["maxmemory-policy"] == "noeviction", settings["maxmemory-policy"])
    check("nothing is persisted to disk", settings["appendonly"] == "no" and not settings["save"].strip(),
          f"appendonly {settings['appendonly']}, save '{settings['save']}'")

    try:
        users = connect(secret).execute_command("ACL", "LIST")
    except Exception as exc:  # pragma: no cover - only when the server refuses ACL LIST
        users = [str(exc)]
    rule_line = next((line for line in users if line.startswith(f"user {ACL_USER} ")), "")
    check(f"the product has its own user '{ACL_USER}'", bool(rule_line), rule_line[:90])
    check("that user is confined to its own keys", f"~{KEY_PREFIX}*" in rule_line, f"~{KEY_PREFIX}*")

    return {"checks": checks, "failures": [c["name"] for c in checks if not c["ok"]], "info": {
        "memurai_version": info.get("memurai_version"), "redis_version": info.get("redis_version"),
    }}


def do_health(as_json: bool) -> int:
    report = health()
    if as_json:
        _print(json.dumps({**report, "passed": not report["failures"]}, indent=2, default=str))
    else:
        _print("=== Memurai health ===")
        for item in report["checks"]:
            _print(f"  [{'PASS' if item['ok'] else 'FAIL'}] {item['name']}")
            if item["detail"]:
                _print(f"         {item['detail']}")
        _print("  RESULT: " + ("PASS" if not report["failures"] else "FAIL"))
    return 0 if not report["failures"] else 1


def do_uninstall() -> int:
    if os.name == "nt" and shutil.which("choco"):
        subprocess.run(["choco", "uninstall", "memurai-developer", "memurai-developer.install", "-y", "--no-progress"],
                       capture_output=True, text=True, timeout=1800)
    if service_present():
        _print("the service is still present; remove it from Programs and Features")
        return 1
    _print("Removed.")
    if SECRET_PATH.exists():
        _print(f"The password file is left in place: {SECRET_PATH} (delete it when the install is gone for good).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["install", "configure", "health", "uninstall"], nargs="?", default="health")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.action == "install":
        return do_install()
    if args.action == "configure":
        return do_configure()
    if args.action == "uninstall":
        return do_uninstall()
    return do_health(args.json)


if __name__ == "__main__":
    raise SystemExit(main())
