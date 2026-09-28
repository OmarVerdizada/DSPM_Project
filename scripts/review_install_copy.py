"""Review an installation's security configuration on a DISPOSABLE COPY of its database.

    python scripts/review_install_copy.py [--db data/dspm.sqlite] [--port 8973]
                                          [--report docs/evidence/install-review.json]

M2's exit review asks for the ASVS checks "against the actual deployment ... on a
disposable copy so active tenant state is not changed". This is that review, re-runnable:

1. The database is copied with SQLite's online backup API from a READ-ONLY connection, so
   a running server keeps running and nothing is written to the install.
2. `main.py audit verify` checks every tenant's audit hash chain on the copy.
3. This tree's server is started on the copy (loopback, its own port, temporary keys and
   directories) and asked: is it ready at this tree's schema; does every page carry the
   strict CSP and the security headers; is every versioned asset URL its content digest;
   does the console name another origin; are sensitive API calls refused without a
   session (each with the method the route takes); is the API never cached.
4. The production boundary is evaluated with the install's current configuration, to name
   what a production start would refuse.
5. The copy and everything the server wrote are deleted, and a JSON report is written.

Exit status 1 when any check fails. The copy's server never sees the install's keys, so
it cannot decrypt a vaulted credential or sign a session the install would accept.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# (method, path): calls that must be refused without a session.
SENSITIVE = [("GET", "/api/findings"), ("GET", "/api/inventory"), ("GET", "/api/audit"), ("GET", "/api/users"),
             ("GET", "/api/scan-targets"), ("GET", "/api/settings/siem"), ("POST", "/api/v1/reports/office"),
             ("POST", "/api/v1/reports"), ("POST", "/api/scan")]
HEADERS = {"x-content-type-options": "nosniff", "x-frame-options": "DENY",
           "referrer-policy": "strict-origin-when-cross-origin"}


class Review:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"check": name, "passed": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}{' - ' + detail if detail else ''}", flush=True)


def _request(base: str, method: str, path: str) -> tuple[int, dict, bytes]:
    data = b"{}" if method == "POST" else None
    request = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as error:
        return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()


def _environment(home: Path, copy: Path) -> dict:
    env = {key: value for key, value in os.environ.items() if not key.startswith("DSPM_")}
    env.update({
        "DSPM_DB_PATH": str(copy), "DSPM_ENV": "local", "PYTHONIOENCODING": "utf-8",
        "DSPM_ARTIFACT_DIR": str(home / "artifacts"), "DSPM_SCAN_CACHE_DIR": str(home / "cache"),
        "DSPM_BACKUP_DIR": str(home / "backups"), "DSPM_REPORT_DIR": str(home / "reports"),
        "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(home / "artifact.key"), "DSPM_LOCAL_JWT_SECRET_PATH": str(home / "jwt"),
        "DSPM_LOCAL_VAULT_KEY_PATH": str(home / "vault.key"), "DSPM_LOCAL_BACKUP_KEY_PATH": str(home / "backup.key"),
        "DSPM_LOCAL_EVIDENCE_KEY_PATH": str(home / "evidence.key"),
    })
    return env


def review(db: Path, port: int) -> dict:
    result = Review()
    home = Path(tempfile.mkdtemp(prefix="sentro-install-review-"))
    copy = home / "copy.sqlite"
    base = f"http://127.0.0.1:{port}"
    env = _environment(home, copy)
    try:
        source = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)
        target = sqlite3.connect(copy)
        source.backup(target)
        source.close()
        target.close()
        print(f"copied {db} ({db.stat().st_size:,} bytes, plus its WAL) read-only")

        verify = subprocess.run([sys.executable, "main.py", "audit", "verify"], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=1800)
        lines = verify.stdout.strip().splitlines() or [verify.stderr.strip()[:300]]
        result.check("audit hash chains verify (V7)", verify.returncode == 0, " | ".join(lines)[:400])

        server = subprocess.Popen([sys.executable, "main.py", "serve", "--host", "127.0.0.1", "--port", str(port)],
                                  cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready: dict = {}
            for _ in range(180):
                try:
                    status, _headers, body = _request(base, "GET", "/api/ready")
                    if status == 200:
                        ready = json.loads(body)
                        break
                except OSError:
                    pass
                time.sleep(1)
            revision = (ready.get("database") or {}).get("schema_revision") or {}
            result.check("the copy upgrades to this tree's schema and is ready",
                         ready.get("ready") is True and revision.get("applied") == revision.get("expected"),
                         json.dumps(revision))

            for page in ("/", "/dashboard", "/profile"):
                status, headers, body = _request(base, "GET", page)
                csp = headers.get("content-security-policy", "")
                result.check(f"{page}: strict CSP (V14)", status == 200 and "'unsafe-inline'" not in csp
                             and "default-src 'self'" in csp and "http" not in csp, csp[:160])
                wrong = {name: headers.get(name) for name, value in HEADERS.items() if headers.get(name) != value}
                result.check(f"{page}: security headers (V14)", not wrong, json.dumps(wrong))
                html = body.decode("utf-8", "replace")
                references = re.findall(r'/static/([A-Za-z0-9_./-]+)\?v=([^"\']+)', html)
                stale = [name for name, version in references
                         if hashlib.sha256((ROOT / "frontend" / name).read_bytes()).hexdigest()[:12] != version]
                result.check(f"{page}: every versioned asset URL is its content digest (C6)",
                             bool(references) and not stale, f"{len(references)} references, stale={stale}")
                external = re.findall(r'(?:src|href)="((?:https?:)?//[^"]+)"', html)
                result.check(f"{page}: no other origin (C6)", not external, str(external[:3]))

            for method, path in SENSITIVE:
                status, _headers, _body = _request(base, method, path)
                result.check(f"{method} {path} without a session is refused (V4)", status == 401, str(status))
            status, headers, _body = _request(base, "GET", "/api/ready")
            result.check("the API is never cached (V8)", headers.get("cache-control") == "no-store",
                         str(headers.get("cache-control")))
        finally:
            server.terminate()
            try:
                server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                server.kill()

        # The install's own configuration, read as a production start would read it.
        probe_env = {key: value for key, value in os.environ.items()}
        probe_env["DSPM_ENV"] = "production"
        probe_env["DSPM_DB_PATH"] = str(copy)
        probe = subprocess.run([sys.executable, "-c", (
            "from backend import deployment_boundary as b;"
            "print('\\n'.join(b.production_problems(b.trusted_hosts_setting(), b.cors_origins_setting(), '127.0.0.1')))")],
            cwd=ROOT, env=probe_env, capture_output=True, text=True, timeout=120)
        problems = [line for line in probe.stdout.splitlines() if line.strip()]
        result.check("the production boundary can be evaluated (V13)", probe.returncode == 0,
                     f"{len(problems)} thing(s) a production start would refuse")
    finally:
        shutil.rmtree(home, ignore_errors=True)
    print("copy removed:", not home.exists())
    failed = [item for item in result.checks if not item["passed"]]
    return {
        "reviewed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "database": str(db), "database_bytes": db.stat().st_size,
        "commit": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                                 text=True).stdout.strip(),
        "working_tree_clean": not subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
                                                 capture_output=True, text=True).stdout.strip(),
        "passed": len(result.checks) - len(failed), "failed": len(failed),
        "checks": result.checks, "production_boundary_problems": problems,
        "copy_removed": not home.exists(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", type=Path, default=ROOT / "data" / "dspm.sqlite")
    parser.add_argument("--port", type=int, default=8973)
    parser.add_argument("--report", type=Path, default=None, help="write the JSON report here")
    args = parser.parse_args(argv)
    report = review(args.db, args.port)
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text + "\n", encoding="utf-8")
        print("report:", args.report)
    print(f"\n{report['passed']}/{report['passed'] + report['failed']} checks passed")
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
