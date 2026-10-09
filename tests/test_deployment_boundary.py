"""C5: the network boundary a production install refuses to start without, and the
client address no request can choose for itself.

The gate: "unsafe production configurations refuse startup; proxy spoof cannot bypass
throttle". Each refused configuration is a test here, and the throttle is tried against
a real `main.py serve` - the stack a deployment runs, where uvicorn's own proxy handling
sits in front of the app and TestClient would not have shown it.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.testclient import TestClient

from backend import deployment_boundary
from backend.app import app
from backend.client_address import request_address, request_scheme

ROOT = Path(__file__).resolve().parent.parent
GOOD = {
    "DSPM_ENV": "production",
    "DSPM_TRUSTED_HOSTS": "sentro.corp.example",
    "DSPM_CORS_ORIGINS": "",
    "DSPM_TRUSTED_PROXIES": "127.0.0.1",
    "DSPM_ALLOW_EXTERNAL_BIND": "",
}


def _problems(hosts="sentro.corp.example", origins="", bind=None, **env) -> list[str]:
    split = lambda value: [item.strip() for item in value.split(",") if item.strip()]  # noqa: E731
    with mock.patch.dict(os.environ, {**GOOD, **env}):
        return deployment_boundary.production_problems(split(hosts), split(origins), bind)


class WhatProductionRefusesTest(unittest.TestCase):

    def test_a_safe_configuration_passes(self) -> None:
        self.assertEqual(_problems(bind="127.0.0.1"), [])
        self.assertEqual(_problems(origins="https://portal.corp.example", bind="localhost"), [])

    def test_no_trusted_host(self) -> None:
        self.assertIn("DSPM_TRUSTED_HOSTS is empty", " ".join(_problems(hosts="")))

    def test_a_wildcard_host(self) -> None:
        for hosts in ("*", "sentro.corp.example, *.corp.example"):
            with self.subTest(hosts=hosts):
                self.assertIn("wildcard", " ".join(_problems(hosts=hosts)))

    def test_a_wildcard_local_or_plain_http_origin(self) -> None:
        refused = {
            "*": "wildcard",
            "http://localhost:8000": "local origin",
            "https://localhost": "local origin",
            "https://127.0.0.1:8443": "local origin",
            "https://[::1]:8443": "local origin",
            "https://sentro.localhost": "local origin",
            "https://0.0.0.0": "local origin",
            "http://sentro.corp.example": "not an https:// origin",
        }
        for origin, reason in refused.items():
            with self.subTest(origin=origin):
                self.assertIn(reason, " ".join(_problems(origins=origin)))

    def test_a_proxy_list_that_is_unreadable_or_trusts_everyone(self) -> None:
        for proxies, reason in (("proxy.corp", "not an address"), ("0.0.0.0/0", "trusts every address"),
                                ("::/0", "trusts every address")):
            with self.subTest(proxies=proxies):
                self.assertIn(reason, " ".join(_problems(DSPM_TRUSTED_PROXIES=proxies)))

    def test_serving_off_loopback_without_saying_so(self) -> None:
        self.assertIn("not loopback", " ".join(_problems(bind="0.0.0.0")))
        self.assertIn("not loopback", " ".join(_problems(bind="10.1.2.3")))
        self.assertEqual(_problems(bind="0.0.0.0", DSPM_ALLOW_EXTERNAL_BIND="1"), [])

    def test_serving_on_loopback_with_no_trusted_proxy(self) -> None:
        message = " ".join(_problems(bind="127.0.0.1", DSPM_TRUSTED_PROXIES=""))
        self.assertIn("DSPM_TRUSTED_PROXIES does not name it", message)
        self.assertEqual(_problems(bind="127.0.0.1", DSPM_TRUSTED_PROXIES="127.0.0.0/8"), [])

    def test_production_has_no_cross_origin_list_unless_one_is_set(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production"}):
            os.environ.pop("DSPM_CORS_ORIGINS", None)
            self.assertEqual(deployment_boundary.cors_origins_setting(), [])
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local"}):
            os.environ.pop("DSPM_CORS_ORIGINS", None)
            self.assertIn("http://localhost:8000", deployment_boundary.cors_origins_setting())

    def test_every_problem_is_named_at_once_and_development_is_not_checked(self) -> None:
        with mock.patch.dict(os.environ, {**GOOD, "DSPM_TRUSTED_PROXIES": "0.0.0.0/0"}):
            with self.assertRaises(RuntimeError) as refused:
                deployment_boundary.enforce([], ["*"], "0.0.0.0")
        text = str(refused.exception)
        for fragment in ("DSPM_TRUSTED_HOSTS is empty", "wildcard", "trusts every address", "not loopback"):
            self.assertIn(fragment, text)
        with mock.patch.dict(os.environ, {**GOOD, "DSPM_ENV": "local"}):
            deployment_boundary.enforce([], ["*"], "0.0.0.0")  # nothing raised


def _startup_env(tmp: str, **extra) -> dict:
    from backend.config import TEST_ONLY

    # A production process as a host would start it: none of the suite's own switches
    # (DSPM_PG_TEST_RESET on the PostgreSQL run), which production refuses (C11).
    env = {key: value for key, value in os.environ.items() if key != "DSPM_DB_URL" and key not in TEST_ONLY}
    env.update({
        "DSPM_DB_PATH": str(Path(tmp) / "boundary.sqlite"),
        "DSPM_ARTIFACT_DIR": str(Path(tmp) / "artifacts"),
        "DSPM_MIGRATIONS_CLI": "1",   # keep the import from touching any schema
        **GOOD, **extra,
    })
    return env


class TheInstallRefusesToStartTest(unittest.TestCase):
    """The same rules where they are enforced: importing the app, and `main.py serve`."""

    def test_the_app_will_not_import_with_an_unsafe_boundary(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            run = subprocess.run([sys.executable, "-c", "import backend.app"], cwd=ROOT, capture_output=True,
                                 text=True, timeout=180,
                                 env=_startup_env(tmp, DSPM_TRUSTED_HOSTS="", DSPM_CORS_ORIGINS="http://localhost:8000"))
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("Refusing to start in production", run.stderr)
        self.assertIn("DSPM_TRUSTED_HOSTS is empty", run.stderr)
        self.assertIn("local origin", run.stderr)

    def test_a_safe_boundary_goes_on_to_the_next_check(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            env = _startup_env(tmp)
            env.pop("DSPM_CORS_ORIGINS")   # the production default: no cross-origin list
            run = subprocess.run([sys.executable, "-c", "import backend.app"], cwd=ROOT, capture_output=True,
                                 text=True, timeout=180, env=env)
        self.assertNotIn("Refusing to start in production", run.stderr)
        # ...which fails on the next production requirement (a signing key, then
        # PostgreSQL), not on the boundary: the boundary passed.
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("production", run.stderr.strip().splitlines()[-1])

    def test_serve_refuses_to_listen_off_loopback_or_without_its_proxy(self) -> None:
        # C11: `main.py` checks the whole production configuration before anything starts,
        # so without its keys serve is refused for those, every one named...
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            run = subprocess.run([sys.executable, "main.py", "serve", "--host", "127.0.0.1", "--port", "1"],
                                 cwd=ROOT, capture_output=True, text=True, timeout=180, env=_startup_env(tmp))
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("DSPM_VAULT_KEY (or DSPM_VAULT_KEY_FILE) must be set in production", run.stderr)
        # ...and with them, on the boundary.
        keys = {"DSPM_SECRET_KEY": "k" * 48, "DSPM_VAULT_KEY": "v" * 44, "DSPM_ARTIFACT_KEY": "a" * 44,
                "DSPM_BACKUP_KEY": "b" * 44, "DSPM_EVIDENCE_HMAC_KEY": "e" * 48,
                "DSPM_ADMIN_PASSWORD": "Kestrel-boundary-771", "DSPM_DB_URL": "postgresql://app:pw@127.0.0.1:1/none"}
        for host, extra, reason in (("0.0.0.0", {}, "not loopback"),
                                    ("127.0.0.1", {"DSPM_TRUSTED_PROXIES": ""}, "DSPM_TRUSTED_PROXIES does not name it")):
            with self.subTest(host=host), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                run = subprocess.run([sys.executable, "main.py", "serve", "--host", host, "--port", "1"],
                                     cwd=ROOT, capture_output=True, text=True, timeout=180,
                                     env=_startup_env(tmp, **keys, **extra))
                self.assertNotEqual(run.returncode, 0)
                self.assertIn(reason, run.stderr)

    def test_serve_leaves_forwarded_headers_to_the_app(self) -> None:
        import main

        with mock.patch.object(main.uvicorn, "run") as run, mock.patch.dict(os.environ, {"DSPM_ENV": "local"}):
            main.serve(SimpleNamespace(host="127.0.0.1", port=8000, reload=False, workers=1))
        self.assertIs(run.call_args.kwargs["proxy_headers"], False)


class TheForwardedHeadersTest(unittest.TestCase):

    def _request(self, peer: str, headers: list[tuple[str, str]], scheme: str = "http"):
        from starlette.datastructures import Headers

        raw = [(name.lower().encode(), value.encode()) for name, value in headers]
        return SimpleNamespace(client=SimpleNamespace(host=peer), headers=Headers(raw=raw),
                               url=SimpleNamespace(scheme=scheme))

    def test_every_forwarded_for_line_is_read(self) -> None:
        # A proxy that adds its own line leaves the client's forgery first.
        request = self._request("127.0.0.1", [("X-Forwarded-For", "1.2.3.4"), ("X-Forwarded-For", "203.0.113.9")])
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": "127.0.0.1"}):
            self.assertEqual(request_address(request), "203.0.113.9")

    def test_the_scheme_is_the_trusted_proxys_word_and_nobody_elses(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": "127.0.0.1"}):
            self.assertEqual(request_scheme(self._request("127.0.0.1", [("X-Forwarded-Proto", "https")])), "https")
            self.assertEqual(request_scheme(self._request("198.51.100.4", [("X-Forwarded-Proto", "https")])), "http")
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": ""}):
            self.assertEqual(request_scheme(self._request("127.0.0.1", [("X-Forwarded-Proto", "https")])), "http")

    def test_a_forgery_on_its_own_line_does_not_escape_the_throttle(self) -> None:
        client = TestClient(app, client=("127.0.0.1", 50000))
        statuses = []
        with mock.patch.dict(os.environ, {"DSPM_TRUSTED_PROXIES": "127.0.0.1"}):
            for attempt in range(12):
                response = client.post(
                    "/api/auth/login", json={"username": "spoof-line", "password": "not-it-at-all-1"},
                    headers=[("X-Forwarded-For", f"10.9.{attempt}.1"), ("X-Forwarded-For", "203.0.113.9")])
                statuses.append(response.status_code)
        self.assertIn(429, statuses, statuses)
        self.assertEqual(statuses.index(429), 8, "blocked after the per-account limit, as one client")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class AForgedAddressDoesNotEscapeTheThrottleTest(unittest.TestCase):
    """The gate's words - "proxy spoof cannot bypass throttle" - against a real server.
    uvicorn believes X-Forwarded-For from 127.0.0.1 by default; on a backend served on
    loopback that meant any local program could claim a fresh address per attempt."""

    def test_a_new_forwarded_address_per_attempt_is_still_one_client(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            env = {key: value for key, value in os.environ.items() if key != "DSPM_DB_URL"}
            env.update({
                "DSPM_ENV": "local", "DSPM_DB_PATH": str(Path(tmp) / "spoof.sqlite"),
                "DSPM_ARTIFACT_DIR": str(Path(tmp) / "artifacts"),
                "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(Path(tmp) / "artifact_key"),
                "DSPM_SCAN_CACHE_DIR": str(Path(tmp) / "scan_cache"),
                "DSPM_ADMIN_PASSWORD": "boundary-heron-lantern-4", "DSPM_TRUSTED_PROXIES": "",
                "DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS": "0",
            })
            port = _free_port()
            server = subprocess.Popen([sys.executable, "main.py", "serve", "--host", "127.0.0.1", "--port", str(port)],
                                      cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.time() + 90
                while True:
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ready", timeout=5) as ready:
                            if ready.status == 200:
                                break
                    except (OSError, urllib.error.URLError):
                        pass
                    if time.time() > deadline:
                        self.fail("the server did not become ready")
                    time.sleep(0.3)
                statuses = []
                for attempt in range(12):
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/auth/login", method="POST",
                        data=json.dumps({"username": "spoof-target", "password": "not-it-at-all-2"}).encode())
                    request.add_header("Content-Type", "application/json")
                    request.add_header("X-Forwarded-For", f"198.51.{attempt}.7")
                    try:
                        with urllib.request.urlopen(request, timeout=30) as response:
                            statuses.append(response.status)
                    except urllib.error.HTTPError as error:
                        statuses.append(error.code)
            finally:
                server.terminate()
                try:
                    server.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    server.kill()
        self.assertIn(429, statuses, f"twelve attempts, each claiming a new address, were never throttled: {statuses}")
        self.assertEqual(statuses.index(429), 8)


if __name__ == "__main__":
    unittest.main()
