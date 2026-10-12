"""M2/C1: an old token fails after a password change - on two backends.

C1 moved session state into the database so that it is shared: a revocation made by one
backend must be seen by every other one at once. The earlier C1 tests stood in for a
second backend by clearing the in-process caches; this runs two real servers on one
database and asks the second one about a token the first has just revoked.

That is the case the process-local caches hid. A backend that had already accepted a
token remembered "not revoked" for DSPM_TOKEN_REVOCATION_CACHE_SECONDS (30 s), so the
token signed out, or orphaned by a password change, on backend A kept working on B.
`serve --workers N` turns those caches off inside one server, but two servers started
separately - behind a load balancer, say - each kept its own.
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
from http.cookies import SimpleCookie
from pathlib import Path

from backend import db

ROOT = Path(__file__).resolve().parent.parent
USER = "two-backend-user"
PASSWORD = "a-two-backend-pass-4"
NEW_PASSWORD = "a-changed-backend-pass-7"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _call(port: int, method: str, path: str, *, token: str = "", body: dict | None = None,
          cookie: str = "") -> tuple[int, dict, str]:
    """(status, json body, Set-Cookie refresh value)."""
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if cookie:
        request.add_header("Cookie", f"dspm_refresh={cookie}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status, raw, headers = response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        with error:
            status, raw, headers = error.code, error.read(), error.headers
    refresh = ""
    for header in headers.get_all("Set-Cookie") or []:
        parsed = SimpleCookie(header)
        if "dspm_refresh" in parsed:
            refresh = parsed["dspm_refresh"].value
    try:
        payload = json.loads(raw or b"{}")
    except ValueError:
        payload = {}
    return status, payload, refresh


class TwoBackendsShareOneSessionStateTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(cls.temp.name)
        env = {
            **os.environ,
            "DSPM_DB_PATH": str(root / "shared.sqlite"),
            "DSPM_ARTIFACT_DIR": str(root / "artifacts"),
            "DSPM_LOCAL_ARTIFACT_KEY_PATH": str(root / "artifact_key"),
            "DSPM_SCAN_CACHE_DIR": str(root / "scan_cache"),
            "DSPM_ADMIN_PASSWORD": "harbour-kestrel-two-9",
            "DSPM_SECRET_KEY": "two-backends-share-this-signing-key-0123456789",
            # The default a single server runs with - the case under test.
            "DSPM_TOKEN_REVOCATION_CACHE_SECONDS": "30",
            "DSPM_SCAN_SCHEDULER_INTERVAL_SECONDS": "0",
        }
        # On PostgreSQL (the C1 gate's production backend) both servers share the suite's
        # own test database, and the account is made per test, after the suite's reset.
        # On SQLite they share a file of their own, and the account is made here.
        cls.postgres = db.is_postgres()
        if not cls.postgres:
            env.pop("DSPM_DB_URL", None)
            prepare = (
                "from backend import store, security; "
                f"store.create_user('{USER}', security.hash_password('{PASSWORD}'), 'analyst', 'default')"
            )
            subprocess.run([sys.executable, "-c", prepare], cwd=ROOT, env=env, check=True, timeout=180)
        cls.ports = [_free_port(), _free_port()]
        cls.servers = [
            subprocess.Popen([sys.executable, "main.py", "serve", "--host", "127.0.0.1", "--port", str(port)],
                             cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for port in cls.ports
        ]
        deadline = time.time() + 90
        for port in cls.ports:
            while time.time() < deadline:
                try:
                    if _call(port, "GET", "/api/ready")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.3)
            else:
                cls.tearDownClass()
                raise RuntimeError(f"the backend on {port} did not become ready")

    @classmethod
    def tearDownClass(cls) -> None:
        for server in getattr(cls, "servers", []):
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
        cls.temp.cleanup()

    def setUp(self) -> None:
        if self.postgres:
            from backend import security, store

            if store.get_tenant("default") is None:
                store.create_tenant("default", "Default")
            if store.get_user(USER) is None:
                store.create_user(USER, security.hash_password(PASSWORD), "analyst", "default")

    def _sign_in(self, port: int, password: str = PASSWORD) -> tuple[str, str]:
        status, body, refresh = _call(port, "POST", "/api/auth/login", body={"username": USER, "password": password})
        self.assertEqual(status, 200, body)
        return body["access_token"], refresh

    def test_a_password_change_on_one_ends_the_session_on_the_other(self) -> None:
        a, b = self.ports
        token, _ = self._sign_in(a)
        # B has seen and accepted the token, so any cache it keeps is warm.
        self.assertEqual(_call(b, "GET", "/api/profile", token=token)[0], 200)
        changed = _call(a, "POST", "/api/auth/change-password", token=token,
                        body={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
        self.assertEqual(changed[0], 200, changed[1])
        try:
            self.assertEqual(_call(b, "GET", "/api/profile", token=token)[0], 401,
                             "the other backend must refuse the old token at once")
            self.assertEqual(_call(a, "GET", "/api/profile", token=token)[0], 401)
        finally:
            # Put the password back so the tests stay independent of their order.
            fresh, _ = self._sign_in(a, NEW_PASSWORD)
            _call(a, "POST", "/api/auth/change-password", token=fresh,
                  body={"current_password": NEW_PASSWORD, "new_password": PASSWORD})

    def test_signing_out_on_one_ends_the_token_on_the_other(self) -> None:
        a, b = self.ports
        token, _ = self._sign_in(a)
        self.assertEqual(_call(b, "GET", "/api/profile", token=token)[0], 200)
        self.assertEqual(_call(a, "POST", "/api/auth/logout", token=token)[0], 200)
        self.assertEqual(_call(b, "GET", "/api/profile", token=token)[0], 401)

    def test_a_refresh_token_replayed_on_the_other_ends_the_family(self) -> None:
        a, b = self.ports
        _, first = self._sign_in(a)
        status, body, second = _call(a, "POST", "/api/auth/refresh", cookie=first)
        self.assertEqual(status, 200, body)
        # The retired cookie, presented to the other backend: a replay, wherever it lands.
        self.assertEqual(_call(b, "POST", "/api/auth/refresh", cookie=first)[0], 401)
        self.assertEqual(_call(a, "POST", "/api/auth/refresh", cookie=second)[0], 401,
                         "the whole family ends, including the live cookie")


if __name__ == "__main__":
    unittest.main()
