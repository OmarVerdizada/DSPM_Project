"""C5: each workspace's scan targets - the networks and host names it may scan.

The gate: "out-of-scope targets fail before connect and are audited". Asked of every
way a scan reaches the network: the API before a scan is accepted, and the collectors
when they connect (scheduled, queued and resumed scans never pass the API) - with the
connection itself made to fail the test if it is ever attempted.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4

from fastapi.testclient import TestClient

from backend import store, target_scope
from backend.app import app
from backend.security import create_token, hash_password
from backend.target_scope import Scope, TargetScopeError, decide, parse_entry
from collectors.net_guard import TargetNotAllowed

PASSWORD = "scope-lantern-harbour-7"
ROOT = Path(__file__).resolve().parent.parent


def _gai(*ips: str):
    return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


def _ip(*values: str) -> list:
    return [ipaddress.ip_address(value) for value in values]


def _scope(*entries: str) -> Scope:
    networks, hosts = [], []
    for entry in entries:
        kind, value = parse_entry(entry)
        (networks if kind == "network" else hosts).append(
            ipaddress.ip_network(value) if kind == "network" else value)
    return Scope("t", tuple(networks), tuple(hosts))


class WhatAnEntryMayBeTest(unittest.TestCase):

    def test_networks_addresses_and_names_are_normalised(self) -> None:
        self.assertEqual(parse_entry("10.20.1.7/16"), ("network", "10.20.0.0/16"))
        self.assertEqual(parse_entry(" 192.168.4.10 "), ("network", "192.168.4.10/32"))
        self.assertEqual(parse_entry("2001:db8::/48"), ("network", "2001:db8::/48"))
        self.assertEqual(parse_entry("FS01.Corp.Example."), ("host", "fs01.corp.example"))
        self.assertEqual(parse_entry("*.corp.example"), ("host", "*.corp.example"))

    def test_what_is_refused(self) -> None:
        for value in ("", "0.0.0.0/0", "::/0", "127.0.0.0/8", "127.0.0.1", "169.254.0.0/16", "::1", "224.0.0.0/4",
                      "*", "*.example", "fs*.corp.example", "smb://fs01", "fs01 corp", "10.0.0.0/33", "a..b"):
            with self.subTest(value=value), self.assertRaises(TargetScopeError):
                parse_entry(value)


class TheDecisionTest(unittest.TestCase):

    def test_with_no_list_development_scans_anything_but_what_is_never_a_target(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "local"}):
            self.assertIsNone(decide(Scope("t"), "fs01", _ip("10.0.0.5")))
            self.assertIsNone(decide(Scope("t"), "93.184.216.34", _ip("93.184.216.34")))
            for address in ("127.0.0.1", "169.254.169.254", "fe80::1", "0.0.0.0"):
                with self.subTest(address=address):
                    self.assertIn("never a scan target", decide(Scope("t"), address, _ip(address)))

    def test_with_no_list_production_scans_nothing(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production"}):
            for address in ("10.0.0.5", "93.184.216.34"):
                with self.subTest(address=address):
                    self.assertIn("No scan targets are defined", decide(Scope("t"), address, _ip(address)))

    def test_a_listed_network_holds_every_address_or_nothing_is_scanned(self) -> None:
        scope = _scope("10.20.0.0/16", "192.168.4.10")
        for env in ("local", "production"):
            with self.subTest(env=env), mock.patch.dict(os.environ, {"DSPM_ENV": env}):
                self.assertIsNone(decide(scope, "fs01", _ip("10.20.3.4")))
                self.assertIsNone(decide(scope, "192.168.4.10", _ip("192.168.4.10")))
                self.assertIn("not in this workspace's scan targets", decide(scope, "10.21.0.1", _ip("10.21.0.1")))
                self.assertIn("93.184.216.34", decide(scope, "public.example", _ip("93.184.216.34")))
                # A name that answers with one address inside and one outside is outside.
                self.assertIn("10.99.0.1", decide(scope, "split.corp", _ip("10.20.0.9", "10.99.0.1")))

    def test_a_listed_name_is_in_scope_by_name(self) -> None:
        scope = _scope("fs01.corp.example", "*.branch.corp.example")
        self.assertIsNone(decide(scope, "FS01.corp.example", _ip("10.77.0.1")))
        self.assertIsNone(decide(scope, "nas.oslo.branch.corp.example", _ip("10.8.0.1")))
        self.assertIsNotNone(decide(scope, "branch.corp.example", _ip("10.8.0.2")))
        self.assertIsNotNone(decide(scope, "evilbranch.corp.example", _ip("10.8.0.3")))
        self.assertIsNotNone(decide(scope, "fs02.corp.example", _ip("10.77.0.2")))
        # Listed by name is not a way to reach what is never a target.
        self.assertIn("never a scan target", decide(scope, "fs01.corp.example", _ip("127.0.0.1")))

    def test_a_name_that_does_not_resolve_is_in_scope_only_by_name(self) -> None:
        scope = _scope("10.20.0.0/16", "fs01.corp.example")
        self.assertIsNone(decide(scope, "fs01.corp.example", []))
        self.assertIn("could not be resolved", decide(scope, "gone.corp.example", []))


class _Workspace(unittest.TestCase):

    def setUp(self) -> None:
        self.tenant = f"sc-{uuid4().hex[:8]}"
        self.other = f"sc-{uuid4().hex[:8]}"
        for tenant in (self.tenant, self.other):
            store.create_tenant(tenant, tenant)
        self.client = TestClient(app)
        self.admin = self._user("admin")
        self.operator = self._user("scan_operator")
        self.viewer = self._user("viewer")

    def _user(self, role: str, tenant: str | None = None) -> dict:
        name = f"{role[:5]}-{uuid4().hex[:6]}"
        store.create_user(name, hash_password(PASSWORD), role, tenant or self.tenant)
        return {"Authorization": f"Bearer {create_token(name, role, tenant or self.tenant)}"}

    def _audit(self, action: str, tenant: str | None = None) -> list[dict]:
        return [row for row in store.read_audit_log(tenant or self.tenant, limit=200) if row["action"] == action]

    def _add(self, value: str, headers: dict | None = None):
        return self.client.post("/api/scan-targets", json={"value": value, "note": "test"}, headers=headers or self.admin)


class ManagingTheListTest(_Workspace):

    def test_an_administrator_adds_and_removes_and_both_are_recorded(self) -> None:
        self.assertEqual(self.client.get("/api/scan-targets", headers=self.admin).json()["mode"], "open")
        self.assertEqual(self._add("10.20.0.0/16").status_code, 200)
        view = self._add("fs01.corp.example").json()
        self.assertEqual(view["mode"], "list")
        self.assertEqual(sorted(entry["value"] for entry in view["entries"]), ["10.20.0.0/16", "fs01.corp.example"])
        self.assertEqual(self._add("10.20.9.9/16").status_code, 400, "the same network twice")
        refused = self._add("0.0.0.0/0")
        self.assertEqual(refused.status_code, 400)
        self.assertIn("every address", refused.json()["detail"])
        entry = next(entry for entry in view["entries"] if entry["kind"] == "network")
        after = self.client.delete(f"/api/scan-targets/{entry['entry_id']}", headers=self.admin).json()
        self.assertEqual([entry["value"] for entry in after["entries"]], ["fs01.corp.example"])
        self.assertEqual(self.client.delete(f"/api/scan-targets/{entry['entry_id']}", headers=self.admin).status_code, 404)
        self.assertEqual({row["detail"]["value"] for row in self._audit("scan_targets.added")},
                         {"10.20.0.0/16", "fs01.corp.example"})
        self.assertEqual([row["detail"]["value"] for row in self._audit("scan_targets.removed")], ["10.20.0.0/16"])

    def test_who_may_read_and_who_may_change(self) -> None:
        self.assertEqual(self.client.get("/api/scan-targets", headers=self.viewer).status_code, 403)
        seen = self.client.get("/api/scan-targets", headers=self.operator)
        self.assertEqual(seen.status_code, 200)
        self.assertFalse(seen.json()["editable"])
        self.assertTrue(self.client.get("/api/scan-targets", headers=self.admin).json()["editable"])
        self.assertEqual(self._add("10.20.0.0/16", self.operator).status_code, 403)
        self.assertEqual(self._add("10.20.0.0/16", self.viewer).status_code, 403)

    def test_one_workspaces_list_is_its_own(self) -> None:
        self._add("10.20.0.0/16")
        other_admin = self._user("admin", self.other)
        self.assertEqual(self.client.get("/api/scan-targets", headers=other_admin).json()["entries"], [])
        entry_id = store.list_scan_targets(self.tenant)[0]["entry_id"]
        self.assertEqual(self.client.delete(f"/api/scan-targets/{entry_id}", headers=other_admin).status_code, 404)
        self.assertEqual(len(store.list_scan_targets(self.tenant)), 1)

    def test_erasing_the_workspace_erases_its_list(self) -> None:
        self._add("10.20.0.0/16")
        store.delete_tenant_with_data(self.tenant)
        self.assertEqual(store.list_scan_targets(self.tenant), [])

    def test_checking_a_host_answers_and_records_nothing(self) -> None:
        self._add("10.20.0.0/16")
        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("10.99.0.1")):
            answer = self.client.post("/api/scan-targets/check", json={"host": "outside.corp"}, headers=self.operator).json()
        self.assertFalse(answer["allowed"])
        self.assertIn("10.99.0.1", answer["reason"])
        self.assertTrue(self.client.post("/api/scan-targets/check", json={"host": "10.20.1.1"},
                                         headers=self.operator).json()["allowed"])
        self.assertEqual(self._audit("scan.target_refused"), [])


def _never_connect(*args, **kwargs):
    raise AssertionError("a connection was attempted to a target outside the list")


class OutOfScopeFailsBeforeConnectTest(_Workspace):
    """The gate, at each place a scan reaches the network."""

    def setUp(self) -> None:
        super().setUp()
        self._add("10.20.0.0/16")

    def test_the_api_refuses_a_scan_and_records_who_asked(self) -> None:
        with mock.patch("smb.SMBConnection.SMBConnection", side_effect=_never_connect), \
                mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("10.99.0.1")):
            for path, body in (("/api/test-connection", {"server": "fs9.corp.example"}),
                               ("/api/scan", {"server": "fs9.corp.example"}),
                               ("/api/endpoint/test-connection", {"host": "fs9.corp.example", "username": "u", "password": "p"}),
                               ("/api/endpoint/scan", {"host": "fs9.corp.example", "username": "u", "password": "p"})):
                with self.subTest(path=path):
                    response = self.client.post(path, json=body, headers=self.operator)
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertIn("not in this workspace's scan targets", response.json()["detail"])
        refused = self._audit("scan.target_refused")
        self.assertEqual(len(refused), 4)
        self.assertTrue(all(row["detail"]["target"] == "fs9.corp.example" and row["detail"]["where"] == "api"
                            for row in refused))
        self.assertEqual({row["detail"]["addresses"][0] for row in refused}, {"10.99.0.1"})

    def test_the_smb_collector_refuses_before_it_connects(self) -> None:
        from collectors.smb_scanner import SMBConfig, SMBScanner

        scanner = SMBScanner(SMBConfig(server="10.99.0.1", username="u", password="p", tenant_id=self.tenant))
        with mock.patch("smb.SMBConnection.SMBConnection", side_effect=_never_connect):
            with self.assertRaises(ConnectionError) as refused:
                scanner.scan()
        self.assertIn("not in this workspace's scan targets", str(refused.exception))
        row = self._audit("scan.target_refused")[0]
        self.assertEqual((row["actor"], row["detail"]["where"]), ("scan", "connect"))

    def test_the_endpoint_collector_refuses_before_it_connects(self) -> None:
        from collectors.winrm_endpoint_scanner import WinRMEndpointConfig, WinRMEndpointScanner

        scanner = WinRMEndpointScanner(WinRMEndpointConfig(host="10.99.0.1", username="u", password="p",
                                                           tenant_id=self.tenant))
        with self.assertRaises(TargetNotAllowed):
            scanner._endpoint_url("10.99.0.1")
        self.assertEqual(self._audit("scan.target_refused")[0]["detail"]["where"], "connect")

    def test_a_scan_that_never_passed_the_api_is_refused_too(self) -> None:
        # Scheduled, queued and resumed scans are rebuilt from a stored request and run by
        # the engine directly. The engine hands the workspace to the collector.
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        engine = DSPMDiscoveryEngine(ScanConfig(tenant_id=self.tenant, server="10.99.0.1", username="u",
                                                password="p", persistent_cache_enabled=False,
                                                incremental_enabled=False))
        with mock.patch("smb.SMBConnection.SMBConnection", side_effect=_never_connect):
            try:
                engine.run()
            except ConnectionError:
                pass
        self.assertTrue(self._audit("scan.target_refused"), "the refusal is in the workspace's trail")

    def test_a_listed_target_is_dialled_at_the_address_that_was_checked(self) -> None:
        from collectors.net_guard import resolve_and_pin

        with mock.patch("collectors.net_guard.socket.getaddrinfo", return_value=_gai("10.20.5.5")):
            self.assertEqual(resolve_and_pin("fs1.corp.example", tenant_id=self.tenant), "10.20.5.5")
        self.assertEqual(self._audit("scan.target_refused"), [])


class TheOldSwitchTest(unittest.TestCase):

    def test_an_install_that_still_sets_it_is_told_it_is_not_read(self) -> None:
        client = TestClient(app)
        with mock.patch.dict(os.environ, {"DSPM_ALLOW_PRIVATE_TARGETS": "1"}):
            warnings = client.get("/api/ready").json()["warnings"]
        self.assertTrue(any("DSPM_ALLOW_PRIVATE_TARGETS is set but no longer read" in item for item in warnings))
        with mock.patch.dict(os.environ, {"DSPM_ALLOW_PRIVATE_TARGETS": ""}):
            self.assertFalse(any("DSPM_ALLOW_PRIVATE_TARGETS" in item for item in client.get("/api/ready").json()["warnings"]))


@unittest.skipUnless(shutil.which("node"), "Node.js runs the console's own code")
class TheConsolePanelTest(unittest.TestCase):
    """The Security operations panel, driven in the real frontend/app.js."""

    def _evaluate(self, expressions: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "scenario.json"
            fixture.write_text(json.dumps({"script": "app.js", "drive": "evaluate", "permissions": ["tenant.admin"],
                                           "evaluate": expressions}), encoding="utf-8")
            run = subprocess.run([shutil.which("node"), str(ROOT / "tests" / "js" / "refresh_retry_smoke.js"),
                                  str(fixture)], cwd=ROOT, capture_output=True, encoding="utf-8", timeout=180)
        report = json.loads(run.stdout.strip().splitlines()[-1])
        self.assertIsNone(report.get("error"), report.get("error"))
        return report["values"]

    def test_the_line_says_what_the_list_means_now(self) -> None:
        values = self._evaluate({
            "open": "scanTargetsModeLine({mode: 'open', entries: []})",
            "closed": "scanTargetsModeLine({mode: 'closed', entries: []})",
            "list": "scanTargetsModeLine({mode: 'list', entries: [{}, {}]})",
        })
        self.assertIn("development install", values["open"])
        self.assertIn("Nothing on the network can be scanned yet", values["closed"])
        self.assertIn("(2 entries) can be scanned", values["list"])

    def test_remove_is_offered_only_to_whoever_may_change_the_list(self) -> None:
        entry = "{entry_id: 'e1', kind: 'network', value: '10.20.0.0/16', note: '<b>finance</b>'}"
        values = self._evaluate({
            "admin": f"scanTargetsListHtml({{editable: true, entries: [{entry}]}})",
            "operator": f"scanTargetsListHtml({{editable: false, entries: [{entry}]}})",
            "none": "scanTargetsListHtml({editable: true, entries: []})",
        })
        self.assertIn('data-remove-scan-target="e1"', values["admin"])
        self.assertNotIn("data-remove-scan-target", values["operator"])
        self.assertIn("10.20.0.0/16", values["operator"])
        self.assertNotIn("<b>finance</b>", values["admin"], "a note is text, never markup")
        self.assertIn("No scan targets listed", values["none"])


class ProductionWithNoListTest(_Workspace):

    def test_nothing_is_scanned_until_targets_are_listed(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production"}), \
                mock.patch("smb.SMBConnection.SMBConnection", side_effect=_never_connect):
            view = self.client.get("/api/scan-targets", headers=self.admin).json()
            self.assertEqual(view["mode"], "closed")
            response = self.client.post("/api/test-connection", json={"server": "93.184.216.34"}, headers=self.operator)
            self.assertEqual(response.status_code, 403)
            self.assertIn("No scan targets are defined", response.json()["detail"])
            self._add("93.184.216.0/24")
            with mock.patch.object(target_scope, "resolve_addresses", return_value=_ip("93.184.216.34")):
                self.assertIsNone(target_scope.check(self.tenant, "93.184.216.34", actor="t", where="test"))


if __name__ == "__main__":
    unittest.main()
