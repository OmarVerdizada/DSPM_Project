"""D11: production observability - metrics a pilot's monitoring scrapes, alerts on a stuck
queue and a failed or stale backup, and logs a shipper can read.

Gate line: "Pilot monitoring scrapes metrics; queue and backup failure alert;
failover/failback drill meets agreed targets." The last clause needs a second node and a
replicated database: HELD. The pilot's own Prometheus is the live half of the first.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import logging_setup, metrics, ops_alerts, security, store
from backend.app import app

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Kestrel-lantern-4471"
TOKEN = "scrape-token-for-tests-only-7f3a"
SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*",?)*\})? -?[0-9.e+-]+$')


def parse(text: str) -> dict[str, list[tuple[str, float]]]:
    """Every sample, checked against the text format; {name: [(labels, value)]}."""
    samples: dict[str, list[tuple[str, float]]] = {}
    typed = set()
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            typed.add(line.split()[2])
            continue
        if line.startswith("#") or not line:
            continue
        assert SAMPLE.match(line), f"not a Prometheus sample: {line!r}"
        name_labels, value = line.rsplit(" ", 1)
        name, _, labels = name_labels.partition("{")
        base = re.sub(r"_(bucket|sum|count)$", "", name)
        assert base in typed or name in typed, f"{name} has no TYPE line"
        samples.setdefault(name, []).append((labels.rstrip("}"), float(value)))
    return samples


class D11Case(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d11.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        if store.get_tenant("default") is None:
            store.create_tenant("default", "Default")
        store.create_tenant("t-d11", "t-d11")
        if store.get_user("admin") is None:
            store.create_user("admin", security.hash_password(PASSWORD), "admin", "default")
        store.create_user("d11-admin", security.hash_password(PASSWORD), "admin", "t-d11")
        patcher = mock.patch.dict(os.environ, {"DSPM_METRICS_TOKEN": TOKEN,
                                               "DSPM_BACKUP_DIR": str(self.tmp / "backups")})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(app)

    def scrape(self, token: str = TOKEN):
        return self.client.get("/metrics", headers={"Authorization": f"Bearer {token}"} if token else {})

    def as_(self, user: str = "admin", tenant: str = "default") -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, 'admin', tenant, mfa_verified=True)}"}


class TheMetricsTest(D11Case):

    def test_a_scraper_with_the_token_reads_valid_prometheus_text(self) -> None:
        response = self.scrape()
        self.assertEqual(response.status_code, 200, response.text[:300])
        self.assertTrue(response.headers["content-type"].startswith("text/plain; version=0.0.4"))
        samples = parse(response.text)
        for name in ("sentro_up", "sentro_ready", "sentro_build_info", "sentro_http_requests_total",
                     "sentro_http_request_duration_seconds_bucket", "sentro_scan_job_oldest_queued_seconds",
                     "sentro_siem_outbox_events", "sentro_alert_deliveries_pending", "sentro_backup_age_seconds",
                     "sentro_licence_valid", "sentro_collector_up"):
            self.assertIn(name, samples)
        self.assertEqual({labels: value for labels, value in samples["sentro_collector_up"]},
                         {'collector="queue"': 1, 'collector="siem"': 1, 'collector="alerts"': 1,
                          'collector="backup"': 1, 'collector="licence"': 1})
        ready = self.client.get("/api/ready").status_code == 200
        self.assertEqual(samples["sentro_ready"][0][1], 1 if ready else 0, "the same answer as /api/ready")

    def test_only_the_token_or_the_installation_administrator_reads_them(self) -> None:
        self.assertEqual(self.scrape("").status_code, 401)
        self.assertEqual(self.scrape("not-the-token").status_code, 401)
        self.assertEqual(self.client.get("/metrics", headers=self.as_("d11-admin", "t-d11")).status_code, 403)
        self.assertEqual(self.client.get("/metrics", headers=self.as_()).status_code, 200)
        with mock.patch.dict(os.environ, {"DSPM_METRICS_TOKEN": ""}):
            self.assertEqual(self.scrape().status_code, 401, "no token configured: the token means nothing")

    def test_they_count_the_installation_never_a_workspace(self) -> None:
        store.save_alert_channel("t-d11", "webhook", enabled=True, config={"url": "https://x.test", "min_severity": "LOW"},
                                 secret_ref="", actor="t")
        store.save_alerts("t-d11", "scan-1", [{"severity": "CRITICAL", "title": "secret-title-xyz"}])
        text = self.scrape().text
        for private in ("t-d11", "secret-title-xyz", "x.test", TOKEN):
            self.assertNotIn(private, text)
        self.assertEqual(parse(text)["sentro_alert_deliveries_pending"][0][1], 1)

    def test_requests_are_counted_by_method_and_status_not_path(self) -> None:
        self.client.get("/api/findings/finding_secret123", headers=self.as_())
        samples = parse(self.scrape().text)
        self.assertTrue(any('code="404"' in labels or 'code="200"' in labels
                            for labels, _ in samples["sentro_http_requests_total"]))
        self.assertNotIn("finding_secret123", self.scrape().text)
        methods = {re.search(r'method="([^"]*)"', labels).group(1) for labels, _ in samples["sentro_http_requests_total"]}
        self.assertLessEqual(methods, {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

    def test_an_invented_method_or_status_makes_no_new_series(self) -> None:
        """M4 exit review: every request is counted before it is authenticated and the server
        accepts any token as a method, so a client inventing methods made a new series with
        each one, without limit. Anything not known is OTHER; a status outside 100-599 is 0."""
        with mock.patch.dict(metrics._requests, clear=True):
            for index in range(40):
                metrics.record_request(f"AAAAAAAAA{index}", 405, 0.01)
                metrics.record_request("get", 1000 + index, 0.01)
            metrics.record_request("BREW", -7, 0.01)
            metrics.record_request("DELETE", 204, 0.01)
            self.assertEqual(metrics._requests, {("OTHER", "405"): 40, ("GET", "0"): 40, ("OTHER", "0"): 1,
                                                 ("DELETE", "204"): 1})
            # The same through the server's own middleware.
            before = dict(metrics._requests)
            self.client.request("AAAAAAAAA1", "/api/health")
            counted = {key for key, value in metrics._requests.items() if value != before.get(key)}
            self.assertEqual({method for method, _code in counted}, {"OTHER"}, metrics._requests)
            exposed = parse(metrics.render(ready=True, build={}))["sentro_http_requests_total"]
        methods = {re.search(r'method="([^"]*)"', labels).group(1) for labels, _ in exposed}
        self.assertEqual(methods, {"OTHER", "GET", "DELETE"})
        self.assertNotIn("AAAAAAAAA", str(exposed))

    def test_a_queued_scan_and_a_failing_siem_show(self) -> None:
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with store._connect() as conn:
            conn.execute("INSERT INTO scan_jobs (id, tenant_id, status, created_at, updated_at) VALUES (?, ?, 'queued', ?, ?)",
                         ("job-d11", "t-d11", old, old))
        samples = parse(self.scrape().text)
        self.assertIn(('state="queued"', 1.0), samples["sentro_scan_jobs"])
        self.assertGreater(samples["sentro_scan_job_oldest_queued_seconds"][0][1], 7000)

    def test_a_failing_collector_is_reported_and_the_rest_still_answer(self) -> None:
        with mock.patch.object(store, "metrics_scan_jobs", side_effect=RuntimeError("down")):
            samples = parse(self.scrape().text)
        self.assertIn(('collector="queue"', 0.0), samples["sentro_collector_up"])
        self.assertIn("sentro_siem_outbox_events", samples)
        self.assertNotIn("sentro_scan_jobs", samples)

    def test_every_alert_rule_reads_a_metric_that_exists(self) -> None:
        rules = (ROOT / "deploy" / "monitoring" / "sentro-alerts.yml").read_text(encoding="utf-8")
        exposed = set(parse(self.scrape().text))
        exposed |= {"sentro_backup_last_attempt_success"}  # present once a backup was attempted
        used = set(re.findall(r"\b(sentro_[a-z_]+)", rules))
        self.assertTrue(used)
        self.assertEqual(sorted(used - exposed), [])


class TheBackupAttemptTest(D11Case):

    def test_a_failed_backup_is_a_metric_and_an_alert(self) -> None:
        import main

        with mock.patch("backend.backup.create_backup", side_effect=RuntimeError("pg_dump: password=hunter2")):
            with self.assertRaises(RuntimeError):
                main.backup_command(mock.Mock(backup_command="create", json=True, verify=False, keep=0))
        attempt = json.loads(store.get_app_setting("backup.last_attempt"))
        self.assertEqual((attempt["ok"], attempt["error"]), (False, "RuntimeError"), "the type, never the text")
        self.assertEqual(parse(self.scrape().text)["sentro_backup_last_attempt_success"][0][1], 0)
        self.assertIn("backup_failed", ops_alerts.conditions())


class TheInstallationsOwnAlertsTest(D11Case):

    def test_a_stuck_queue_raises_one_alert_until_it_clears(self) -> None:
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with store._connect() as conn:
            conn.execute("INSERT INTO scan_jobs (id, tenant_id, status, created_at, updated_at) VALUES (?, ?, 'queued', ?, ?)",
                         ("job-stuck", "t-d11", old, old))
        self.assertEqual(ops_alerts.evaluate(), ["queue_stuck"])
        self.assertEqual(ops_alerts.evaluate(), [], "still stuck: not raised again")
        alerts = store.read_alerts("default")
        self.assertEqual([alert["title"] for alert in alerts], ["Scan queue is not moving"])
        self.assertNotIn("t-d11", json.dumps(alerts), "the workspace that queued it is not named")
        with store._connect() as conn:
            conn.execute("UPDATE scan_jobs SET status = 'done' WHERE id = 'job-stuck'")
        ops_alerts.evaluate()
        self.assertIn("ops.recovered", [row["action"] for row in store.read_audit_log("default", 50)])

    def test_a_stale_backup_in_production_alerts_and_a_fresh_one_does_not(self) -> None:
        with mock.patch.dict(os.environ, {"DSPM_ENV": "production"}):
            self.assertIn("backup_stale", ops_alerts.conditions(), "no backup at all")
            with mock.patch("backend.backup.latest_backup_age_seconds", return_value=3600.0):
                self.assertNotIn("backup_stale", ops_alerts.conditions())
            with mock.patch("backend.backup.latest_backup_age_seconds", return_value=27 * 3600.0):
                self.assertIn("backup_stale", ops_alerts.conditions())
        self.assertNotIn("backup_stale", ops_alerts.conditions(), "a development checkout with no backups is quiet")

    def test_the_deliverer_checks_the_installation_every_pass(self) -> None:
        from backend import alert_delivery

        with mock.patch.object(ops_alerts, "maybe_evaluate") as checked:
            alert_delivery.run_pass()
        checked.assert_called_once()

    def test_an_ops_alert_goes_to_the_installations_channels(self) -> None:
        store.save_alert_channel("default", "webhook", enabled=True, config={"url": "https://x.test", "min_severity": "HIGH"},
                                 secret_ref="", actor="t")
        store.set_app_setting("backup.last_attempt", json.dumps({"at": "2026-09-29T00:00:00+00:00", "ok": False,
                                                                  "error": "OSError"}))
        self.assertEqual(ops_alerts.evaluate(), ["backup_failed"])
        [alert] = store.read_alerts("default")
        self.assertEqual([delivery["channel"] for delivery in alert["deliveries"]], ["webhook"])


class TheLogShippingTest(unittest.TestCase):

    def test_json_lines_are_json_and_redacted(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging_setup.JsonFormatter("backend"))
        handler.addFilter(logging_setup.RedactingFilter(lambda: ["vault-key-value-123"]))
        logger = logging.getLogger("d11.test")
        logger.addHandler(handler)
        logger.propagate = False
        self.addCleanup(logger.removeHandler, handler)
        try:
            raise ValueError("password=hunter2 in vault-key-value-123")
        except ValueError:
            logger.exception("connecting with token=abc123def456 failed")
        line = json.loads(stream.getvalue().strip())
        self.assertEqual((line["level"], line["service"], line["logger"]), ("ERROR", "backend", "d11.test"))
        text = json.dumps(line)
        for secret in ("hunter2", "abc123def456", "vault-key-value-123"):
            self.assertNotIn(secret, text)

    def test_the_format_is_chosen_by_the_setting(self) -> None:
        temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, temp, True)
        root = logging.getLogger()
        saved = list(root.handlers), root.level
        try:
            with mock.patch.dict(os.environ, {"DSPM_LOG_FORMAT": "json"}):
                logging_setup.configure("backend", log_dir=temp)
            self.assertTrue(all(isinstance(handler.formatter, logging_setup.JsonFormatter) for handler in root.handlers))
        finally:
            for handler in list(root.handlers):
                root.removeHandler(handler)
                handler.close()
            for handler in saved[0]:
                root.addHandler(handler)
            root.setLevel(saved[1])


if __name__ == "__main__":
    unittest.main()
