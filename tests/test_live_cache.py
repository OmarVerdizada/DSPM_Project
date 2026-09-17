"""B3.1: the dashboard's aggregates are shared between backends, and Memurai holds nothing else.

The case for Redis in this product was never the queue - it was the estate aggregates the
console asks for on every refresh, which each backend and each worker paid for separately
because the only cache was per-process and thirty seconds long. Measured on this host's
PostgreSQL: four aggregates, 7.31 ms at 1,369 assets, 5.34 s extrapolated to a million,
and a 3.9-hour scan spending about 6.95 hours of database time answering the console.

What matters as much as the speed is the boundary. These pin both:

- a second process answers **without touching the database** - that is the whole point;
- a saved scan makes the cached answer unreachable at once, so the console is never
  showing the estate as it was before the scan;
- the cache holds derived numbers under `dspm:` keys, every one of them with a TTL,
  never content or samples;
- with no `DSPM_REDIS_URL` - or with Memurai down - every call is exactly the database
  read it always was. Memurai is an accelerator, never a dependency.
"""

from __future__ import annotations

import json
import os
import time
import unittest
from unittest import mock

from backend import live_cache


class _FakeRedis:
    """Only the commands live_cache uses, and a record of what it was asked."""

    def __init__(self, *, broken: bool = False) -> None:
        self.values: dict[str, tuple[str, float | None]] = {}
        self.broken = broken
        self.calls: list[str] = []

    def _check(self) -> None:
        if self.broken:
            raise RuntimeError("memurai is down")

    def ping(self):
        self._check()
        return True

    def get(self, key):
        self.calls.append(f"get {key}")
        self._check()
        stored = self.values.get(key)
        if stored is None:
            return None
        value, expires = stored
        if expires is not None and expires <= time.monotonic():
            self.values.pop(key, None)
            return None
        return value

    def set(self, key, value, ex=None):
        self.calls.append(f"set {key}")
        self._check()
        self.values[key] = (value, time.monotonic() + ex if ex else None)
        return True

    def incr(self, key):
        self._check()
        current = int(self.values.get(key, ("0", None))[0])
        self.values[key] = (str(current + 1), None)
        return current + 1

    def expire(self, key, seconds):
        self._check()
        if key in self.values:
            self.values[key] = (self.values[key][0], time.monotonic() + seconds)
        return True


class _CacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fake = _FakeRedis()
        # The suite runs with the shared cache OFF (tests/conftest.py), so these tests
        # turn it on for themselves - and never touch a real server: `client` is faked.
        self._env = mock.patch.dict(os.environ, {
            "DSPM_REDIS_URL": "redis://127.0.0.1:6379/0",
            "DSPM_LIVE_CACHE": "1",
        })
        self._env.start()
        live_cache.reset_for_tests()
        self._client = mock.patch.object(live_cache, "client", return_value=self.fake)
        self._client.start()

    def tearDown(self) -> None:
        self._client.stop()
        self._env.stop()
        live_cache.reset_for_tests()


class WhatTheCacheSavesTest(_CacheTest):

    def test_a_second_reader_does_not_pay_for_the_aggregate(self) -> None:
        built = []

        def builder() -> dict:
            built.append(1)
            return {"assets": 1_000_000}

        first = live_cache.cached_json("t1", "posture_inputs", None, builder)
        second = live_cache.cached_json("t1", "posture_inputs", None, builder)

        self.assertEqual(first, second)
        self.assertEqual(len(built), 1, "the second reader went back to the database")

    def test_one_tenants_answer_is_never_another_tenants(self) -> None:
        live_cache.cached_json("t1", "posture_inputs", None, lambda: {"assets": 1})
        other = live_cache.cached_json("t2", "posture_inputs", None, lambda: {"assets": 2})
        self.assertEqual(other, {"assets": 2})

    def test_a_saved_scan_makes_the_cached_answer_unreachable_at_once(self) -> None:
        live_cache.cached_json("t1", "posture_inputs", None, lambda: {"assets": 1})
        live_cache.bump("t1")
        after = live_cache.cached_json("t1", "posture_inputs", None, lambda: {"assets": 2})
        self.assertEqual(after, {"assets": 2}, "the console would have shown the estate as it was before the scan")

    def test_it_invalidates_without_ever_listing_keys(self) -> None:
        live_cache.cached_json("t1", "posture_inputs", None, lambda: {"assets": 1})
        live_cache.bump("t1")
        self.assertFalse([call for call in self.fake.calls if call.startswith(("keys", "scan", "flush"))],
                         "the product's Redis user is not allowed to run those, by design")

    def test_every_key_it_writes_expires(self) -> None:
        live_cache.cached_json("t1", "inventory_facets", {"source": ""}, lambda: {"risk": {}})
        live_cache.publish_progress("t1", "job-1", {"progress": 10})
        live_cache.bump("t1")
        for key, (_value, expires) in self.fake.values.items():
            with self.subTest(key=key):
                self.assertIsNotNone(expires, f"{key} would live forever under noeviction")

    def test_its_keys_are_the_ones_the_acl_allows(self) -> None:
        live_cache.cached_json("t1", "inventory_facets", {"source": ""}, lambda: {})
        live_cache.publish_progress("t1", "job-1", {"progress": 1})
        for key in self.fake.values:
            with self.subTest(key=key):
                self.assertTrue(key.startswith("dspm:"), "the ACL confines this user to ~dspm:*")


class WhatTheCacheMayNeverDoTest(_CacheTest):

    def test_it_never_changes_the_answer(self) -> None:
        answer = {"assets": 3, "sensitive": 1}
        self.assertEqual(live_cache.cached_json("t1", "x", None, lambda: answer), answer)
        self.assertEqual(live_cache.cached_json("t1", "x", None, lambda: {"assets": 99}), answer,
                         "a cached answer is the one that was built, not a new one")

    def test_a_memurai_that_is_down_is_not_an_outage(self) -> None:
        self._client.stop()
        broken = _FakeRedis(broken=True)
        with mock.patch.object(live_cache, "client", return_value=broken):
            self.assertEqual(live_cache.cached_json("t1", "x", None, lambda: {"assets": 7}), {"assets": 7})
            live_cache.bump("t1")
            self.assertIsNone(live_cache.read_progress("t1", "job-1"))
        self._client.start()

    def test_with_no_url_configured_it_is_exactly_the_database_read(self) -> None:
        self._client.stop()
        with mock.patch.dict(os.environ, {"DSPM_REDIS_URL": "", "DSPM_LIVE_CACHE": "1"}):
            live_cache.reset_for_tests()
            calls = []
            value = live_cache.cached_json("t1", "x", None, lambda: calls.append(1) or {"assets": 2})
            self.assertEqual(value, {"assets": 2})
            self.assertEqual(len(calls), 1)
            self.assertFalse(live_cache.configured())
        self._client.start()

    def test_what_it_stores_is_derived_state_and_says_so(self) -> None:
        live_cache.cached_json("t1", "posture_inputs", None, lambda: {"assets": 5, "sensitive_assets": 2})
        stored = json.loads(next(iter(self.fake.values.values()))[0])
        self.assertEqual(stored, {"assets": 5, "sensitive_assets": 2},
                         "only counts belong here - never content, previews or samples")


class LiveProgressTest(_CacheTest):

    def test_a_scan_running_elsewhere_can_still_be_watched(self) -> None:
        live_cache.publish_progress("t1", "job-7", {"progress": 42, "message": "Scanning share"})
        self.assertEqual(live_cache.read_progress("t1", "job-7"),
                         {"progress": 42, "message": "Scanning share"})

    def test_an_unknown_job_reads_as_nothing(self) -> None:
        self.assertIsNone(live_cache.read_progress("t1", "job-missing"))

    def test_progress_is_reported_in_the_diagnostics(self) -> None:
        live_cache.publish_progress("t1", "job-7", {"progress": 1})
        live_cache.read_progress("t1", "job-7")
        diagnostics = live_cache.diagnostics()
        self.assertTrue(diagnostics["enabled"])
        self.assertGreaterEqual(diagnostics["hits"], 1)


if __name__ == "__main__":
    unittest.main()
