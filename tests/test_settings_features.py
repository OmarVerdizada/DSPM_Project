"""Settings surface: runtime feature flags and account avatars.

The OCR flag must persist install-wide, apply to this process's env on write
(collectors read the env per call, so a toggle needs no restart), and be
admin-only to change. The avatar is a bounded data URL on the user row -
allowed for every account including the protected admin, validated at the API.
"""

from __future__ import annotations

import base64
import os
import unittest

from fastapi.testclient import TestClient

from backend.app import app, _apply_persisted_feature_flags
from backend.security import create_token, hash_password
from backend.store import create_user, delete_user, get_app_setting, set_app_setting, get_user

PNG_DATA_URL = "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\nfakebody").decode()


def _headers(role: str = "admin", subject: str = "admin") -> dict:
    return {"Authorization": f"Bearer {create_token(subject, role, 'default')}"}


def _viewer_headers() -> dict:
    # The principal's role comes from the user record, so a real viewer row is
    # needed - a viewer-claim token for 'admin' would still resolve as admin.
    if get_user("settings-viewer") is None:
        create_user("settings-viewer", hash_password("ViewerPass123"), "viewer", "default", "Settings Viewer")
    return _headers("viewer", "settings-viewer")


class FeatureFlagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)
        self._saved_env = os.environ.get("DSPM_OCR_ENABLED")

    def tearDown(self) -> None:
        if self._saved_env is None:
            os.environ.pop("DSPM_OCR_ENABLED", None)
        else:
            os.environ["DSPM_OCR_ENABLED"] = self._saved_env

    def test_viewer_reads_but_cannot_change(self) -> None:
        headers = _viewer_headers()
        try:
            response = self.client.get("/api/settings/features", headers=headers)
            self.assertEqual(response.status_code, 200)
            ocr = response.json()["features"]["ocr"]
            self.assertIn("enabled", ocr)
            self.assertIn("dependency_installed", ocr)
            self.assertFalse(ocr["editable"])
            denied = self.client.put("/api/settings/features", json={"ocr_enabled": True}, headers=headers)
            self.assertEqual(denied.status_code, 403)
        finally:
            delete_user("settings-viewer")

    def test_admin_toggle_persists_and_applies_without_restart(self) -> None:
        on = self.client.put("/api/settings/features", json={"ocr_enabled": True}, headers=_headers())
        self.assertEqual(on.status_code, 200)
        self.assertTrue(on.json()["features"]["ocr"]["enabled"])
        # Applied to the running process (what collectors read per call)...
        self.assertEqual(os.environ.get("DSPM_OCR_ENABLED"), "1")
        # ...and persisted for the next boot.
        self.assertEqual(get_app_setting("feature.ocr_enabled"), "1")

        off = self.client.put("/api/settings/features", json={"ocr_enabled": False}, headers=_headers())
        self.assertFalse(off.json()["features"]["ocr"]["enabled"])
        self.assertEqual(os.environ.get("DSPM_OCR_ENABLED"), "0")
        self.assertEqual(get_app_setting("feature.ocr_enabled"), "0")

    def test_startup_reapplies_persisted_flag(self) -> None:
        set_app_setting("feature.ocr_enabled", "1")
        os.environ["DSPM_OCR_ENABLED"] = "0"
        _apply_persisted_feature_flags()
        self.assertEqual(os.environ.get("DSPM_OCR_ENABLED"), "1")


class AvatarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_avatar_roundtrip_including_protected_admin(self) -> None:
        put = self.client.put("/api/profile/avatar", json={"avatar": PNG_DATA_URL}, headers=_headers())
        self.assertEqual(put.status_code, 200)
        self.assertEqual(put.json()["avatar"], PNG_DATA_URL)
        self.assertEqual(get_user("admin")["avatar"], PNG_DATA_URL)

        profile = self.client.get("/api/profile", headers=_headers())
        self.assertEqual(profile.json()["avatar"], PNG_DATA_URL)
        # Listings stay lean: no avatar blob in the public user shape.
        self.assertNotIn("avatar", profile.json()["user"])

        cleared = self.client.put("/api/profile/avatar", json={"avatar": ""}, headers=_headers())
        self.assertEqual(cleared.json()["avatar"], "")
        self.assertEqual(get_user("admin")["avatar"], "")

    def test_avatar_rejects_non_image_and_bad_base64(self) -> None:
        bad_prefix = self.client.put(
            "/api/profile/avatar", json={"avatar": "data:text/html;base64,PGI+"}, headers=_headers()
        )
        self.assertEqual(bad_prefix.status_code, 400)
        bad_body = self.client.put(
            "/api/profile/avatar", json={"avatar": "data:image/png;base64,@@not-base64@@"}, headers=_headers()
        )
        self.assertEqual(bad_body.status_code, 400)


class InventoryDetailCountsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_batch_counts_requires_auth_and_handles_empty(self) -> None:
        denied = self.client.get("/api/inventory-detail-counts?ids=a,b")
        self.assertIn(denied.status_code, (401, 403))
        ok = self.client.get("/api/inventory-detail-counts?ids=", headers=_headers())
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json(), {"tenant_id": "default", "counts": {}})
        unknown = self.client.get("/api/inventory-detail-counts?ids=deadbeef", headers=_headers())
        self.assertEqual(unknown.status_code, 200)
        self.assertEqual(unknown.json()["counts"], {})


if __name__ == "__main__":
    unittest.main()
