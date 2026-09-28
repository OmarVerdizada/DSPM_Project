"""C7 (Bandit B310): the alert webhook opens http(s) URLs only.

urllib's urlopen also reads file: and ftp: URLs, so a mistyped or planted
DSPM_ALERT_WEBHOOK_URL could make the server read a local file.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

from backend import alerts


class TheWebhookOpensOnlyHttpUrlsTest(unittest.TestCase):

    def _send(self, url: str) -> mock.MagicMock:
        with mock.patch.dict(os.environ, {"DSPM_ALERT_WEBHOOK_URL": url}), \
                mock.patch.object(alerts.request, "urlopen") as urlopen:
            alerts._send_webhook([{"title": "High-risk file"}])
        return urlopen

    def test_a_file_or_ftp_url_is_never_opened(self) -> None:
        for url in ("file:///etc/passwd", "FILE:///C:/Windows/win.ini", "ftp://example.test/drop", " file:///x"):
            with self.subTest(url=url):
                self.assertFalse(self._send(url).called)

    def test_an_https_url_is_posted(self) -> None:
        urlopen = self._send("https://hooks.example.test/sentro")
        self.assertTrue(urlopen.called)
        sent = urlopen.call_args.args[0]
        self.assertEqual(sent.get_method(), "POST")
        self.assertEqual(sent.full_url, "https://hooks.example.test/sentro")


if __name__ == "__main__":
    unittest.main()
