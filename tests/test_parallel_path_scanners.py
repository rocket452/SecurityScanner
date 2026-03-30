#!/usr/bin/env python3
"""
Behavior tests for admin/backup path scanners with parallel probes.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

# Add project root to import path.
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanners.admin_scanner import check_admin  # noqa: E402
from scanners.backup_scanner import check_backup  # noqa: E402


class _FakeResponse:
    def __init__(self, status_code=404, text="", content=None):
        self.status_code = status_code
        self.text = text
        self.content = content if content is not None else text.encode("utf-8")


class ParallelPathScannerTests(unittest.TestCase):
    def test_check_admin_detects_login_page(self):
        base = "https://example.test"

        def fake_get(url, timeout=5, verify=False, headers=None):
            if url == base:
                return _FakeResponse(status_code=200, text="<html>home</html>")
            if url.endswith("/login"):
                return _FakeResponse(status_code=200, text="<title>Admin Login</title>")
            return _FakeResponse(status_code=404, text="not found")

        with mock.patch("scanners.admin_scanner.requests.get", side_effect=fake_get):
            self.assertTrue(check_admin(base, max_workers=4))

    def test_check_admin_returns_false_when_no_admin_signals(self):
        base = "https://example.test"

        def fake_get(url, timeout=5, verify=False, headers=None):
            if url == base:
                return _FakeResponse(status_code=200, text="<html>home</html>")
            return _FakeResponse(status_code=404, text="not found")

        with mock.patch("scanners.admin_scanner.requests.get", side_effect=fake_get):
            self.assertFalse(check_admin(base, max_workers=4))

    def test_check_backup_detects_non_trivial_backup_file(self):
        base = "https://example.test"
        large_blob = b"x" * 200

        def fake_get(url, timeout=5, verify=False, headers=None):
            if url.endswith("/backup.zip"):
                return _FakeResponse(status_code=200, text="binary", content=large_blob)
            return _FakeResponse(status_code=404, text="not found")

        with mock.patch("scanners.backup_scanner.requests.get", side_effect=fake_get):
            self.assertTrue(check_backup(base, max_workers=4))

    def test_check_backup_returns_false_when_no_hits(self):
        base = "https://example.test"

        def fake_get(url, timeout=5, verify=False, headers=None):
            return _FakeResponse(status_code=404, text="not found")

        with mock.patch("scanners.backup_scanner.requests.get", side_effect=fake_get):
            self.assertFalse(check_backup(base, max_workers=4))


if __name__ == "__main__":
    unittest.main()
