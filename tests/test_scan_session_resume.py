#!/usr/bin/env python3
"""
Regression tests for resumable scan session state.
"""

import sys
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

# Add project root to import path.
sys.path.insert(0, str(Path(__file__).parent.parent))

import scanner  # noqa: E402


class ScanSessionResumeTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.session_file = Path(self._tmpdir.name) / "session.json"

    def test_session_state_round_trip_preserves_completed_and_pending_urls(self):
        state = scanner.ScanSessionState("https://example.test", self.session_file)
        state.enqueue("https://example.test", "https://example.test", 0)
        state.enqueue("https://example.test", "https://example.test/admin?from=seed", 1)
        state.mark_completed("https://example.test")
        state.save()

        loaded = scanner.ScanSessionState.load("https://example.test", self.session_file)

        self.assertTrue(loaded.is_completed("https://example.test/"))
        self.assertEqual(
            [entry["url"] for entry in loaded.pending],
            ["https://example.test/admin"],
        )

    def test_load_scan_session_state_uses_default_file_when_flag_omitted(self):
        default_session = Path(self._tmpdir.name) / "reports" / "sessions" / "example_test.session.json"
        args = SimpleNamespace(session_file=None, no_session=False, reset_session=False, har=None)

        with mock.patch("scanner._default_session_file_for_target", return_value=default_session):
            state = scanner.load_scan_session_state("https://example.test", args)

        self.assertIsNotNone(state)
        self.assertEqual(state.session_file, default_session)
        self.assertTrue(default_session.exists())

    def test_load_scan_session_state_can_be_disabled(self):
        args = SimpleNamespace(session_file=None, no_session=True, reset_session=False, har=None)

        state = scanner.load_scan_session_state("https://example.test", args)

        self.assertIsNone(state)

    def test_path_recursion_resumes_from_pending_queue_without_rescanning_root(self):
        args = SimpleNamespace(path_scan_depth=2, path_scan_max_urls=1, xss_only=False)
        state = scanner.ScanSessionState("https://example.test", self.session_file)
        calls = []

        def fake_scan(url, args, skip_nuclei=False):
            norm = scanner._normalize_url_for_recursion(url)
            calls.append(norm)
            if norm == "https://example.test/":
                return [{"endpoint": "https://example.test/admin?from=root"}]
            return []

        with mock.patch("scanner.scan_single_domain_for_vulnerabilities", side_effect=fake_scan):
            first_run = scanner.scan_with_path_recursion(
                "https://example.test",
                args,
                session_state=state,
            )
            second_run = scanner.scan_with_path_recursion(
                "https://example.test",
                args,
                session_state=state,
            )

        self.assertEqual(
            [scanner._normalize_url_for_recursion(url) for url, _ in first_run],
            ["https://example.test/"],
        )
        self.assertEqual(
            [scanner._normalize_url_for_recursion(url) for url, _ in second_run],
            ["https://example.test/admin"],
        )
        self.assertEqual(
            calls,
            ["https://example.test/", "https://example.test/admin"],
        )
        self.assertFalse(state.pending)

    def test_normalize_url_for_recursion_coerces_host_like_targets(self):
        self.assertEqual(
            scanner._normalize_url_for_recursion("example.test"),
            "https://example.test/",
        )
        self.assertEqual(
            scanner._normalize_url_for_recursion("://example.test/path?x=1"),
            "https://example.test/path",
        )
        self.assertEqual(
            scanner._normalize_url_for_recursion("//example.test/path#frag"),
            "https://example.test/path",
        )

    def test_session_load_normalizes_legacy_hostname_entries(self):
        payload = {
            "version": 1,
            "target": "example.test",
            "created_at": "2026-03-01T10:00:00",
            "updated_at": "2026-03-01T10:00:00",
            "completed_urls": ["example.test"],
            "pending_urls": [
                {
                    "root_url": "example.test",
                    "url": "example.test/admin?from=seed",
                    "depth": 1,
                }
            ],
        }
        self.session_file.write_text(json.dumps(payload), encoding="utf-8")

        loaded = scanner.ScanSessionState.load("example.test", self.session_file)

        self.assertTrue(loaded.is_completed("https://example.test/"))
        self.assertEqual(
            [entry["url"] for entry in loaded.pending],
            ["https://example.test/admin"],
        )

    def test_xss_only_run_all_scans_coerces_targets_to_urls(self):
        args = SimpleNamespace(xss_only=True, zap=False, zap_only=False, skip_nuclei=True)

        with mock.patch("scanner.run_traditional_scans", return_value=[]) as run_traditional, mock.patch(
            "scanner.probe_live_domains"
        ) as probe_live:
            scanner.run_all_scans(
                ["example.test", "://legacy.test", "https://ready.test/path", "example.test"],
                args,
            )

        probe_live.assert_not_called()
        live_domains_arg = run_traditional.call_args.args[0]
        self.assertEqual(
            live_domains_arg,
            [
                ("https://example.test", True, None),
                ("https://legacy.test", True, None),
                ("https://ready.test/path", True, None),
            ],
        )


if __name__ == "__main__":
    unittest.main()
