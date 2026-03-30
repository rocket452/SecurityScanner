#!/usr/bin/env python3
"""
Regression tests for SVG animation allowlist bypass strategy.

These tests model the PortSwigger allowlist lab pattern where:
- common payloads are blocked (HTTP 400)
- only selected SVG-related tags are accepted
- `onbegin` is accepted on `<animatetransform>` and is exploitable
"""

import sys
import urllib.parse
import unittest
from pathlib import Path

# Add project root to import path.
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanners.xss_advanced import (  # noqa: E402
    SVG_ANIMATION_ALLOWLIST_TECHNIQUE_ID,
    _probe_tag_event_allowlist_xss,
)
from scanners.xss_breakout_integration import _probe_tag_event_allowlist_breakout  # noqa: E402


class _FakeResponse:
    def __init__(self, status_code: int, text: str, url: str) -> None:
        self.status_code = status_code
        self.text = text
        self.url = url


class _FakeAllowlistClient:
    """
    Minimal client that emulates an allowlist-filtered XSS lab.
    """

    def get(self, url: str, params=None):  # pragma: no cover - exercised by tests
        params = params or {}
        payload = self._extract_payload(params)
        status_code, body = self._simulate_response(payload)
        query = urllib.parse.urlencode(params, doseq=True)
        full_url = f"{url}?{query}" if query else url
        return _FakeResponse(status_code, body, full_url)

    @staticmethod
    def _extract_payload(params: dict) -> str:
        if "search" in params:
            value = params["search"]
        elif params:
            value = next(iter(params.values()))
        else:
            value = ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    @staticmethod
    def _simulate_response(payload: str):
        # Baseline vector blocked.
        if payload == "<img src=1 onerror=print()>":
            return 400, ""

        # Tag probing: only these are allowlisted.
        allowlisted_tag_probes = {
            "<svg><animatetransform>",
            "<svg>",
            "<svg><title>",
            "<svg><image>",
        }
        if payload in allowlisted_tag_probes:
            return 200, payload

        # Event probing: only onbegin is allowlisted for animatetransform.
        if payload == "<svg><animatetransform onbegin=1>":
            return 200, payload

        # Final exploit reflection.
        if payload == '\"><svg><animatetransform onbegin=print()>':
            return 200, f"<html>{payload}</html>"

        # Everything else blocked by filter in this modeled lab.
        if payload.startswith("<") or payload.startswith('\"><'):
            return 400, ""
        return 200, payload


class SvgAllowlistStrategyTests(unittest.TestCase):
    def test_advanced_probe_detects_svg_animation_allowlist_bypass(self):
        client = _FakeAllowlistClient()
        vuln = _probe_tag_event_allowlist_xss(
            client=client,
            base_url="https://example.test/",
            param_name="search",
            baseline_params={},
            headers=None,
            browser_verify=False,
        )

        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.get("technique_id"), SVG_ANIMATION_ALLOWLIST_TECHNIQUE_ID)
        self.assertEqual(vuln.get("evidence", {}).get("allowed_tag"), "animatetransform")
        self.assertEqual(vuln.get("evidence", {}).get("allowed_event"), "onbegin")
        self.assertIn("<animatetransform onbegin=print()>", vuln.get("payload", ""))

    def test_breakout_probe_detects_svg_animation_allowlist_bypass(self):
        client = _FakeAllowlistClient()
        vuln = _probe_tag_event_allowlist_breakout(
            client=client,
            url="https://example.test/",
            param_name="search",
        )

        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.get("evidence", {}).get("allowed_tag"), "animatetransform")
        self.assertEqual(vuln.get("evidence", {}).get("allowed_event"), "onbegin")
        self.assertIn("<animatetransform onbegin=print()>", vuln.get("successful_payload", ""))

    def test_advanced_probe_skips_non_search_params(self):
        client = _FakeAllowlistClient()
        vuln = _probe_tag_event_allowlist_xss(
            client=client,
            base_url="https://example.test/",
            param_name="id",
            baseline_params={},
            headers=None,
            browser_verify=False,
        )
        self.assertIsNone(vuln)


if __name__ == "__main__":
    unittest.main()
