#!/usr/bin/env python3
import argparse
import sys
from typing import Optional

from scanners.dom_xss_returnpath import check_returnpath_dom_xss


def log(message: str, level: str = "INFO") -> None:
    print(f"[{level}] {message}", flush=True)


def run(base_url: str, feedback_path: Optional[str], timeout_s: int, headed: bool, slow_mo_ms: int) -> int:
    vuln = check_returnpath_dom_xss(
        base_url=base_url,
        feedback_path=feedback_path,
        timeout_s=timeout_s,
        headed=headed,
        slow_mo_ms=slow_mo_ms,
    )
    if vuln:
        log("DOM XSS confirmed: alert dialog triggered", "VULN")
        return 0
    log("No DOM XSS confirmation (alert dialog not observed)", "ERROR")
    return 5


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automate PortSwigger DOM XSS lab steps for returnPath -> javascript: href"
    )
    parser.add_argument("base_url", help="Base URL of the lab, e.g. https://<lab-id>.web-security-academy.net/")
    parser.add_argument(
        "--feedback-path",
        help="Feedback page path (default: auto-discover or /feedback)",
    )
    parser.add_argument("--timeout", type=int, default=12, help="Timeout in seconds (default: 12)")
    parser.add_argument("--headed", action="store_true", help="Run browser in headed mode")
    parser.add_argument("--slow-mo", type=int, default=0, help="Slow motion in ms for debugging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.base_url.startswith(("http://", "https://")):
        log("Base URL must include scheme (http:// or https://)", "ERROR")
        return 1
    return run(
        base_url=args.base_url,
        feedback_path=args.feedback_path,
        timeout_s=args.timeout,
        headed=args.headed,
        slow_mo_ms=args.slow_mo,
    )


if __name__ == "__main__":
    sys.exit(main())
