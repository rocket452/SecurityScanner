import re
import urllib.parse
from typing import Dict, List, Optional, Sequence, Tuple

import httpx


def _same_origin(base_url: str, candidate: str) -> bool:
    try:
        b = urllib.parse.urlparse(base_url)
        c = urllib.parse.urlparse(urllib.parse.urljoin(base_url, candidate))
        return c.scheme in ("http", "https") and c.netloc == b.netloc
    except Exception:
        return False


def _extract_scripts(html_text: str) -> Tuple[List[str], List[str]]:
    """
    Returns (inline_scripts, script_srcs).
    Keep this intentionally regex-based; we only need a lightweight best-effort extractor.
    """
    inline = []
    srcs = []

    # src attributes
    for m in re.finditer(r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>", html_text, re.IGNORECASE):
        srcs.append(m.group(1))

    # inline blocks (avoid grabbing huge pages)
    for m in re.finditer(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html_text, re.IGNORECASE | re.DOTALL):
        body = (m.group(1) or "").strip()
        if body:
            inline.append(body)

    return inline, srcs


def _snippet(text: str, start: int, end: int, width: int = 160) -> str:
    s = max(0, start - width)
    e = min(len(text), end + width)
    out = text[s:e].replace("\r", "")
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


def _detect_hash_taint(js_text: str) -> Sequence[str]:
    """
    Extract variable names that are assigned (directly or via basic transforms) from location.hash.
    """
    tainted = set()
    assign_re = re.compile(
        r"(?:\bvar\b|\blet\b|\bconst\b)?\s*([A-Za-z_$][\w$]*)\s*=\s*[^;]{0,400}?(?:window\.)?(?:document\.)?location\.hash\b[^;]{0,400};",
        re.IGNORECASE,
    )
    for m in assign_re.finditer(js_text):
        tainted.add(m.group(1))
    return sorted(tainted)


def _find_sink_flows(js_text: str, tainted_vars: Sequence[str]) -> List[Dict]:
    """
    Find likely flows of location.hash (or hash-derived vars) into common DOM XSS sinks.
    This is static and conservative; it produces "potential" findings only.
    """
    findings: List[Dict] = []

    sinks = [
        ("innerHTML assignment", re.compile(r"\.innerHTML\s*=\s*[^;]{0,600};", re.IGNORECASE)),
        ("outerHTML assignment", re.compile(r"\.outerHTML\s*=\s*[^;]{0,600};", re.IGNORECASE)),
        ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(\s*[^,]{0,200},\s*[^)]{0,600}\)", re.IGNORECASE)),
        ("document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\(\s*[^)]{0,800}\)", re.IGNORECASE)),
        ("eval", re.compile(r"\beval\s*\(\s*[^)]{0,800}\)", re.IGNORECASE)),
        ("Function constructor", re.compile(r"\bFunction\s*\(\s*[^)]{0,800}\)", re.IGNORECASE)),
        ("setTimeout(string)", re.compile(r"\bsetTimeout\s*\(\s*[^,]{0,800},\s*\d+\s*\)", re.IGNORECASE)),
        ("setInterval(string)", re.compile(r"\bsetInterval\s*\(\s*[^,]{0,800},\s*\d+\s*\)", re.IGNORECASE)),
    ]

    hash_re = re.compile(r"(?:window\.)?(?:document\.)?location\.hash\b", re.IGNORECASE)
    taint_re = None
    if tainted_vars:
        taint_re = re.compile(r"\b(" + "|".join(re.escape(v) for v in tainted_vars) + r")\b")

    for sink_name, sink_re in sinks:
        for m in sink_re.finditer(js_text):
            stmt = m.group(0)
            if not hash_re.search(stmt) and not (taint_re and taint_re.search(stmt)):
                continue
            findings.append(
                {
                    "sink": sink_name,
                    "snippet": _snippet(js_text, m.start(), m.end()),
                }
            )

    return findings


def scan_dom_xss_hash(
    base_url: str,
    timeout_s: int = 10,
    headers: Optional[Dict[str, str]] = None,
    max_scripts: int = 10,
    max_bytes_per_script: int = 1_000_000,
) -> List[Dict]:
    """
    Static "DOM audit" for the homepage: look for location.hash usage and likely flow to sinks.
    Returns vulnerability dict(s) (unverified).
    """
    vulns: List[Dict] = []

    try:
        with httpx.Client(timeout=timeout_s, follow_redirects=True, verify=False, headers=headers) as client:
            r = client.get(base_url)
            html_text = r.text or ""
            inline_scripts, script_srcs = _extract_scripts(html_text)

            # Pull same-origin external JS scripts (bounded).
            js_blobs: List[str] = []
            js_blobs.extend(inline_scripts)

            fetched = 0
            for src in script_srcs:
                if fetched >= max_scripts:
                    break
                if not _same_origin(base_url, src):
                    continue
                js_url = urllib.parse.urljoin(base_url, src)
                try:
                    jr = client.get(js_url)
                    if jr.status_code >= 400:
                        continue
                    content = jr.text or ""
                    if len(content) > max_bytes_per_script:
                        content = content[:max_bytes_per_script]
                    js_blobs.append(content)
                    fetched += 1
                except Exception:
                    continue

            combined_js = "\n\n".join(js_blobs)
            if not combined_js:
                return []

            if not re.search(r"(?:window\.)?(?:document\.)?location\.hash\b", combined_js, re.IGNORECASE):
                return []

            tainted_vars = _detect_hash_taint(combined_js)
            flows = _find_sink_flows(combined_js, tainted_vars)
            if not flows:
                return []

            # Emit one vuln per sink occurrence (keeps evidence tight in reports).
            for f in flows[:25]:
                vulns.append(
                    {
                        "type": "dom_xss",
                        "method": "GET",
                        "parameter": "#fragment",
                        "payload": None,
                        "url": base_url,
                        "severity": "medium",
                        "verified": False,
                        "context": "static-analysis",
                        "pattern": f.get("sink"),
                        "context_snippet": f.get("snippet"),
                        "description": f"Potential DOM XSS: location.hash flows into {f.get('sink')} (static)",
                        "severity_reasoning": "Static source/sink pattern match only; not browser-verified execution.",
                        "exploitation": {
                            "browser_steps": [
                                f"Open: {base_url}",
                                "Open DevTools (Sources) and search for `location.hash`",
                                "Look for the matched sink usage in the code context shown in the report",
                            ]
                        },
                        "remediation": "Avoid inserting untrusted data from URL fragments into DOM sinks. Use safe DOM APIs (textContent) or robust sanitization.",
                    }
                )
    except Exception:
        return []

    return vulns

