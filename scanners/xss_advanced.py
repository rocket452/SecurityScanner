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
from typing import List, Dict, Tuple, Optional, Set
from html.parser import HTMLParser
from .xss_payloads import XSSPayloads, load_custom_payloads
from .xss_scanner import FormParser, extract_forms, log
from .param_discovery import discover_parameters


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
        
        # Find position of marker
        pos = response_text.find(marker)
        
        # Get context around marker (200 chars before and after)
        start = max(0, pos - 200)
        end = min(len(response_text), pos + len(marker) + 200)
        context = response_text[start:end]
        
        # Detect JavaScript context
        js_patterns = [
            r'<script[^>]*>.*?' + re.escape(marker),
            r'var\s+\w+\s*=\s*["\']?' + re.escape(marker),
            r'function\s*\([^)]*\)\s*{[^}]*' + re.escape(marker),
            r'on\w+\s*=\s*["\'][^"\'\']*' + re.escape(marker),
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
        
        if headers:
            for key, value in headers.items():
                cmd += f" -H '{key}: {value}'"
        
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
        steps = [
            f"1. Open a web browser and navigate to: {url}",
        ]
        
        if method == 'GET':
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            params[parameter] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            steps.append(f"2. Modify the URL parameter '{parameter}' to: {payload}")
            steps.append(f"3. Navigate to the modified URL: {exploit_url}")
            steps.append("4. Observe the XSS payload execution (alert box or other behavior)")
        
        elif method == 'POST':
            steps.append(f"2. Locate the form containing the '{parameter}' input field")
            steps.append(f"3. Enter the following payload into the '{parameter}' field: {payload}")
            steps.append("4. Submit the form")
            steps.append("5. Observe the XSS payload execution (alert box or other behavior)")
        
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
                      enable_param_discovery: bool = True) -> List[Dict]:
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
    
    # Select payloads based on mode
    if mode == 'basic':
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
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            # Initial request to analyze CSP and get forms
            initial_response = client.get(url)
            
            # Analyze CSP
            csp_analysis = CSPAnalyzer.analyze_csp(
                CSPAnalyzer.extract_csp(dict(initial_response.headers))
            )
            
            log(f"CSP Analysis: {csp_analysis['potential_bypasses']}", 'INFO')
            
            # Extract forms
            forms = extract_forms(initial_response.text)
            
            # Parse URL parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Arjun parameter discovery (if enabled)
            discovered_params = []
            if enable_param_discovery and mode in ['advanced', 'exploitation']:
                log("Running Arjun parameter discovery...", 'INFO')
                arjun_result = discover_parameters(url, method='GET', threads=5, timeout=30)
                if arjun_result['parameters']:
                    discovered_params = arjun_result['parameters']
                    log(f"Arjun found {len(discovered_params)} hidden parameters: {', '.join(discovered_params)}", 'INFO')
                    # Add discovered params to test list
                    for param in discovered_params:
                        if param not in params:
                            params[param] = ['test']
            
            if not params:
                # Try common parameter names
                common_params = ['q', 'search', 'query', 'keyword', 'term', 'id', 'page', 'url', 'redirect', 'name', 'input', 'data']
                params = {param: ['test'] for param in common_params}
            
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Context detection phase - use unique marker
            marker = "__XSS_CONTEXT_MARKER_12345__"
            context_map = {}
            
            # Detect context for each parameter
            for param_name in params.keys():
                test_params = params.copy()
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
            for param_name, context in context_map.items():
                log(f"Testing XSS on GET parameter: {param_name} (context: {context})", 'INFO')
                
                # Get context-specific payloads
                context_payloads = XSSPayloads.get_context_payloads(context)
                
                # Add WAF bypass payloads for advanced mode
                if mode == 'advanced':
                    context_payloads.extend(XSSPayloads.get_waf_bypass_payloads())
                
                for payload in context_payloads[:20]:  # Limit to prevent excessive requests
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in test_params.items()}
                    
                    try:
                        response = client.get(base_url, params=flat_params)
                        
                        if payload in response.text and is_xss_vulnerable(response.text, payload):
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
                                'GET', base_url, flat_params
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
                            
                            vulnerabilities.append(vuln)
                            log(f"XSS FOUND: {param_name} (severity: {severity}, score: {score}, discovered via: {discovery_method})", 'VULN')
                            break  # Move to next parameter after finding vulnerability
                    
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
                    form_url = urllib.parse.urljoin(url, form_action) if form_action else url
                    
                    # Similar testing for forms (abbreviated for length)
                    for input_field in form['inputs']:
                        if input_field['type'] in ['submit', 'button', 'image']:
                            continue
                        
                        field_name = input_field['name']
                        
                        # Test with basic payloads for forms
                        for payload in XSSPayloads.get_basic_payloads():
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
                            except:
                                continue
    
    except Exception as e:
        log(f"Advanced XSS scanner error: {str(e)}", 'ERROR')
    
    if vulnerabilities:
        log(f"Found {len(vulnerabilities)} XSS vulnerability(ies)", 'VULN')
    else:
        log(f"No XSS vulnerabilities found", 'INFO')
    
    return vulnerabilities


def is_xss_vulnerable(response_text: str, payload: str) -> bool:
    """
    Enhanced vulnerability detection
    """
    if payload not in response_text:
        return False
    
    # Check for encoding
    encoded_chars = ['&lt;', '&gt;', '&quot;', '&#', '&amp;']
    payload_pos = response_text.find(payload)
    
    if payload_pos == -1:
        return False
    
    context_start = max(0, payload_pos - 30)
    context_end = min(len(response_text), payload_pos + len(payload) + 30)
    context = response_text[context_start:context_end]
    
    for encoded in encoded_chars:
        if encoded in context:
            return False
    
    # Check for dangerous patterns
    if any(keyword in payload.lower() for keyword in ['<script', 'onerror', 'onload', 'javascript:']):
        return True
    
    return False
