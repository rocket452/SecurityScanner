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


def log(msg: str, level: str = 'INFO'):
    """Simple logging function"""
    print(f"[{level}] {msg}")


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


def discover_form_parameters(url: str, timeout: int = 10) -> List[Tuple[str, str, Dict]]:
    """
    Discover POST parameters by fetching the page and parsing forms
    
    Args:
        url: Target URL to fetch
        timeout: Request timeout
    
    Returns:
        List of (param_name, method, form_data) tuples
    """
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            response = client.get(url)
            
            # Simple form parsing - look for input/textarea elements
            import re
            
            # Find all input fields
            input_pattern = r'<input[^>]+name=["\']([^"\'\']+)["\']'
            inputs = re.findall(input_pattern, response.text, re.IGNORECASE)
            
            # Find all textarea fields
            textarea_pattern = r'<textarea[^>]+name=["\']([^"\'\']+)["\']'
            textareas = re.findall(textarea_pattern, response.text, re.IGNORECASE)
            
            # Find all select fields
            select_pattern = r'<select[^>]+name=["\']([^"\'\']+)["\']'
            selects = re.findall(select_pattern, response.text, re.IGNORECASE)
            
            all_fields = list(set(inputs + textareas + selects))
            
            if all_fields:
                log(f"Discovered {len(all_fields)} form field(s): {', '.join(all_fields)}", 'INFO')
                # Return tuples with empty form_data for now - will be populated during testing
                return [(field, 'POST', {}) for field in all_fields]
            else:
                return []
    
    except Exception as e:
        log(f"Error discovering form parameters: {str(e)}", 'WARN')
        return []


def scan_url_for_breakout_xss(url: str,
                               use_arjun: bool = True,
                               timeout: int = 10,
                               callback_url: Optional[str] = None) -> List[Dict]:
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
    
    # Step 2: Discover hidden parameters with Arjun (if enabled)
    if use_arjun:
        try:
            arjun_result = discover_parameters(url, method='GET', timeout=30)
            if arjun_result.get('parameters'):
                for param in arjun_result['parameters']:
                    if (param, 'GET') not in url_params:
                        url_params.append((param, 'GET'))
                log(f"Arjun discovered {len(arjun_result['parameters'])} additional parameter(s)", 'INFO')
        except Exception as e:
            log(f"Arjun parameter discovery failed: {str(e)}", 'WARN')
    
    # Step 3: Discover POST parameters from forms
    form_params = discover_form_parameters(url, timeout=timeout)
    log(f"Found {len(form_params)} form parameter(s)", 'INFO')
    
    # Step 4: Test each GET parameter
    for param_name, method in url_params:
        param_key = f"{param_name}:{method}"
        if param_key in tested_params:
            continue
        
        tested_params.add(param_key)
        log(f"Testing GET parameter: {param_name}", 'INFO')
        
        vuln = detect_breakout_xss(
            url=url,
            param_name=param_name,
            method='GET',
            timeout=timeout,
            callback_url=callback_url
        )
        
        if vuln:
            log(f"✓ BREAKOUT XSS found in parameter '{param_name}' (GET)", 'VULN')
            vulnerabilities.append(vuln)
        else:
            log(f"  No breakout XSS in parameter '{param_name}'", 'DEBUG')
    
    # Step 5: Test each POST parameter
    for param_name, method, form_data in form_params:
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
            callback_url=callback_url
        )
        
        if vuln:
            log(f"✓ BREAKOUT XSS found in parameter '{param_name}' (POST)", 'VULN')
            vulnerabilities.append(vuln)
        else:
            log(f"  No breakout XSS in parameter '{param_name}'", 'DEBUG')
    
    # Summary
    if vulnerabilities:
        log(f"\n🚨 Found {len(vulnerabilities)} breakout XSS vulnerabilit{'y' if len(vulnerabilities) == 1 else 'ies'}", 'VULN')
    else:
        log(f"\n✓ No breakout XSS vulnerabilities detected", 'INFO')
    
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
        'remediation': vuln.get('remediation'),
        'exploitation': vuln.get('exploitation'),
        'simple_payloads_blocked': vuln.get('simple_payloads_blocked', True),
    }
