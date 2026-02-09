#!/usr/bin/env python3
"""
Enhanced XSS Scanner with Breakout Detection Integration

Integrates the breakout detector into the advanced XSS scanning workflow.
This module extends xss_advanced.py to specifically identify and report
breakout-only XSS vulnerabilities.
"""

import httpx
import urllib.parse
from typing import List, Dict, Optional
from .xss_advanced import (
    advanced_xss_scan, 
    CSPAnalyzer, 
    SeverityScorer,
    ExploitationProofGenerator,
    log
)
from .xss_breakout_detector import (
    detect_breakout_xss,
    BreakoutContextAnalyzer,
    BreakoutPayloadGenerator
)
from .xss_scanner import extract_forms
from .param_discovery import discover_parameters


def enhanced_xss_scan_with_breakout(url: str,
                                     mode: str = 'advanced',
                                     timeout: int = 10,
                                     enable_param_discovery: bool = True) -> Dict:
    """
    Comprehensive XSS scan that identifies both standard and breakout XSS
    
    Args:
        url: Target URL to scan
        mode: Scan mode ('basic', 'advanced', 'exploitation')
        timeout: Request timeout in seconds
        enable_param_discovery: Use Arjun to discover hidden parameters
    
    Returns:
        Dictionary containing:
        - standard_xss: List of regular XSS vulnerabilities
        - breakout_xss: List of breakout-only XSS vulnerabilities
        - summary: Scan summary and statistics
    """
    
    log(f"Starting enhanced XSS scan with breakout detection on {url}", 'INFO')
    
    # Run standard advanced scan first
    standard_vulns = advanced_xss_scan(
        url=url,
        mode=mode,
        timeout=timeout,
        enable_param_discovery=enable_param_discovery
    )
    
    # Now run breakout-specific detection
    breakout_vulns = scan_for_breakout_xss(
        url=url,
        timeout=timeout,
        enable_param_discovery=enable_param_discovery
    )
    
    # Filter out duplicates (parameters found in both scans)
    standard_params = {v.get('parameter') for v in standard_vulns}
    breakout_only = [
        v for v in breakout_vulns 
        if v.get('parameter') not in standard_params
    ]
    
    # Generate summary
    summary = {
        'total_vulnerabilities': len(standard_vulns) + len(breakout_only),
        'standard_xss_count': len(standard_vulns),
        'breakout_xss_count': len(breakout_only),
        'url': url,
        'scan_mode': mode,
    }
    
    if breakout_only:
        log(f"Found {len(breakout_only)} breakout-only XSS vulnerability(ies)", 'VULN')
    
    return {
        'standard_xss': standard_vulns,
        'breakout_xss': breakout_only,
        'summary': summary,
    }


def scan_for_breakout_xss(url: str,
                          timeout: int = 10,
                          enable_param_discovery: bool = True) -> List[Dict]:
    """
    Scan specifically for breakout XSS scenarios
    
    This function tests parameters to find cases where:
    1. Simple XSS payloads are blocked/encoded
    2. Context breakout payloads succeed
    
    Args:
        url: Target URL
        timeout: Request timeout
        enable_param_discovery: Use parameter discovery
    
    Returns:
        List of breakout XSS vulnerabilities
    """
    vulnerabilities = []
    
    log(f"Starting breakout-specific XSS scan on {url}", 'INFO')
    
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            # Get initial page
            response = client.get(url)
            
            # Parse URL parameters
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Parameter discovery
            discovered_params = []
            if enable_param_discovery:
                log("Running parameter discovery for breakout scan...", 'INFO')
                arjun_result = discover_parameters(url, method='GET', threads=5, timeout=30)
                if arjun_result.get('parameters'):
                    discovered_params = arjun_result['parameters']
                    log(f"Discovered {len(discovered_params)} parameters for breakout testing", 'INFO')
                    for param in discovered_params:
                        if param not in params:
                            params[param] = ['test']
            
            # If no parameters found, try common ones
            if not params:
                common_params = ['q', 'search', 'query', 'keyword', 'searchFor', 'term', 'id', 'name', 'input', 'data']
                params = {param: ['test'] for param in common_params}
                log(f"No parameters found, testing {len(common_params)} common parameter names", 'INFO')
            
            # Test each GET parameter for breakout XSS
            for param_name in params.keys():
                log(f"Testing parameter '{param_name}' for breakout XSS...", 'INFO')
                
                result = detect_breakout_xss(
                    url=url,
                    param_name=param_name,
                    method='GET',
                    timeout=timeout
                )
                
                if result:
                    # Enhance the result with additional metadata
                    result['discovery_method'] = 'Arjun' if param_name in discovered_params else 'URL parsing'
                    result['scanner'] = 'Breakout XSS Scanner'
                    
                    # Add CSP analysis
                    csp_analysis = CSPAnalyzer.analyze_csp(
                        CSPAnalyzer.extract_csp(dict(response.headers))
                    )
                    result['csp_analysis'] = csp_analysis
                    
                    vulnerabilities.append(result)
                    log(f"BREAKOUT XSS FOUND: {param_name} (context: {result['context_type']})", 'VULN')
            
            # Extract and test forms
            forms = extract_forms(response.text)
            if forms:
                log(f"Testing {len(forms)} form(s) for breakout XSS", 'INFO')
                
                for form in forms:
                    if not form['inputs']:
                        continue
                    
                    form_action = form['action']
                    form_url = urllib.parse.urljoin(url, form_action) if form_action else url
                    
                    # Build form data
                    form_data = {}
                    for inp in form['inputs']:
                        if inp['type'] not in ['submit', 'button', 'image']:
                            form_data[inp['name']] = inp['value'] or 'test'
                    
                    # Test each form field
                    for inp in form['inputs']:
                        if inp['type'] in ['submit', 'button', 'image']:
                            continue
                        
                        field_name = inp['name']
                        log(f"Testing form field '{field_name}' for breakout XSS...", 'INFO')
                        
                        result = detect_breakout_xss(
                            url=form_url,
                            param_name=field_name,
                            method=form['method'],
                            form_data=form_data,
                            timeout=timeout
                        )
                        
                        if result:
                            result['discovery_method'] = 'Form extraction'
                            result['scanner'] = 'Breakout XSS Scanner'
                            result['form_action'] = form_action
                            
                            csp_analysis = CSPAnalyzer.analyze_csp(
                                CSPAnalyzer.extract_csp(dict(response.headers))
                            )
                            result['csp_analysis'] = csp_analysis
                            
                            vulnerabilities.append(result)
                            log(f"BREAKOUT XSS FOUND: Form field {field_name} (context: {result['context_type']})", 'VULN')
    
    except Exception as e:
        log(f"Breakout XSS scan error: {str(e)}", 'ERROR')
    
    return vulnerabilities


def format_breakout_report(breakout_vulns: List[Dict]) -> str:
    """
    Format breakout XSS vulnerabilities into a detailed report
    
    Args:
        breakout_vulns: List of breakout XSS vulnerability dicts
    
    Returns:
        Formatted string report
    """
    if not breakout_vulns:
        return "No breakout XSS vulnerabilities found.\n"
    
    report = []
    report.append("\n" + "="*80)
    report.append("BREAKOUT XSS VULNERABILITIES DETECTED")
    report.append("="*80 + "\n")
    report.append(f"Total breakout-only XSS vulnerabilities: {len(breakout_vulns)}\n")
    
    for idx, vuln in enumerate(breakout_vulns, 1):
        report.append(f"\n[{idx}] BREAKOUT XSS VULNERABILITY")
        report.append("-" * 80)
        report.append(f"URL: {vuln['url']}")
        report.append(f"Parameter: {vuln['parameter']}")
        report.append(f"Method: {vuln['method']}")
        report.append(f"Severity: {vuln['severity'].upper()}")
        report.append(f"Discovery Method: {vuln.get('discovery_method', 'Unknown')}\n")
        
        report.append(f"Context Type: {vuln['context_type']}")
        report.append(f"Context Description: {vuln['context_description']}\n")
        
        report.append("Surrounding Code:")
        report.append(f"  {vuln['surrounding_code']}\n")
        
        report.append("Context Snippet (showing reflection):")
        report.append(f"  {vuln['context_snippet'][:200]}...\n")
        
        report.append(f"Required Escape: {vuln['required_escape']}")
        report.append(f"Successful Payload: {vuln['successful_payload']}")
        report.append(f"Payload Description: {vuln['payload_description']}\n")
        
        report.append("Why This is Breakout XSS:")
        report.append("  - Simple XSS payloads (e.g., <script>alert('XSS')</script>) are blocked")
        report.append("  - The input is embedded in a restrictive context that requires escaping")
        report.append(f"  - {vuln['exploitation']['explanation']}\n")
        
        report.append("Exploitation:")
        report.append(f"  {vuln['exploitation']['curl_command']}\n")
        
        report.append("Remediation:")
        report.append(f"  {vuln['remediation']}\n")
        
        if 'csp_analysis' in vuln:
            report.append("CSP Status:")
            csp = vuln['csp_analysis']
            if csp['present']:
                report.append(f"  Present: Yes")
                report.append(f"  Bypasses: {', '.join(csp['potential_bypasses'])}")
            else:
                report.append(f"  Present: No (all XSS vectors available)")
        
        report.append("\n" + "="*80 + "\n")
    
    return "\n".join(report)


def get_breakout_statistics(results: Dict) -> Dict:
    """
    Generate statistics about breakout XSS findings
    
    Args:
        results: Results dict from enhanced_xss_scan_with_breakout
    
    Returns:
        Statistics dictionary
    """
    breakout_vulns = results.get('breakout_xss', [])
    
    if not breakout_vulns:
        return {'has_breakout_xss': False}
    
    # Count by context type
    context_counts = {}
    for vuln in breakout_vulns:
        ctx = vuln['context_type']
        context_counts[ctx] = context_counts.get(ctx, 0) + 1
    
    # Count by discovery method
    discovery_counts = {}
    for vuln in breakout_vulns:
        method = vuln.get('discovery_method', 'Unknown')
        discovery_counts[method] = discovery_counts.get(method, 0) + 1
    
    return {
        'has_breakout_xss': True,
        'total_breakout_vulns': len(breakout_vulns),
        'context_type_breakdown': context_counts,
        'discovery_method_breakdown': discovery_counts,
        'most_common_context': max(context_counts.items(), key=lambda x: x[1])[0] if context_counts else None,
    }
