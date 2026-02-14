#!/usr/bin/env python3
"""
Scanner Integration Patch for Breakout XSS Detection

This module provides a drop-in replacement for the XSS scanning portion
of scan_single_domain_for_vulnerabilities() in scanner.py

Usage in scanner.py:
    from scanners.xss_breakout_scanner_patch import scan_for_breakout_xss
    
    # Replace existing XSS scanning code with:
    if args.xss_deep:
        breakout_vulns = scan_for_breakout_xss(url, args, xss_timeout, xss_callback)
        vulns.extend(breakout_vulns)
"""

from typing import List, Dict, Optional
from .xss_breakout_integration import scan_url_for_breakout_xss, format_breakout_vuln_for_report


def log(msg: str, level: str = 'INFO'):
    """Simple logging function matching scanner.py style"""
    print(f"[{level}] {msg}")


def scan_for_breakout_xss(url: str, 
                          args,
                          timeout: int = 10,
                          callback_url: Optional[str] = None,
                          headers: Optional[Dict[str, str]] = None) -> List[Dict]:
    """
    Perform breakout XSS scanning on a URL
    
    This function integrates with the main scanner and returns vulnerabilities
    in the format expected by the scanner's reporting system.
    
    Args:
        url: Target URL to scan
        args: Command-line arguments from scanner.py
        timeout: Request timeout
        callback_url: Optional callback URL for blind XSS
    
    Returns:
        List of formatted vulnerability dictionaries
    """
    log(f"Running advanced breakout XSS scan on {url}", 'INFO')
    
    # Use Arjun parameter discovery unless disabled
    use_arjun = not getattr(args, 'skip_arjun', False)
    
    # Perform comprehensive breakout XSS scanning
    breakout_vulns = scan_url_for_breakout_xss(
        url=url,
        use_arjun=use_arjun,
        timeout=timeout,
        headers=headers,
        callback_url=callback_url,
        safe_mode=getattr(args, 'safe_mode', True),
        arjun_threads=getattr(args, 'arjun_threads', 10),
        arjun_timeout=getattr(args, 'arjun_timeout', 120),
        arjun_wordlist=getattr(args, 'arjun_wordlist', None),
        fallback_params=getattr(args, 'xss_fallback_params', None),
        crawl_enabled=getattr(args, 'xss_crawl_enabled', True),
        crawl_max_pages=getattr(args, 'xss_crawl_max_pages', 25),
        crawl_max_depth=getattr(args, 'xss_crawl_max_depth', 2)
    )
    
    # Format vulnerabilities for main scanner report
    formatted_vulns = []
    for vuln in breakout_vulns:
        formatted = format_breakout_vuln_for_report(vuln)
        formatted['url'] = url  # Ensure URL is set
        formatted_vulns.append(formatted)
        
        # Log each finding
        severity = formatted.get('severity', 'medium').upper()
        param = formatted.get('parameter', 'unknown')
        method = formatted.get('method', 'GET')
        context = formatted.get('context_type', 'unknown')
        score = formatted.get('cvss_score', 'N/A')
        
        log(f"BREAKOUT XSS [{severity}] on {url}: {param} ({method}) in {context} context (CVSS: {score})", 'VULN')
    
    return formatted_vulns


def get_xss_scan_summary(vulns: List[Dict]) -> str:
    """
    Generate a summary of breakout XSS findings
    
    Args:
        vulns: List of vulnerability dictionaries
    
    Returns:
        Formatted summary string
    """
    if not vulns:
        return "No breakout XSS vulnerabilities detected"
    
    summary_lines = []
    summary_lines.append(f"Found {len(vulns)} breakout XSS vulnerability(ies):")
    
    for vuln in vulns:
        param = vuln.get('parameter', 'unknown')
        method = vuln.get('method', 'GET')
        context = vuln.get('context_type', 'unknown')
        summary_lines.append(f"  - {param} ({method}): {context} context breakout")
    
    return "\n".join(summary_lines)
