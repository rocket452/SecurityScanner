#!/usr/bin/env python3
import subprocess
import sys
import argparse
import httpx
import yaml
import json
import csv
import os
import hashlib
from datetime import datetime
from pathlib import Path

# Load configuration
def load_config():
    try:
        with open('config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except:
        # Return defaults if config file not found
        return {
            'rate_limiting': {
                'nuclei_rate_limit': 150,
                'nuclei_concurrency': 25,
                'http_timeout': 10
            },
            'zap': {
                'enabled': False,
                'proxy_url': 'http://localhost:8080',
                'api_key': None,
                'timeout': 300,
                'spider': True,
                'passive_scan': True,
                'active_scan': False,
                'max_spider_depth': 5
            }
        }

CONFIG = load_config()

# Global variables for tracking scan metadata
SCAN_START_TIME = None
ALL_SUBDOMAINS = []

# ============================================================================
# VULNERABILITY DEDUPLICATION
# ============================================================================

def create_vuln_fingerprint(vuln):
    """
    Create a unique fingerprint for a vulnerability to detect duplicates.
    
    Args:
        vuln: Vulnerability dictionary
    
    Returns:
        str: Hash fingerprint of the vulnerability
    """
    # Normalize the vulnerability type and description for comparison
    vuln_type = vuln.get('type', 'unknown').lower().strip()
    description = vuln.get('description', '').lower().strip()
    url = vuln.get('url', '').lower().strip()
    
    # Remove common prefixes like [ZAP], [NUCLEI], etc.
    description = description.replace('[zap]', '').replace('[nuclei]', '').strip()
    
    # Create fingerprint from type + description + url
    fingerprint_data = f"{vuln_type}|{description}|{url}"
    return hashlib.md5(fingerprint_data.encode()).hexdigest()

def deduplicate_vulnerabilities(vulnerabilities):
    """
    Remove duplicate vulnerabilities based on fingerprinting.
    Keeps the first occurrence and tracks which scanner found it.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
    
    Returns:
        List of deduplicated vulnerabilities with source tracking
    """
    seen_fingerprints = {}
    deduplicated = []
    
    for vuln in vulnerabilities:
        fingerprint = create_vuln_fingerprint(vuln)
        
        if fingerprint not in seen_fingerprints:
            # First time seeing this vulnerability
            seen_fingerprints[fingerprint] = vuln
            
            # Add source tracking
            if 'sources' not in vuln:
                # Determine source from type
                vuln_type = vuln.get('type', '')
                if vuln_type.startswith('zap_'):
                    vuln['sources'] = ['ZAP']
                elif vuln_type == 'nuclei':
                    vuln['sources'] = ['Nuclei']
                elif vuln_type == 'xss':
                    vuln['sources'] = ['XSS Scanner']
                else:
                    vuln['sources'] = ['Custom Scanner']
            
            deduplicated.append(vuln)
        else:
            # Duplicate found - add source to existing vulnerability
            existing_vuln = seen_fingerprints[fingerprint]
            
            # Determine source of duplicate
            vuln_type = vuln.get('type', '')
            if vuln_type.startswith('zap_'):
                source = 'ZAP'
            elif vuln_type == 'nuclei':
                source = 'Nuclei'
            elif vuln_type == 'xss':
                source = 'XSS Scanner'
            else:
                source = 'Custom Scanner'
            
            # Add source if not already tracked
            if source not in existing_vuln['sources']:
                existing_vuln['sources'].append(source)
    
    if len(vulnerabilities) > len(deduplicated):
        duplicates_removed = len(vulnerabilities) - len(deduplicated)
        log(f'Removed {duplicates_removed} duplicate finding(s)', 'INFO')
    
    return deduplicated

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Main entry point for the security scanner.
    Clean and simple: discover -> scan -> report.
    """
    global SCAN_START_TIME
    SCAN_START_TIME = datetime.now()
    
    # Parse arguments
    args = parse_arguments()
    
    # Print header
    print_header(args.target)
    
    # Step 1: Discover all subdomains
    subdomains = discover_all_subdomains(args.target)
    
    # Step 2: Run all vulnerability scans
    scan_results = run_all_scans(subdomains, args)
    
    # Step 3: Deduplicate findings across all URLs
    scan_results = deduplicate_scan_results(scan_results)
    
    # Step 4: Generate and save reports
    generate_reports(scan_results, args)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Security Scanner with ZAP and Nuclei Integration')
    parser.add_argument('target', help='Target domain')
    parser.add_argument('-o', '--output', help='Output file path (default: /reports/report_<target>_<timestamp>.<format>)', default=None)
    parser.add_argument('-f', '--format', choices=['json', 'html', 'markdown', 'csv'], 
                       help='Report format (default: json)', default='json')
    parser.add_argument('--no-file', action='store_true', help='Skip saving report to file (console only)')
    
    # ZAP integration options
    parser.add_argument('--zap', action='store_true', help='Enable OWASP ZAP scanning')
    parser.add_argument('--zap-active', action='store_true', help='Enable ZAP active scanning (requires permission!)')
    parser.add_argument('--zap-proxy', default=None, help='ZAP proxy URL (default: from config.yaml)')
    parser.add_argument('--zap-timeout', type=int, default=None, help='ZAP scan timeout in seconds (default: 300)')
    parser.add_argument('--zap-only', action='store_true', help='Run only ZAP scans (skip other vulnerability scanners)')
    parser.add_argument('--skip-nuclei', action='store_true', help='Skip Nuclei scanning')
    
    return parser.parse_args()

def print_header(target):
    """Print scan header with target information."""
    print(f'\n🔍 {target}')
    print('=' * 60)
    rate_limits = CONFIG.get('rate_limiting', {})
    log(f'Rate limiting: ffuf={rate_limits.get("ffuf_threads", 20)} threads, '
        f'nuclei={rate_limits.get("nuclei_rate_limit", 150)}/min, '
        f'concurrency={rate_limits.get("nuclei_concurrency", 25)}', 'INFO')

# ============================================================================
# STEP 1: SUBDOMAIN DISCOVERY
# ============================================================================

def discover_all_subdomains(target):
    """
    Discover all subdomains using multiple tools.
    Returns a deduplicated list of all discovered subdomains including the base domain.
    """
    global ALL_SUBDOMAINS
    
    subdomains = []
    
    # Run discovery tools
    subdomains.extend(retrieve_sub_domains_from_subfinder(target))
    subdomains.extend(retrieve_sub_domains_from_amass(target))
    
    # Always include the base domain
    subdomains.append(target)
    log(f'Including base domain in scan: {target}', 'INFO')
    
    # Deduplicate
    subdomains = deduplicate_domains(subdomains)
    ALL_SUBDOMAINS = subdomains
    
    # Print summary
    print_scan_summary(subdomains, target)
    
    return subdomains

# ============================================================================
# STEP 2: VULNERABILITY SCANNING
# ============================================================================

def run_all_scans(subdomains, args):
    """
    Run all enabled vulnerability scans on discovered subdomains.
    Returns combined scan results from all scanners.
    """
    # Probe for live domains
    live_domains = probe_live_domains(subdomains)
    
    # Initialize results
    all_results = {}
    
    # Run ZAP scanning if enabled
    if args.zap or CONFIG.get('zap', {}).get('enabled', False):
        log('ZAP scanning enabled', 'INFO')
        zap_results = run_zap_scans(live_domains, args)
        all_results.update(zap_results)
    
    # Run traditional vulnerability scans unless --zap-only is specified
    if not args.zap_only:
        traditional_results = run_traditional_scans(live_domains, skip_nuclei=args.skip_nuclei)
        
        # Merge with ZAP results
        for url, vulns in traditional_results:
            if url in all_results:
                all_results[url].extend(vulns)
            else:
                all_results[url] = vulns
    
    # Convert dict to list of tuples for reporting
    scan_results = [(url, vulns) for url, vulns in all_results.items()]
    
    return scan_results

def run_traditional_scans(live_domains, skip_nuclei=False):
    """
    Run traditional vulnerability scanners on live domains.
    """
    scan_results = []
    for url, is_live, status_code in live_domains:
        if is_live:
            vulns = scan_single_domain_for_vulnerabilities(url, skip_nuclei=skip_nuclei)
            scan_results.append((url, vulns))
    
    return scan_results

def deduplicate_scan_results(scan_results):
    """
    Deduplicate vulnerabilities across all scanned URLs.
    
    Args:
        scan_results: List of (url, vulnerabilities) tuples
    
    Returns:
        List of (url, deduplicated_vulnerabilities) tuples
    """
    deduplicated_results = []
    
    for url, vulns in scan_results:
        deduplicated_vulns = deduplicate_vulnerabilities(vulns)
        deduplicated_results.append((url, deduplicated_vulns))
    
    return deduplicated_results

# ============================================================================
# STEP 3: REPORT GENERATION
# ============================================================================

def generate_reports(scan_results, args):
    """
    Generate and save all reports.
    Prints to console and optionally saves to file.
    """
    # Print to console
    print_vulnerability_report(scan_results)
    
    # Save to file if not disabled
    if not args.no_file:
        output_file = save_report(scan_results, args.target, args.output, args.format)
        if output_file:
            log(f'Report saved to: {output_file}', 'INFO')

# ============================================================================
# LOGGING UTILITIES
# ============================================================================

def log(msg, level='INFO'):
    """Centralized logging function"""
    print(f'[{level}] {msg}')

# ============================================================================
# SUBDOMAIN ENUMERATION
# ============================================================================

def retrieve_sub_domains_from_subfinder(target):
    """
    Use Subfinder to discover subdomains for the target domain.
    """
    log(f'Subfinder on {target}')
    cmd = ['subfinder', '-d', target, '-silent']
    
    try:
        log(f'Running: {" ".join(cmd)}')
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        
        if subdomains:
            log(f'Subfinder found {len(subdomains)} subdomain(s)', 'OK')
            for sub in sorted(subdomains):
                log(f'  → {sub}', 'OK')
            return subdomains
        else:
            log('Subfinder found no subdomains', 'INFO')
            return []
            
    except subprocess.TimeoutExpired:
        log('Subfinder timeout', 'WARN')
        return []
    except FileNotFoundError:
        log('Subfinder not installed', 'WARN')
        return []
    except subprocess.CalledProcessError as e:
        log(f'Subfinder error {e.returncode}: {e.stderr[:200]}...', 'ERROR')
        return []
    except Exception as e:
        log(f'Subfinder unexpected error: {e}', 'ERROR')
        return []

def retrieve_sub_domains_from_amass(target):
    """
    Use Amass to discover subdomains for the target domain.
    """
    log(f'Amass on {target}')
    cmd = ['amass', 'enum', '-passive', '-d', target, '-silent']
    
    try:
        log(f'Running: {" ".join(cmd)}')
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
        subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        
        if subdomains:
            log(f'Amass found {len(subdomains)} subdomain(s)', 'OK')
            for sub in sorted(subdomains):
                log(f'  → {sub}', 'OK')
            return subdomains
        else:
            log('Amass found no subdomains', 'INFO')
            return []
            
    except subprocess.TimeoutExpired:
        log('Amass timeout', 'WARN')
        return []
    except FileNotFoundError:
        log('Amass not installed', 'WARN')
        return []
    except subprocess.CalledProcessError as e:
        log(f'Amass error {e.returncode}: {e.stderr[:300] or e.stdout[:300]}...', 'ERROR')
        return []
    except Exception as e:
        log(f'Amass unexpected error: {e}', 'ERROR')
        return []

def deduplicate_domains(domains):
    """
    Remove duplicate domains from the list and return sorted unique domains.
    """
    unique_domains = sorted(set(domains))
    log(f'Deduplicated to {len(unique_domains)} unique domain(s)', 'INFO')
    return unique_domains

# ============================================================================
# ZAP INTEGRATION
# ============================================================================

def run_zap_scans(live_domains, args):
    """
    Run OWASP ZAP scans on discovered subdomains.
    
    Args:
        live_domains: List of (url, is_live, status_code) tuples
        args: Command line arguments
    
    Returns:
        Dict mapping URLs to their ZAP vulnerabilities
    """
    try:
        from scanners.zap_scanner import ZAPScanner, check_zap_docker
    except ImportError:
        log('ZAP scanner module not found', 'ERROR')
        return {}
    
    # Get ZAP configuration
    zap_config = CONFIG.get('zap', {})
    zap_proxy = args.zap_proxy or zap_config.get('proxy_url', 'http://localhost:8080')
    zap_timeout = args.zap_timeout or zap_config.get('timeout', 300)
    zap_api_key = zap_config.get('api_key')
    
    # Check if ZAP is running
    log(f'Checking ZAP at {zap_proxy}...', 'INFO')
    
    try:
        scanner = ZAPScanner(proxy_url=zap_proxy, api_key=zap_api_key, timeout=zap_timeout)
        
        if not scanner.check_zap_running():
            log('ZAP is not accessible. Starting ZAP...', 'WARN')
            if not check_zap_docker():
                log('ZAP could not be started. Ensure ZAP container is running: docker-compose up -d zap', 'ERROR')
                return {}
    except Exception as e:
        log(f'Error connecting to ZAP: {e}', 'ERROR')
        return {}
    
    log('✅ ZAP is running and accessible', 'OK')
    
    # Prepare list of URLs to scan
    urls_to_scan = [url for url, is_live, _ in live_domains if is_live]
    
    if not urls_to_scan:
        log('No live domains to scan with ZAP', 'WARN')
        return {}
    
    log(f'Scanning {len(urls_to_scan)} domain(s) with ZAP', 'INFO')
    
    # Determine scan options
    spider_enabled = zap_config.get('spider', True)
    passive_enabled = zap_config.get('passive_scan', True)
    active_enabled = args.zap_active or zap_config.get('active_scan', False)
    
    if active_enabled:
        log('⚠️ ACTIVE SCANNING ENABLED - Only use on authorized targets!', 'WARN')
    
    # Run ZAP scans
    try:
        results = scanner.scan_subdomain_list(
            urls_to_scan,
            spider=spider_enabled,
            passive=passive_enabled,
            active=active_enabled
        )
        
        # Convert ZAP alerts to vulnerability format
        zap_vulns = {}
        for url, alerts in results.items():
            vulns = scanner.parse_alerts_to_vulns(alerts)
            zap_vulns[url] = vulns
            
            # Log summary
            if vulns:
                log(f'ZAP found {len(vulns)} vulnerability(ies) on {url}', 'OK')
        
        return zap_vulns
        
    except Exception as e:
        log(f'Error during ZAP scanning: {e}', 'ERROR')
        return {}

# Import remaining functions from original scanner.py
# (scan_single_domain_for_vulnerabilities, probe_live_domains, reporting functions, etc.)
# These are unchanged and too long to include here - keeping them as-is

# [REST OF THE ORIGINAL CODE CONTINUES HERE - unchanged]
