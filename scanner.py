#!/usr/bin/env python3
import subprocess
import sys
import argparse
import httpx
import yaml
import json
import csv
import os
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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

# Get custom headers from bug bounty config
CUSTOM_HEADERS = CONFIG.get('bug_bounty', {}).get('custom_headers', {})

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point for the security scanner.
    Clean and simple: discover -> scan -> deduplicate -> report.
    """
    global SCAN_START_TIME
    SCAN_START_TIME = datetime.now()
    
    # Parse arguments
    args = parse_arguments()
    
    # Log bug bounty program info if configured
    bug_bounty_config = CONFIG.get('bug_bounty', {})
    if bug_bounty_config:
        program = bug_bounty_config.get('program')
        username = bug_bounty_config.get('hackerone_username')
        if program:
            log(f'🎯 Bug Bounty Program: {program}', 'INFO')
        if username:
            log(f'👤 HackerOne Username: {username}', 'INFO')
        if CUSTOM_HEADERS:
            log(f'📋 Custom Headers: {", ".join(f"{k}: {v}" for k, v in CUSTOM_HEADERS.items())}', 'INFO')
    
    # Run with or without keep-awake based on flag
    if args.keep_awake:
        log('Keep-awake mode enabled - system will not sleep during scan', 'INFO')
        from keep_awake import keep_awake_context
        with keep_awake_context():
            run_scan(args)
    else:
        run_scan(args)

def run_scan(args):
    """Execute the main scan workflow."""
    # Stage 0: Resolve target(s) - either from HackerOne or manual input
    targets = resolve_targets(args)
    
    if not targets:
        log('No targets to scan', 'ERROR')
        sys.exit(1)
    
    # Aggregate results from all targets
    all_scan_results = []
    
    # Process each target
    for target in targets:
        # Print header
        print_header(target)
        
        # Step 1: Discover all subdomains
        subdomains = discover_all_subdomains(target)
        
        # Step 2: Run all vulnerability scans
        scan_results = run_all_scans(subdomains, args)
        
        # Add to aggregated results
        all_scan_results.extend(scan_results)
    
    # Step 3: Deduplicate findings across all targets
    from scanners.deduplicator import deduplicate_scan_results
    all_scan_results = deduplicate_scan_results(all_scan_results)
    
    # Step 4: Generate and save reports
    # Use first target or program name for report naming
    report_target = args.h1_program if args.fetch_scope else targets[0]
    generate_reports(all_scan_results, args, report_target)

def resolve_targets(args):
    """Resolve target(s) from either HackerOne Scope Fetcher or manual input.
    
    Returns:
        List of target domain strings
    """
    if args.fetch_scope:
        # Import scope fetcher
        try:
            from scanners.hackerone_scope_fetcher import (
                HackerOneAPIScopeFetcher,
                ScopeFilter,
                EligibilityFilter,
                ScopeExporter
            )
        except ImportError as e:
            log(f'Failed to import HackerOne Scope Fetcher: {e}', 'ERROR')
            sys.exit(1)
        
        log(f'Fetching scope for HackerOne program: {args.h1_program}', 'INFO')
        
        # Get credentials from args or environment variables
        h1_username = args.h1_username or os.getenv('H1_USERNAME')
        h1_token = args.h1_token or os.getenv('H1_TOKEN')
        
        if h1_username and h1_token:
            log('Using HackerOne API credentials (authenticated)', 'INFO')
        else:
            log('No credentials provided - accessing public programs only', 'INFO')
        
        # Initialize fetcher with credentials
        fetcher = HackerOneAPIScopeFetcher(
            username=h1_username,
            api_token=h1_token
        )
        
        # Fetch program scope
        program = fetcher.get_program_by_handle(args.h1_program)
        
        if not program:
            log(f'Failed to fetch program: {args.h1_program}', 'ERROR')
            sys.exit(1)
        
        # Print program summary
        ScopeExporter.print_summary(program)
        
        # Apply scope filter
        filter_type = EligibilityFilter(args.scope_filter)
        filtered_assets = ScopeFilter.filter_by_eligibility(program.assets, filter_type)
        
        log(f'Filtered to {len(filtered_assets)} asset(s) using filter: {args.scope_filter}', 'INFO')
        
        # Determine if IPs should be skipped
        skip_ips = not args.include_ips
        
        # Export scope if requested
        if args.export_scope:
            ScopeExporter.to_text(filtered_assets, args.export_scope, skip_ips=skip_ips)
        
        # Extract scannable targets (skip IPs by default)
        targets = ScopeFilter.extract_targets(filtered_assets, skip_ips=skip_ips)
        
        if not targets:
            log('No scannable targets found in program scope', 'WARN')
            return []
        
        log(f'✓ Extracted {len(targets)} scannable target(s) from HackerOne', 'OK')
        print('\nTargets to scan:')
        for target in targets[:10]:  # Show first 10
            print(f'  • {target}')
        if len(targets) > 10:
            print(f'  ... and {len(targets) - 10} more')
        print()
        
        return targets
    
    else:
        # Manual target provided
        return [args.target]

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Security Scanner with HackerOne Integration, ZAP and Nuclei',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Manual target scan
  %(prog)s example.com --zap
  
  # HackerOne program scan (public program)
  %(prog)s --fetch-scope --h1-program github
  
  # HackerOne with credentials from .env file
  %(prog)s --fetch-scope --h1-program github
  
  # HackerOne with credentials from command line
  %(prog)s --fetch-scope --h1-username USER --h1-token TOKEN --h1-program github
  
  # Export scope for review
  %(prog)s --fetch-scope --h1-program github --export-scope github_scope.txt
  
  # Include IP addresses in scan (default: skip)
  %(prog)s --fetch-scope --h1-program shopify --include-ips
  
  # Keep system awake during long scan
  %(prog)s example.com --keep-awake
        '''
    )
    
    # Target specification (required unless using --fetch-scope)
    parser.add_argument('target', nargs='?', help='Target domain (not required if --fetch-scope is used)')
    
    # HackerOne Scope Fetcher options
    scope_group = parser.add_argument_group('HackerOne Scope Fetcher')
    scope_group.add_argument(
        '--fetch-scope',
        action='store_true',
        help='Fetch scope from HackerOne program'
    )
    scope_group.add_argument(
        '--h1-program',
        help='HackerOne program handle (e.g., github, gitlab, shopify)'
    )
    scope_group.add_argument(
        '--h1-username',
        help='HackerOne username (optional, can use H1_USERNAME env var)'
    )
    scope_group.add_argument(
        '--h1-token',
        help='HackerOne API token (optional, can use H1_TOKEN env var)'
    )
    scope_group.add_argument(
        '--scope-filter',
        choices=['all', 'bounty-eligible', 'in-scope', 'out-of-scope'],
        default='bounty-eligible',
        help='Filter scope by eligibility (default: bounty-eligible)'
    )
    scope_group.add_argument(
        '--include-ips',
        action='store_true',
        help='Include IP addresses and CIDR ranges in scan (default: skip for faster scans)'
    )
    scope_group.add_argument(
        '--export-scope',
        metavar='FILE',
        help='Export filtered scope to text file'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        help='Output file path (default: ./reports/report_<target>_<timestamp>.<format>)'
    )
    output_group.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'markdown', 'csv'],
        default='json',
        help='Report format (default: json)'
    )
    output_group.add_argument(
        '--no-file',
        action='store_true',
        help='Skip saving report to file (console only)'
    )
    
    # System options
    system_group = parser.add_argument_group('System Options')
    system_group.add_argument(
        '--keep-awake',
        action='store_true',
        help='Keep system awake during scan (prevents sleep, allows screen lock)'
    )
    
    # ZAP integration options
    zap_group = parser.add_argument_group('OWASP ZAP Options')
    zap_group.add_argument(
        '--zap',
        action='store_true',
        help='Enable OWASP ZAP scanning'
    )
    zap_group.add_argument(
        '--zap-active',
        action='store_true',
        help='Enable ZAP active scanning (requires permission!)'
    )
    zap_group.add_argument(
        '--zap-proxy',
        help='ZAP proxy URL (default: http://localhost:8080)'
    )
    zap_group.add_argument(
        '--zap-timeout',
        type=int,
        help='ZAP scan timeout in seconds (default: 300)'
    )
    zap_group.add_argument(
        '--zap-only',
        action='store_true',
        help='Run only ZAP scans (skip other vulnerability scanners)'
    )
    
    # Scanner options
    scanner_group = parser.add_argument_group('Scanner Options')
    scanner_group.add_argument(
        '--skip-nuclei',
        action='store_true',
        help='Skip Nuclei scanning'
    )
    
    args = parser.parse_args()
    
    # Validation: require either target or --fetch-scope
    if not args.fetch_scope and not args.target:
        parser.error('Either provide a target domain or use --fetch-scope with --h1-program')
    
    if args.fetch_scope and not args.h1_program:
        parser.error('--fetch-scope requires --h1-program')
    
    return args

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
    """Discover all subdomains using multiple tools.
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
    """Run all enabled vulnerability scans on discovered subdomains.
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
    """Run traditional vulnerability scanners on live domains."""
    scan_results = []
    for url, is_live, status_code in live_domains:
        if is_live:
            vulns = scan_single_domain_for_vulnerabilities(url, skip_nuclei=skip_nuclei)
            scan_results.append((url, vulns))
    
    return scan_results

# ============================================================================
# STEP 3: REPORT GENERATION
# ============================================================================

def generate_reports(scan_results, args, target):
    """Generate and save all reports.
    Prints to console and optionally saves to file.
    """
    # Print to console
    print_vulnerability_report(scan_results)
    
    # Save to file if not disabled
    if not args.no_file:
        output_file = save_report(scan_results, target, args.output, args.format)
        if output_file:
            log(f'Report saved to: {output_file}', 'INFO')
        
        # Generate ZAP-specific report if ZAP was used
        if args.zap and scan_results:
            generate_zap_report(output_file, args)

def generate_zap_report(output_file, args):
    """Generate ZAP-specific HTML report."""
    try:
        from scanners.zap_scanner import ZAPScanner
        zap_proxy = args.zap_proxy or CONFIG.get('zap', {}).get('proxy_url', 'http://localhost:8080')
        scanner = ZAPScanner(proxy_url=zap_proxy)
        
        zap_report_path = output_file.replace(f'.{args.format}', '_zap.html')
        if scanner.generate_report(zap_report_path, format='html'):
            log(f'ZAP report saved to: {zap_report_path}', 'INFO')
    except Exception as e:
        log(f'Could not generate ZAP report: {e}', 'WARN')

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
    """Use Subfinder to discover subdomains for the target domain."""
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
    """Use Amass to discover subdomains for the target domain."""
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
    """Remove duplicate domains from the list and return sorted unique domains."""
    unique_domains = sorted(set(domains))
    log(f'Deduplicated to {len(unique_domains)} unique domain(s)', 'INFO')
    return unique_domains

# ============================================================================
# ZAP INTEGRATION
# ============================================================================

def run_zap_scans(live_domains, args):
    """Run OWASP ZAP scans on discovered subdomains.
    
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
                log('ZAP could not be started. Run manually: docker run -u zap -p 8080:8080 -d zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true', 'ERROR')
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

# ============================================================================
# VULNERABILITY SCANNING
# ============================================================================

def scan_single_domain_for_vulnerabilities(url, skip_nuclei=False):
    """Perform comprehensive vulnerability scanning on a single URL."""
    vulns = []
    
    try:
        # Import scanners from scanners package
        from scanners.admin_scanner import check_admin
        from scanners.backup_scanner import check_backup
        from scanners.directory_scanner import check_exposed_buckets, fuzz_directories
        from scanners.xss_scanner import check_xss
        
        # Admin panel detection
        if check_admin(url):
            vulns.append({'type': 'admin_panel', 'description': 'Admin panel exposed', 'severity': 'medium', 'url': url})
            log(f'ADMIN on {url}', 'VULN')
        
        # Backup file detection
        if check_backup(url):
            vulns.append({'type': 'backup_file', 'description': 'Backup file found', 'severity': 'high', 'url': url})
            log(f'BACKUP on {url}', 'VULN')
        
        # XSS vulnerability detection
        xss_vulns = check_xss(url)
        if xss_vulns:
            for xss_vuln in xss_vulns:
                xss_vuln['url'] = url
            vulns.extend(xss_vulns)
            for xss_vuln in xss_vulns:
                severity = xss_vuln.get('severity', 'medium').upper()
                desc = xss_vuln.get('description', 'XSS vulnerability')
                log(f'XSS [{severity}] on {url}: {desc}', 'VULN')
        
        # Exposed buckets/storage detection (scanner module handles its own logging)
        bucket_results = check_exposed_buckets(url)
        
        if bucket_results:
            for path, status, vuln_type in bucket_results:
                # Construct full URL from base url and path
                from urllib.parse import urljoin
                full_url = urljoin(url, path)
                
                if vuln_type == 'DIRECTORY_LISTING':
                    vulns.append({
                        'type': 'exposed_storage',
                        'description': f'Exposed directory listing: {full_url}',
                        'status_code': status,
                        'severity': 'high',
                        'url': url
                    })
                    log(f'BUCKET EXPOSED: {full_url} [{status}] - {vuln_type}', 'VULN')
                elif vuln_type == 'ACCESSIBLE':
                    vulns.append({
                        'type': 'accessible_path',
                        'description': f'Accessible path: {full_url}',
                        'status_code': status,
                        'severity': 'medium',
                        'url': url
                    })
                    log(f'ACCESSIBLE PATH: {full_url} [{status}]', 'VULN')
                elif vuln_type == 'FORBIDDEN_BUT_EXISTS':
                    # Log it but DON'T add to vulnerabilities list
                    log(f'PATH EXISTS (forbidden): {full_url} [{status}]', 'INFO')
        
        # Recursive directory fuzzing (scanner module handles its own logging)
        discovered = fuzz_directories(url, timeout=180, recursive=True, max_depth=3)
        
        if discovered:
            log(f'Discovered {len(discovered)} total paths via recursive fuzzing', 'OK')
            accessible_count = 0
            for path, status in discovered:
                # Only report 200-level and 300-level status codes as findings
                if status.startswith('2') or status.startswith('3'):
                    # Construct full URL
                    from urllib.parse import urljoin
                    full_path_url = urljoin(url, path)
                    
                    vulns.append({
                        'type': 'discovered_path',
                        'description': f'Discovered path: {full_path_url}',
                        'status_code': int(status),
                        'severity': 'low',
                        'url': url
                    })
                    accessible_count += 1
                    if accessible_count <= 20:
                        log(f'FUZZ: {full_path_url} [{status}]', 'VULN')
                else:
                    # Log 403, 401 etc. but don't count as vulnerabilities
                    if accessible_count <= 20:
                        from urllib.parse import urljoin
                        full_path_url = urljoin(url, path)
                        log(f'FUZZ (blocked): {full_path_url} [{status}]', 'INFO')
            
            if accessible_count > 20:
                log(f'... and {accessible_count - 20} more accessible paths', 'INFO')
        else:
            log('No paths discovered via recursive fuzzing', 'INFO')
        
        # Nuclei vulnerability scanning with rate limiting (skip if requested)
        if not skip_nuclei:
            log(f'Running Nuclei on {url}', 'INFO')
            
            # Get rate limiting settings from config
            nuclei_rate_limit = CONFIG.get('rate_limiting', {}).get('nuclei_rate_limit', 150)
            nuclei_concurrency = CONFIG.get('rate_limiting', {}).get('nuclei_concurrency', 25)
            
            result = subprocess.run([
                'nuclei',
                '-u', url,
                '-silent',
                '-nc',  # No color
                '-severity', 'critical,high,medium',
                '-rate-limit', str(nuclei_rate_limit),  # Requests per minute
                '-c', str(nuclei_concurrency)  # Concurrent templates
            ], capture_output=True, text=True, timeout=180)
            
            if result.stdout.strip():
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        # Parse Nuclei output for severity
                        severity = 'medium'
                        if 'critical' in line.lower():
                            severity = 'critical'
                        elif 'high' in line.lower():
                            severity = 'high'
                        
                        vulns.append({
                            'type': 'nuclei',
                            'description': line.strip(),
                            'severity': severity,
                            'url': url
                        })
                        log(f'NUCLEI: {line.strip()}', 'VULN')
        else:
            log(f'Skipping Nuclei scan on {url}', 'INFO')
                    
    except subprocess.TimeoutExpired:
        log('Nuclei timeout', 'WARN')
    except FileNotFoundError:
        log('Nuclei not installed', 'WARN')
    except Exception as e:
        log(f'Scanner error: {e}', 'WARN')
    
    return vulns

def probe_live_domains(domains):
    """Test which domains are live and accessible via HTTP/HTTPS."""
    live_domains = []
    timeout = CONFIG.get('rate_limiting', {}).get('http_timeout', 10)
    
    # Create client with custom headers from config
    headers = CUSTOM_HEADERS.copy() if CUSTOM_HEADERS else {}
    
    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
        for domain in sorted(domains):
            for proto in ['https', 'http']:
                try:
                    url = f'{proto}://{domain}'
                    resp = client.get(url)
                    
                    if 200 <= resp.status_code < 500:
                        live_domains.append((url, True, resp.status_code))
                        print(f'✅ {url} ({resp.status_code})')
                        break
                        
                except Exception as e:
                    log(f'{url} unreachable: {str(e)[:50]}', 'DEBUG')
    
    return live_domains

# ============================================================================
# REPORTING
# ============================================================================

def print_vulnerability_report(scan_results):
    """Print the final vulnerability report to console."""
    print('\n🚨 VULNERABILITIES:')
    has_vulns = False
    for url, vulns in scan_results:
        if vulns:
            has_vulns = True
            for vuln in vulns:
                desc = vuln.get('description', str(vuln))
                sources = vuln.get('sources', [])
                if sources:
                    print(f'{url}: {desc} [Detected by: {", ".join(sources)}]')
                else:
                    print(f'{url}: {desc}')
    
    if not has_vulns:
        print('No vulnerabilities detected.')

def print_scan_summary(domains, target):
    """Print a summary of domains to be scanned."""
    print('\n' + '=' * 60)
    print(f'📊 SUMMARY: {len(domains)} total target(s) to scan')
    print('=' * 60)
    for domain in domains:
        print(f'  • {domain}')
    print('=' * 60 + '\n')

def save_report(scan_results, target, output_file=None, format='json'):
    """Save vulnerability report to file in specified format.
    
    Args:
        scan_results: List of (url, vulnerabilities) tuples
        target: Target domain name
        output_file: Custom output file path (optional)
        format: Output format (json, html, markdown, csv)
    
    Returns:
        str: Path to saved report file
    """
    # Create reports directory relative to script location
    script_dir = Path(__file__).parent
    reports_dir = script_dir / 'reports'
    reports_dir.mkdir(exist_ok=True)
    
    # Generate default filename if not provided
    if output_file is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = target.replace('://', '_').replace('/', '_').replace('.', '_')
        output_file = reports_dir / f'report_{safe_target}_{timestamp}.{format}'
    else:
        output_file = Path(output_file)
    
    try:
        # Prepare report data
        report_data = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'total_targets': len(scan_results),
            'total_vulnerabilities': sum(len(vulns) for _, vulns in scan_results),
            'results': []
        }
        
        for url, vulns in scan_results:
            report_data['results'].append({
                'url': url,
                'vulnerability_count': len(vulns),
                'vulnerabilities': vulns
            })
        
        # Save in requested format
        if format == 'json':
            save_json_report(report_data, output_file)
        elif format == 'html':
            save_html_report(report_data, output_file)
        elif format == 'markdown':
            save_markdown_report(report_data, output_file)
        elif format == 'csv':
            save_csv_report(report_data, output_file)
        
        return str(output_file)
        
    except Exception as e:
        log(f'Error saving report: {e}', 'ERROR')
        return None

def save_json_report(report_data, output_file):
    """Save report in JSON format."""
    with open(output_file, 'w') as f:
        json.dump(report_data, f, indent=2)

def save_html_report(report_data, output_file):
    """Save report in HTML format with styling."""
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {report_data['target']}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; color: #667eea; }}
        .target-section {{
            background: white;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .target-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 2px solid #e9ecef;
        }}
        .target-header h2 {{ margin: 0; color: #495057; }}
        .vuln-item {{
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
        }}
        .vuln-item:last-child {{ border-bottom: none; }}
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 10px;
        }}
        .severity.critical {{ background: #dc3545; color: white; }}
        .severity.high {{ background: #fd7e14; color: white; }}
        .severity.medium {{ background: #ffc107; color: black; }}
        .severity.low {{ background: #28a745; color: white; }}
        .severity.info {{ background: #17a2b8; color: white; }}
        .sources {{
            display: inline-block;
            font-size: 11px;
            color: #666;
            margin-left: 10px;
        }}
        .no-vulns {{
            background: white;
            padding: 40px;
            text-align: center;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Scan Report</h1>
        <p><strong>Target:</strong> {report_data['target']}</p>
        <p><strong>Scan Date:</strong> {report_data['scan_date']}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Targets</h3>
            <div class="value">{report_data['total_targets']}</div>
        </div>
        <div class="summary-card">
            <h3>Vulnerabilities Found</h3>
            <div class="value">{report_data['total_vulnerabilities']}</div>
        </div>
    </div>
'''
    
    if report_data['total_vulnerabilities'] == 0:
        html += '    <div class="no-vulns">🎉 No vulnerabilities detected!</div>\n'
    else:
        for result in report_data['results']:
            if result['vulnerabilities']:
                html += f'''    <div class="target-section">
        <div class="target-header">
            <h2>{result['url']}</h2>
            <p>{result['vulnerability_count']} vulnerability(ies) found</p>
        </div>
'''
                for vuln in result['vulnerabilities']:
                    severity = vuln.get('severity', 'low')
                    desc = vuln.get('description', 'No description')
                    vuln_type = vuln.get('type', 'unknown')
                    sources = vuln.get('sources', [])
                    sources_html = f'<span class="sources">Detected by: {", ".join(sources)}</span>' if sources else ''
                    html += f'''        <div class="vuln-item">
            <span class="severity {severity}">{severity}</span>
            <strong>{vuln_type.replace('_', ' ').title()}:</strong> {desc}
            {sources_html}
        </div>
'''
                html += '    </div>\n'
    
    html += '''</body>
</html>'''
    
    with open(output_file, 'w') as f:
        f.write(html)

def save_markdown_report(report_data, output_file):
    """Save report in Markdown format."""
    md = f'''# Security Scan Report

**Target:** {report_data['target']}  
**Scan Date:** {report_data['scan_date']}  
**Total Targets:** {report_data['total_targets']}  
**Total Vulnerabilities:** {report_data['total_vulnerabilities']}

---

'''
    
    if report_data['total_vulnerabilities'] == 0:
        md += '## 🎉 No Vulnerabilities Detected\n\n'
    else:
        for result in report_data['results']:
            if result['vulnerabilities']:
                md += f"## {result['url']}\n\n"
                md += f"**{result['vulnerability_count']} vulnerability(ies) found**\n\n"
                
                for vuln in result['vulnerabilities']:
                    severity = vuln.get('severity', 'low').upper()
                    desc = vuln.get('description', 'No description')
                    vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
                    sources = vuln.get('sources', [])
                    sources_text = f" (Detected by: {', '.join(sources)})" if sources else ''
                    md += f"- **[{severity}]** {vuln_type}: {desc}{sources_text}\n"
                
                md += '\n'
    
    with open(output_file, 'w') as f:
        f.write(md)

def save_csv_report(report_data, output_file):
    """Save report in CSV format."""
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Target', 'URL', 'Vulnerability Type', 'Description', 'Severity', 'Status Code', 'Sources'])
        
        for result in report_data['results']:
            for vuln in result['vulnerabilities']:
                sources = ', '.join(vuln.get('sources', []))
                writer.writerow([
                    report_data['target'],
                    result['url'],
                    vuln.get('type', 'unknown'),
                    vuln.get('description', ''),
                    vuln.get('severity', 'low'),
                    vuln.get('status_code', ''),
                    sources
                ])

# ============================================================================
# BOOTSTRAP
# ============================================================================

if __name__ == '__main__':
    # This must remain at the bottom to ensure all functions are defined
    main()
