#!/usr/bin/env python3
import subprocess
import sys
import argparse
import httpx
import yaml
import json
import csv
import os
import html as html_escape
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Avoid Windows console UnicodeEncodeError crashes (cp1252, etc.).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

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
            },
            'xss': {
                'mode': 'basic',
                'timeout': 10,
                'callback_url': None
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

    # HAR inventory mode: build endpoint/parameter inventory and exit (no scanning).
    if getattr(args, 'har', None):
        run_har_inventory(args)
        return
    
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
    
    # Log XSS scanning configuration if enabled
    if getattr(args, 'xss_enabled', False):
        xss_mode = args.xss_mode or CONFIG.get('xss', {}).get('mode', 'advanced')
        safe_label = 'safe' if getattr(args, 'safe_mode', True) else 'unsafe'
        standard_label = 'standard' if getattr(args, 'xss_standard_enabled', False) else 'no-standard'
        breakout_label = 'breakout' if getattr(args, 'xss_breakout_enabled', False) else 'no-breakout'
        log(f'?? XSS scanning enabled ({standard_label} + {breakout_label}) (mode: {xss_mode}, {safe_label})', 'INFO')
        if args.xss_payloads:
            log(f'?? Using custom XSS payloads from: {args.xss_payloads}', 'INFO')
        if args.xss_callback:
            log(f'?? Blind XSS callback URL: {args.xss_callback}', 'INFO')
        if getattr(args, 'xss_returnpath', False):
            log('?? ReturnPath DOM XSS workflow enabled', 'INFO')
        if getattr(args, 'xss_dom_audit', False):
            log('?? Static DOM XSS audit enabled', 'INFO')

    # Run with or without keep-awake based on flag
    if args.keep_awake:
        log('Keep-awake mode enabled - system will not sleep during scan', 'INFO')
        from keep_awake import keep_awake_context
        with keep_awake_context():
            run_scan(args)
    else:
        run_scan(args)


def run_har_inventory(args) -> None:
    from scanners.har_inventory import build_inventory_from_har, write_inventory_outputs
    import urllib.parse

    scopes = list(getattr(args, 'har_allow_host', []) or [])
    if getattr(args, 'target', None):
        t = str(args.target)
        if t.startswith(("http://", "https://")):
            scopes.append(urllib.parse.urlparse(t).netloc)
        else:
            scopes.append(t)

    redact = not bool(getattr(args, 'har_no_redact', False))
    items = build_inventory_from_har(
        har_path=args.har,
        scopes=scopes,
        include_headers=bool(getattr(args, 'har_include_headers', False)),
        redact=redact,
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    text_out = getattr(args, 'har_out', None) or str(Path("reports") / f"har_inventory_{ts}.txt")
    json_out = getattr(args, 'har_json_out', None)
    text_path, json_path = write_inventory_outputs(items, text_out=text_out, json_out=json_out)

    log(f"HAR inventory entries: {len(items)}", "OK" if items else "WARN")
    if text_path:
        log(f"Inventory text saved to: {text_path}", "INFO")
    if json_path:
        log(f"Inventory JSON saved to: {json_path}", "INFO")

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
        description='Security Scanner with Enhanced Breakout XSS Detection, HackerOne Integration, ZAP, and Nuclei',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Manual target scan
  %(prog)s example.com --zap
  
  # Basic XSS scan
  %(prog)s example.com
  
  # Enhanced Breakout XSS scan with context detection
  %(prog)s example.com --xss-deep
  
  # XSS exploitation mode with callback URL for blind XSS
  %(prog)s example.com --xss-deep --xss-mode exploitation --xss-callback https://webhook.site/your-id
  
  # Custom XSS payloads
  %(prog)s example.com --xss-deep --xss-payloads /path/to/payloads.txt
  
  # HackerOne program scan (public program)
  %(prog)s --fetch-scope --h1-program github --xss-deep
  
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
    
    # XSS Scanning Options (Enhanced Breakout Detection)
    xss_group = parser.add_argument_group('Enhanced Breakout XSS Scanning')
    xss_group.add_argument(
        '--xss-deep',
        action='store_true',
        help='Enable enhanced breakout XSS detection with template literals, JSON contexts, and multi-layer encoding analysis'
    )
    xss_group.add_argument(
        '--xss-returnpath',
        action='store_true',
        help='Run specialized DOM XSS check for returnPath reflected into href (PortSwigger lab workflow)'
    )
    xss_group.add_argument(
        '--xss-returnpath-feedback-path',
        help='Feedback page path for returnPath DOM XSS check (default: auto-discover or /feedback)'
    )
    xss_group.add_argument(
        '--no-xss',
        action='store_true',
        help='Disable all XSS scanning'
    )
    xss_group.add_argument(
        '--no-xss-standard',
        action='store_true',
        help='Disable standard (reflected) XSS scanning'
    )
    xss_group.add_argument(
        '--no-xss-breakout',
        action='store_true',
        help='Disable breakout XSS scanning'
    )
    xss_group.add_argument(
        '--no-xss-stored',
        action='store_true',
        help='Disable stored XSS form workflow scanning'
    )
    xss_group.add_argument(
        '--xss-mode',
        choices=['basic', 'advanced', 'exploitation'],
        help='XSS scanning mode: basic (fast), advanced (comprehensive breakout detection), exploitation (blind XSS with callbacks)'
    )
    xss_group.add_argument(
        '--xss-payloads',
        metavar='FILE',
        help='Path to custom XSS payload file (one payload per line)'
    )
    xss_group.add_argument(
        '--xss-callback',
        metavar='URL',
        help='Callback URL for blind XSS detection (e.g., Burp Collaborator, webhook.site)'
    )
    xss_group.add_argument(
        '--safe',
        action='store_true',
        help='Enable safe mode for XSS scanning (bounded payloads, no bypasses)'
    )
    xss_group.add_argument(
        '--unsafe',
        action='store_true',
        help='Disable safe mode for XSS scanning (more aggressive payloads)'
    )
    xss_group.add_argument(
        '--arjun-threads',
        type=int,
        help='Arjun threads for parameter discovery'
    )
    xss_group.add_argument(
        '--arjun-timeout',
        type=int,
        help='Arjun timeout in seconds for parameter discovery'
    )
    xss_group.add_argument(
        '--arjun-wordlist',
        metavar='FILE',
        help='Custom wordlist for Arjun parameter discovery'
    )
    xss_group.add_argument(
        '--crawl',
        action='store_true',
        help='Enable in-scope crawling for parameter discovery'
    )
    xss_group.add_argument(
        '--no-crawl',
        action='store_true',
        help='Disable in-scope crawling for parameter discovery'
    )
    xss_group.add_argument(
        '--crawl-pages',
        type=int,
        help='Maximum pages to crawl for parameter discovery'
    )
    xss_group.add_argument(
        '--crawl-depth',
        type=int,
        help='Maximum crawl depth for parameter discovery'
    )
    xss_group.add_argument(
        '--browser-verify',
        action='store_true',
        help='Verify DOM XSS execution using a headless browser (Playwright/Chromium). Slower but higher confidence.'
    )
    xss_group.add_argument(
        '--xss-dom-audit',
        action='store_true',
        help='Run static DOM audit for common DOM XSS source/sink flows (e.g. location.hash -> innerHTML)'
    )

    # Traffic import options (inventory only, no scanning)
    traffic_group = parser.add_argument_group('Traffic Import (Inventory)')
    traffic_group.add_argument(
        '--har',
        help='Path to a browser-exported HAR file. When set, the tool will build an endpoint/parameter inventory and exit.'
    )
    traffic_group.add_argument(
        '--har-out',
        help='Write inventory text output to this path (default: ./reports/har_inventory_<timestamp>.txt)'
    )
    traffic_group.add_argument(
        '--har-json-out',
        help='Write inventory JSON output to this path (optional)'
    )
    traffic_group.add_argument(
        '--har-allow-host',
        action='append',
        default=[],
        help='Additional host/domain to treat as in-scope for HAR filtering (repeatable)'
    )
    traffic_group.add_argument(
        '--har-include-headers',
        action='store_true',
        help='Include request header names in the inventory (values are never written)'
    )
    traffic_group.add_argument(
        '--har-no-redact',
        action='store_true',
        help='Do not redact query parameter values in sample URLs'
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
        default='html',
        help='Report format (default: html)'
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
    scanner_group.add_argument(
        '--xss-only',
        action='store_true',
        help='Run only XSS scanning (skip admin/backup/bucket/dir fuzzing and other scanners)'
    )
    scanner_group.add_argument(
        '--path-scan-depth',
        type=int,
        default=0,
        help='Recursively scan discovered internal paths (from links + fuzzing) up to this depth (default: 0 = disabled)'
    )
    scanner_group.add_argument(
        '--path-scan-max-urls',
        type=int,
        default=40,
        help='Maximum number of URLs to scan per root target when --path-scan-depth is enabled (default: 40)'
    )
    
    args = parser.parse_args()
    
    # Validation: require either target or --fetch-scope, unless running in HAR inventory mode.
    if not args.har and not args.fetch_scope and not args.target:
        parser.error('Either provide a target domain/URL, use --fetch-scope with --h1-program, or use --har')
    
    if args.fetch_scope and not args.h1_program:
        parser.error('--fetch-scope requires --h1-program')

    if args.har:
        # In HAR mode, require an explicit scope: either a target or at least one allow-host.
        if not args.target and not getattr(args, 'har_allow_host', []):
            parser.error('--har requires either a positional target (domain/URL) or one or more --har-allow-host values')
    
    # Validate XSS exploitation mode requires callback URL
    if args.xss_mode == 'exploitation' and not args.xss_callback:
        parser.error('--xss-mode exploitation requires --xss-callback URL')

    if args.safe and args.unsafe:
        parser.error('Choose either --safe or --unsafe, not both')
    if args.crawl and args.no_crawl:
        parser.error('Choose either --crawl or --no-crawl, not both')

    # Resolve XSS safety and Arjun defaults from config
    xss_config = CONFIG.get('xss', {})
    safe_default = xss_config.get('safe_mode', True)
    if args.safe:
        args.safe_mode = True
    elif args.unsafe:
        args.safe_mode = False
    else:
        args.safe_mode = safe_default

    # Resolve XSS enabled flags
    standard_default = xss_config.get('standard_enabled', True)
    breakout_default = xss_config.get('breakout_enabled', True)
    stored_default = xss_config.get('stored_enabled', True)
    if args.no_xss:
        args.xss_standard_enabled = False
        args.xss_breakout_enabled = False
        args.xss_stored_enabled = False
        args.xss_returnpath = False
    else:
        args.xss_standard_enabled = standard_default and not args.no_xss_standard
        args.xss_breakout_enabled = breakout_default and not args.no_xss_breakout
        args.xss_stored_enabled = stored_default and not args.no_xss_stored
        if args.xss_deep:
            args.xss_breakout_enabled = True
    
    args.xss_enabled = (
        args.xss_standard_enabled
        or args.xss_breakout_enabled
        or args.xss_stored_enabled
        or getattr(args, 'xss_returnpath', False)
    )

    args.arjun_threads = args.arjun_threads or xss_config.get('arjun_threads', 10)
    args.arjun_timeout = args.arjun_timeout or xss_config.get('arjun_timeout', 120)
    args.arjun_wordlist = args.arjun_wordlist or xss_config.get('arjun_wordlist') or None
    args.xss_fallback_params = xss_config.get('fallback_params', ['q', 'search', 'query', 'keyword', 'term', 'id', 'page', 'url', 'redirect', 'name'])
    crawl_default = xss_config.get('crawl_enabled', True)
    if args.crawl:
        args.xss_crawl_enabled = True
    elif args.no_crawl:
        args.xss_crawl_enabled = False
    else:
        args.xss_crawl_enabled = crawl_default
    args.xss_crawl_max_pages = args.crawl_pages or xss_config.get('crawl_max_pages', 25)
    args.xss_crawl_max_depth = args.crawl_depth or xss_config.get('crawl_max_depth', 2)
    
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

    # If a full URL is provided, skip subdomain discovery
    try:
        import urllib.parse
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme and parsed.netloc:
            log(f'URL target detected, skipping subdomain discovery: {target}', 'INFO')
            subdomains = [target]
            ALL_SUBDOMAINS = subdomains
            print_scan_summary(subdomains, target)
            return subdomains
    except Exception:
        pass
    
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
    # Probe for live domains unless we're doing an XSS-only debug run.
    # In XSS-only mode, we want deterministic execution and logs even if probing is flaky.
    if getattr(args, 'xss_only', False):
        live_domains = []
        for t in subdomains:
            live_domains.append((t, True, None))
    else:
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
        traditional_results = run_traditional_scans(live_domains, args, skip_nuclei=args.skip_nuclei)
        
        # Merge with ZAP results
        for url, vulns in traditional_results:
            if url in all_results:
                all_results[url].extend(vulns)
            else:
                all_results[url] = vulns
    
    # Convert dict to list of tuples for reporting
    scan_results = [(url, vulns) for url, vulns in all_results.items()]
    
    return scan_results

def _normalize_url_for_recursion(url: str) -> str:
    """Canonicalize URL for visited-set comparisons (drop query/fragment)."""
    try:
        import urllib.parse
        p = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse((p.scheme, p.netloc, p.path or '/', '', '', ''))
    except Exception:
        return url

def _should_recurse_url(root_url: str, candidate_url: str) -> bool:
    """Limit recursion to same-origin, non-static, likely-interesting paths."""
    try:
        import urllib.parse
        root = urllib.parse.urlparse(root_url)
        c = urllib.parse.urlparse(candidate_url)
    except Exception:
        return False

    if c.scheme not in ('http', 'https'):
        return False
    if c.netloc != root.netloc:
        return False

    path = c.path or '/'
    if not path.startswith('/'):
        path = '/' + path

    # Skip obvious static asset files.
    last = path.rsplit('/', 1)[-1]
    if '.' in last:
        ext = last.rsplit('.', 1)[-1].lower()
        allowed_dynamic = {'php', 'asp', 'aspx', 'jsp', 'html', 'htm'}
        if ext not in allowed_dynamic:
            return False

    # Skip very common static directories to keep recursion focused.
    seg = path.strip('/').split('/', 1)[0].lower() if path.strip('/') else ''
    skip_dirs = {'resources', 'static', 'assets', 'images', 'img', 'css', 'js', 'fonts', 'image', 'media'}
    if seg in skip_dirs:
        return False

    return True

def _extract_discovered_endpoints_from_vulns(vulns):
    """Pull URLs we discovered during scanning that are worth scanning next."""
    endpoints = []
    for v in vulns or []:
        ep = v.get('endpoint')
        if not ep:
            continue
        endpoints.append(ep)
    return endpoints

def scan_with_path_recursion(root_url: str, args, skip_nuclei: bool = False):
    """
    Scan a root URL, then recursively scan discovered internal paths up to args.path_scan_depth.
    Returns a list of (url, vulns) entries suitable for report generation.
    """
    from collections import deque
    import urllib.parse

    max_depth = max(0, int(getattr(args, 'path_scan_depth', 0) or 0))
    max_urls = max(1, int(getattr(args, 'path_scan_max_urls', 40) or 40))

    visited = set()
    results = []
    q = deque([(root_url, 0)])

    while q and len(visited) < max_urls:
        url, depth = q.popleft()
        norm = _normalize_url_for_recursion(url)
        if norm in visited:
            continue
        visited.add(norm)

        vulns = scan_single_domain_for_vulnerabilities(url, args, skip_nuclei=skip_nuclei)
        results.append((url, vulns))

        if depth >= max_depth:
            continue

        for child in _extract_discovered_endpoints_from_vulns(vulns):
            # Drop query/fragment for recursion to avoid blowing up the URL space.
            child_norm = _normalize_url_for_recursion(child)
            if child_norm in visited:
                continue
            if not _should_recurse_url(root_url, child_norm):
                continue
            # Use the normalized URL to keep recursion stable.
            q.append((child_norm, depth + 1))

    if q and len(visited) >= max_urls:
        log(f'Path recursion hit max URL limit ({max_urls}); {len(q)} remaining in queue not scanned', 'WARN')

    return results

def run_traditional_scans(live_domains, args, skip_nuclei=False):
    """Run traditional vulnerability scanners on live domains."""
    scan_results = []
    for url, is_live, status_code in live_domains:
        if is_live:
            if getattr(args, 'path_scan_depth', 0) and not getattr(args, 'xss_only', False):
                scan_results.extend(scan_with_path_recursion(url, args, skip_nuclei=skip_nuclei))
            else:
                vulns = scan_single_domain_for_vulnerabilities(url, args, skip_nuclei=skip_nuclei)
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
    try:
        print(f'[{level}] {msg}', flush=True)
    except UnicodeEncodeError:
        # Some Windows consoles default to cp1252 and cannot print emoji or other Unicode.
        safe = f'[{level}] {msg}'.encode('ascii', errors='backslashreplace').decode('ascii', errors='ignore')
        print(safe, flush=True)

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

def scan_single_domain_for_vulnerabilities(url, args, skip_nuclei=False):
    """Perform comprehensive vulnerability scanning on a single URL."""
    vulns = []
    
    try:
        # Import scanners from scanners package
        from scanners.admin_scanner import check_admin
        from scanners.backup_scanner import check_backup
        from scanners.directory_scanner import check_exposed_buckets, fuzz_directories, discover_paths_from_links

        def _run_xss_scans() -> None:
            # XSS scanning (standard reflected + breakout)
            if not getattr(args, 'xss_enabled', False):
                return

            xss_config = CONFIG.get('xss', {})
            xss_timeout = xss_config.get('timeout', 10)
            xss_callback = args.xss_callback or xss_config.get('callback_url')
            xss_mode = args.xss_mode or xss_config.get('mode', 'advanced')
            max_payloads = xss_config.get('max_payloads_per_param', 20)
            stored_enabled = xss_config.get('stored_enabled', True)

            if getattr(args, 'xss_standard_enabled', False):
                from scanners.xss_advanced import advanced_xss_scan
                log(f'?? Running standard XSS scan on {url}', 'INFO')
                standard_vulns = advanced_xss_scan(
                    url=url,
                    mode=xss_mode,
                    custom_payloads_file=args.xss_payloads,
                    callback_url=xss_callback,
                    timeout=xss_timeout,
                    enable_param_discovery=True,
                    safe_mode=getattr(args, 'safe_mode', True),
                    arjun_threads=getattr(args, 'arjun_threads', 10),
                    arjun_timeout=getattr(args, 'arjun_timeout', 120),
                    arjun_wordlist=getattr(args, 'arjun_wordlist', None),
                    fallback_params=getattr(args, 'xss_fallback_params', None),
                    max_payloads_per_param=max_payloads,
                    enable_stored_workflow=getattr(args, 'xss_stored_enabled', stored_enabled),
                    browser_verify=getattr(args, 'browser_verify', False)
                )
                if standard_vulns:
                    for v in standard_vulns:
                        v.setdefault('url', url)
                        v.setdefault('sources', []).append('XSS Scanner')
                        severity = v.get('severity', 'medium').upper()
                        desc = v.get('description', 'XSS vulnerability')
                        log(f'XSS [{severity}] on {url}: {desc}', 'VULN')
                    vulns.extend(standard_vulns)

            if getattr(args, 'xss_breakout_enabled', False):
                from scanners.xss_breakout_scanner_patch import scan_for_breakout_xss
                log(f'?? Running breakout XSS scan on {url}', 'INFO')
                breakout_vulns = scan_for_breakout_xss(
                    url=url,
                    args=args,
                    timeout=xss_timeout,
                    callback_url=xss_callback
                )
                if breakout_vulns:
                    for v in breakout_vulns:
                        v.setdefault('url', url)
                        v.setdefault('sources', []).append('XSS Scanner')
                    vulns.extend(breakout_vulns)

            if getattr(args, 'xss_dom_audit', False):
                try:
                    from scanners.dom_xss_hash_detector import scan_dom_xss_hash
                    log(f'?? Running static DOM audit on {url}', 'INFO')
                    dom_vulns = scan_dom_xss_hash(
                        base_url=url,
                        timeout_s=xss_timeout,
                        headers=CUSTOM_HEADERS.copy() if CUSTOM_HEADERS else None,
                    )
                    if dom_vulns:
                        for v in dom_vulns:
                            v.setdefault('url', url)
                            v.setdefault('sources', []).append('XSS Scanner')
                        vulns.extend(dom_vulns)
                        log(f'Static DOM audit produced {len(dom_vulns)} potential finding(s)', 'VULN')
                except Exception as e:
                    log(f'Static DOM audit error: {str(e)[:120]}', 'WARN')

            if getattr(args, 'xss_returnpath', False):
                try:
                    from scanners.dom_xss_returnpath import check_returnpath_dom_xss
                    log(f'?? Running returnPath DOM XSS workflow on {url}', 'INFO')
                    returnpath_vuln = check_returnpath_dom_xss(
                        base_url=url,
                        feedback_path=getattr(args, 'xss_returnpath_feedback_path', None),
                        timeout_s=xss_timeout,
                        headed=False,
                        slow_mo_ms=0,
                    )
                    if returnpath_vuln:
                        returnpath_vuln.setdefault('url', url)
                        returnpath_vuln.setdefault('sources', []).append('XSS Scanner')
                        vulns.append(returnpath_vuln)
                        log('DOM XSS returnPath workflow confirmed', 'VULN')
                except Exception as e:
                    log(f'ReturnPath DOM XSS workflow error: {str(e)[:120]}', 'WARN')

        # XSS-only mode: skip the long-running non-XSS scanners so runs complete quickly.
        if getattr(args, 'xss_only', False):
            _run_xss_scans()
            return vulns
        
        # Admin panel detection
        if check_admin(url):
            vulns.append({'type': 'admin_panel', 'description': 'Admin panel exposed', 'severity': 'medium', 'url': url})
            log(f'ADMIN on {url}', 'VULN')
        
        # Backup file detection
        if check_backup(url):
            vulns.append({'type': 'backup_file', 'description': 'Backup file found', 'severity': 'high', 'url': url})
            log(f'BACKUP on {url}', 'VULN')
        
        _run_xss_scans()

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
                        'endpoint': full_url,
                        'status_code': status,
                        'severity': 'high',
                        'url': url
                    })
                    log(f'BUCKET EXPOSED: {full_url} [{status}] - {vuln_type}', 'VULN')
                elif vuln_type == 'ACCESSIBLE':
                    vulns.append({
                        'type': 'accessible_path',
                        'description': f'Accessible path: {full_url}',
                        'endpoint': full_url,
                        'status_code': status,
                        'severity': 'medium',
                        'url': url
                    })
                    log(f'ACCESSIBLE PATH: {full_url} [{status}]', 'VULN')
                elif vuln_type == 'FORBIDDEN_BUT_EXISTS':
                    # Log it but DON'T add to vulnerabilities list
                    log(f'PATH EXISTS (forbidden): {full_url} [{status}]', 'INFO')
        
        # Recursive directory fuzzing (scanner module handles its own logging)
        # Also try quick link-based discovery so we can pick up obvious endpoints like "/feedback"
        # even when wordlist fuzzing times out or is blocked.
        try:
            link_discovered = discover_paths_from_links(
                url,
                timeout=CONFIG.get('rate_limiting', {}).get('http_timeout', 10),
                headers=CUSTOM_HEADERS.copy() if CUSTOM_HEADERS else None,
            )
        except Exception:
            link_discovered = []

        if link_discovered:
            log(f'Discovered {len(link_discovered)} path(s) from on-page links/forms', 'OK')
            shown = 0
            for path, status in link_discovered:
                if status.startswith('2') or status.startswith('3'):
                    from urllib.parse import urljoin
                    full_path_url = urljoin(url, path)
                    vulns.append({
                        'type': 'discovered_path',
                        'description': f'Discovered path (link-based): {full_path_url}',
                        'endpoint': full_path_url,
                        'status_code': int(status),
                        'severity': 'low',
                        'url': url
                    })
                    shown += 1
                    if shown <= 10:
                        log(f'LINK: {full_path_url} [{status}]', 'VULN')

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
                        'endpoint': full_path_url,
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
            # If already a full URL, probe it directly
            if domain.startswith('http://') or domain.startswith('https://'):
                try:
                    resp = client.get(domain)
                    # Treat any HTTP response as "live" (even 5xx) so scans can still run on flaky targets.
                    live_domains.append((domain, True, resp.status_code))
                    if 200 <= resp.status_code < 500:
                        print(f'✅ {domain} ({resp.status_code})')
                    else:
                        print(f'⚠️  {domain} ({resp.status_code})')
                except Exception as e:
                    log(f'{domain} unreachable: {str(e)[:50]}', 'DEBUG')
                    live_domains.append((domain, False, None))
                continue

            found = False
            last_err = None
            for proto in ['https', 'http']:
                url = f'{proto}://{domain}'
                try:
                    resp = client.get(url)
                    live_domains.append((url, True, resp.status_code))
                    if 200 <= resp.status_code < 500:
                        print(f'✅ {url} ({resp.status_code})')
                    else:
                        print(f'⚠️  {url} ({resp.status_code})')
                    found = True
                    break
                except Exception as e:
                    last_err = e
                    log(f'{url} unreachable: {str(e)[:50]}', 'DEBUG')

            if not found:
                if last_err is not None:
                    log(f'{domain} unreachable: {str(last_err)[:50]}', 'DEBUG')
                live_domains.append((domain, False, None))
    
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
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2)

def save_html_report(report_data, output_file):
    """Save report in HTML format with detailed XSS exploitation steps."""
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {html_escape.escape(report_data['target'])}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1400px;
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
            padding: 20px;
            border-bottom: 1px solid #e9ecef;
        }}
        .vuln-item:last-child {{ border-bottom: none; }}
        .vuln-header {{
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }}
        .severity {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 12px;
        }}
        .severity.critical {{ background: #dc3545; color: white; }}
        .severity.high {{ background: #fd7e14; color: white; }}
        .severity.medium {{ background: #ffc107; color: black; }}
        .severity.low {{ background: #28a745; color: white; }}
        .severity.info {{ background: #17a2b8; color: white; }}
        .vuln-type {{
            font-weight: 600;
            color: #495057;
            font-size: 16px;
        }}
        .detail-section {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        .detail-section h4 {{
            margin: 0 0 10px 0;
            color: #667eea;
            font-size: 14px;
        }}
        .code-block {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 12px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            margin: 8px 0;
        }}
        .steps-list {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .steps-list li {{
            margin: 8px 0;
            color: #495057;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            background: #e9ecef;
            border-radius: 3px;
            font-size: 12px;
            color: #495057;
            margin: 5px 5px 5px 0;
        }}
        .score-badge {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        .no-vulns {{
            background: white;
            padding: 40px;
            text-align: center;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .description {{
            color: #495057;
            margin: 10px 0;
            font-size: 14px;
        }}
        .breakout-context {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 12px;
            margin: 10px 0;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Scan Report</h1>
        <p><strong>Target:</strong> {html_escape.escape(report_data['target'])}</p>
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
            <h2>{html_escape.escape(result['url'])}</h2>
            <p>{result['vulnerability_count']} vulnerability(ies) found</p>
        </div>
'''
                for vuln in result['vulnerabilities']:
                    severity = vuln.get('severity', 'low')
                    desc = html_escape.escape(vuln.get('description', 'No description'))
                    vuln_type = vuln.get('type', 'unknown').replace('_', ' ').title()
                    
                    html += f'''        <div class="vuln-item">
            <div class="vuln-header">
                <span class="severity {severity}">{severity.upper()}</span>
                <span class="vuln-type">{vuln_type}</span>
            </div>
            <div class="description">{desc}</div>
'''
                    
                    # Add breakout XSS-specific details
                    if vuln.get('type', '').lower() == 'breakout_xss':
                        # Context information
                        context_type = vuln.get('context_type')
                        context_desc = vuln.get('context_description')
                        if context_type or context_desc:
                            html += '            <div class="breakout-context">\n'
                            html += '                <h4 style="margin: 0 0 8px 0; color: #856404;">🎯 Breakout Context</h4>\n'
                            if context_type:
                                html += f'                <p style="margin: 5px 0;"><strong>Type:</strong> {html_escape.escape(context_type)}</p>\n'
                            if context_desc:
                                html += f'                <p style="margin: 5px 0;">{html_escape.escape(context_desc)}</p>\n'
                            html += '            </div>\n'
                        
                        # Context snippet
                        context_snippet = vuln.get('context_snippet')
                        if context_snippet:
                            html += '            <div class="detail-section">\n'
                            html += '                <h4>📝 Code Context</h4>\n'
                            html += f'                <div class="code-block">{html_escape.escape(context_snippet[:300])}</div>\n'
                            html += '            </div>\n'
                        
                        # Encoding layers
                        encoding_layers = vuln.get('encoding_layers', [])
                        if encoding_layers:
                            html += '            <div class="detail-section">\n'
                            html += '                <h4>🔒 Encoding Detected</h4>\n'
                            for layer in encoding_layers:
                                html += f'                <span class="badge">{html_escape.escape(layer)}</span>\n'
                            html += '            </div>\n'
                    
                    # Add XSS-specific details (for all XSS types)
                    if vuln.get('type', '').lower().endswith('xss'):
                        # Payload
                        payload = vuln.get('payload')
                        if payload:
                            html += f'''            <div class="detail-section">
                <h4>💥 Successful Payload</h4>
                <div class="code-block">{html_escape.escape(payload)}</div>
            </div>
'''
                        
                        # Target info
                        param = vuln.get('parameter')
                        method = vuln.get('method')
                        context = vuln.get('context')
                        if param or method or context:
                            html += '            <div class="detail-section">\n'
                            html += '                <h4>🎯 Target Information</h4>\n'
                            if param:
                                html += f'                <span class="badge"><strong>Parameter:</strong> {html_escape.escape(param)}</span>\n'
                            if method:
                                html += f'                <span class="badge"><strong>Method:</strong> {method}</span>\n'
                            if context:
                                html += f'                <span class="badge"><strong>Context:</strong> {context}</span>\n'
                            html += '            </div>\n'
                        
                        # CVSS Score
                        cvss_score = vuln.get('cvss_score')
                        severity_reasoning = vuln.get('severity_reasoning')
                        if cvss_score:
                            html += f'''            <div class="detail-section">
                <h4>📈 Severity Analysis</h4>
                <span class="badge score-badge">CVSS Score: {cvss_score}/10.0</span>
'''
                            if severity_reasoning:
                                html += f'                <p style="margin-top: 10px; font-size: 13px; color: #666;">{html_escape.escape(severity_reasoning)}</p>\n'
                            html += '            </div>\n'
                        
                        # Exploitation section
                        exploitation = vuln.get('exploitation', {})
                        if exploitation:
                            # Curl command
                            curl_cmd = exploitation.get('curl_command')
                            if curl_cmd:
                                html += f'''            <div class="detail-section">
                <h4>🔧 Reproduce with cURL</h4>
                <div class="code-block">{html_escape.escape(curl_cmd)}</div>
            </div>
'''
                            
                            # Browser steps
                            browser_steps = exploitation.get('browser_steps', [])
                            if browser_steps:
                                html += '            <div class="detail-section">\n'
                                html += '                <h4>🌐 Browser Reproduction Steps</h4>\n'
                                html += '                <ol class="steps-list">\n'
                                for step in browser_steps:
                                    html += f'                    <li>{html_escape.escape(step)}</li>\n'
                                html += '                </ol>\n'
                                html += '            </div>\n'
                        
                        # Remediation
                        remediation = vuln.get('remediation')
                        if remediation:
                            html += '            <div class="detail-section">\n'
                            html += '                <h4>🛡️ Remediation</h4>\n'
                            html += f'                <p style="font-size: 13px; color: #495057;">{html_escape.escape(remediation[:500])}</p>\n'
                            html += '            </div>\n'
                    
                    # Sources
                    sources = vuln.get('sources', [])
                    if sources:
                        html += '            <div style="margin-top: 15px; font-size: 12px; color: #666;">\n'
                        html += f'                🔍 Detected by: {html_escape.escape(", ".join(sources))}\n'
                        html += '            </div>\n'
                    
                    html += '        </div>\n'  # Close vuln-item
                html += '    </div>\n'  # Close target-section
    
    html += '''</body>
</html>'''
    
    with open(output_file, 'w', encoding='utf-8') as f:
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
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(md)

def save_csv_report(report_data, output_file):
    """Save report in CSV format."""
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
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
