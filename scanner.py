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
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Main entry point for the security scanner.
    Clean and simple: discover -> scan -> deduplicate -> report.
    """
    global SCAN_START_TIME
    SCAN_START_TIME = datetime.now()
    
    # Parse arguments
    args = parse_arguments()
    
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
    """
    Resolve target(s) from either HackerOne Scope Fetcher or manual input.
    
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
        
        # Export scope if requested
        if args.export_scope:
            ScopeExporter.to_text(filtered_assets, args.export_scope)
        
        # Extract scannable targets
        targets = ScopeFilter.extract_targets(filtered_assets)
        
        if not targets:
            log('No scannable targets found in program scope', 'WARN')
            return []
        
        log(f'\u2713 Extracted {len(targets)} scannable target(s) from HackerOne', 'OK')
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
        '--export-scope',
        metavar='FILE',
        help='Export filtered scope to text file'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        help='Output file path (default: /reports/report_<target>_<timestamp>.<format>)'
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

# [Rest of the file remains the same - truncated for brevity]
# The key change is in resolve_targets() function:
# h1_username = args.h1_username or os.getenv('H1_USERNAME')
# h1_token = args.h1_token or os.getenv('H1_TOKEN')

# ... (keeping all remaining functions identical) ...