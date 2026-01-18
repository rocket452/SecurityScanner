#!/usr/bin/env python3
"""
HackerOne Scope Fetcher

Retrieves bug bounty program scope from HackerOne's public and private APIs.
Supports filtering by bounty eligibility, severity, and asset type.

Author: SecurityScanner Team
License: MIT
"""

import requests
import json
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from enum import Enum
import re


class AssetType(Enum):
    """HackerOne asset types"""
    URL = "URL"
    DOMAIN = "DOMAIN"
    WILDCARD = "WILDCARD"
    IP_ADDRESS = "IP_ADDRESS"
    CIDR = "CIDR"
    GOOGLE_PLAY_APP_ID = "GOOGLE_PLAY_APP_ID"
    APPLE_STORE_APP_ID = "APPLE_STORE_APP_ID"
    WINDOWS_APP_STORE_APP_ID = "WINDOWS_APP_STORE_APP_ID"
    SOURCE_CODE = "SOURCE_CODE"
    DOWNLOADABLE_EXECUTABLES = "DOWNLOADABLE_EXECUTABLES"
    HARDWARE = "HARDWARE"
    OTHER = "OTHER"


class EligibilityFilter(Enum):
    """Scope filtering options"""
    ALL = "all"
    BOUNTY_ELIGIBLE = "bounty-eligible"
    IN_SCOPE_ONLY = "in-scope"
    OUT_OF_SCOPE = "out-of-scope"


@dataclass
class Asset:
    """Represents a HackerOne asset"""
    identifier: str
    asset_type: str
    eligible_for_bounty: bool
    eligible_for_submission: bool
    instruction: Optional[str] = None
    max_severity: Optional[str] = None
    
    def __repr__(self):
        bounty_flag = "[BOUNTY]" if self.eligible_for_bounty else "[NO BOUNTY]"
        return f"{bounty_flag} {self.asset_type}: {self.identifier}"


@dataclass
class Program:
    """Represents a HackerOne bug bounty program"""
    handle: str
    name: str
    assets: List[Asset]
    
    def __repr__(self):
        return f"Program({self.name}, {len(self.assets)} assets)"


class HackerOneAPIScopeFetcher:
    """
    Fetches scope from HackerOne using their REST API.
    Requires authentication for private programs.
    """
    
    BASE_URL = "https://api.hackerone.com/v1"
    
    def __init__(self, username: Optional[str] = None, api_token: Optional[str] = None):
        """
        Initialize HackerOne API client.
        
        Args:
            username: HackerOne username (for private programs)
            api_token: HackerOne API token (for private programs)
        """
        self.username = username
        self.api_token = api_token
        self.session = requests.Session()
        
        if username and api_token:
            self.session.auth = (username, api_token)
            self.session.headers.update({
                'Accept': 'application/json'
            })
    
    def get_program_by_handle(self, handle: str) -> Optional[Program]:
        """
        Fetch program details and scope by program handle.
        
        Args:
            handle: Program handle (e.g., 'github', 'gitlab')
            
        Returns:
            Program object with assets, or None if not found
        """
        try:
            # Try authenticated structured_scopes API if credentials provided
            if self.username and self.api_token:
                program = self._fetch_structured_scopes(handle)
                if program:
                    return program
            
            # Fall back to public directory
            program = self._fetch_from_directory(handle)
            if program:
                return program
            
            print(f"[!] Program '{handle}' not found")
            if not (self.username and self.api_token):
                print("[!] Provide API credentials to access private programs and structured scopes")
            return None
            
        except Exception as e:
            print(f"[!] Error fetching program '{handle}': {str(e)}")
            return None
    
    def _fetch_structured_scopes(self, handle: str) -> Optional[Program]:
        """
        Fetch structured scopes from authenticated HackerOne API.
        This is the preferred method when credentials are available.
        
        Endpoint: /v1/hackers/programs/{handle}/structured_scopes
        """
        url = f"{self.BASE_URL}/hackers/programs/{handle}/structured_scopes"
        
        try:
            print(f"[*] Fetching structured scopes from API with authentication...")
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 404:
                print(f"[!] Program '{handle}' not found or not accessible")
                return None
            
            if response.status_code == 401:
                print("[!] Authentication failed - check your API credentials")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            # Parse structured scopes response
            assets = []
            scopes_data = data.get('data', [])
            
            for scope in scopes_data:
                scope_attrs = scope.get('attributes', {})
                
                asset = Asset(
                    identifier=scope_attrs.get('asset_identifier', ''),
                    asset_type=scope_attrs.get('asset_type', 'OTHER'),
                    eligible_for_bounty=scope_attrs.get('eligible_for_bounty', False),
                    eligible_for_submission=scope_attrs.get('eligible_for_submission', True),
                    instruction=scope_attrs.get('instruction'),
                    max_severity=scope_attrs.get('max_severity')
                )
                assets.append(asset)
            
            print(f"[+] Successfully fetched {len(assets)} structured scopes")
            
            return Program(
                handle=handle,
                name=handle.title(),
                assets=assets
            )
            
        except requests.RequestException as e:
            print(f"[!] API request failed: {str(e)}")
            return None
    
    def _fetch_from_directory(self, handle: str) -> Optional[Program]:
        """
        Fetch from public HackerOne directory (no auth required).
        """
        url = f"https://hackerone.com/{handle}/policy_scopes.json"
        
        try:
            print(f"[*] Fetching from public directory...")
            response = requests.get(url, timeout=10)
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            data = response.json()
            
            assets = []
            for scope in data.get('scopes', []):
                asset = Asset(
                    identifier=scope.get('asset_identifier', ''),
                    asset_type=scope.get('asset_type', 'OTHER'),
                    eligible_for_bounty=scope.get('eligible_for_bounty', False),
                    eligible_for_submission=scope.get('eligible_for_submission', True),
                    instruction=scope.get('instruction'),
                    max_severity=scope.get('max_severity')
                )
                assets.append(asset)
            
            print(f"[+] Successfully fetched {len(assets)} scopes from public directory")
            
            return Program(
                handle=handle,
                name=handle.title(),
                assets=assets
            )
            
        except requests.RequestException as e:
            print(f"[!] Failed to fetch from directory: {str(e)}")
            return None


class ScopeFilter:
    """
    Filters and processes HackerOne scope assets.
    """
    
    @staticmethod
    def filter_by_eligibility(assets: List[Asset], filter_type: EligibilityFilter) -> List[Asset]:
        """
        Filter assets by bounty/submission eligibility.
        
        Args:
            assets: List of Asset objects
            filter_type: EligibilityFilter enum value
            
        Returns:
            Filtered list of assets
        """
        if filter_type == EligibilityFilter.ALL:
            return assets
        
        if filter_type == EligibilityFilter.BOUNTY_ELIGIBLE:
            return [a for a in assets if a.eligible_for_bounty]
        
        if filter_type == EligibilityFilter.IN_SCOPE_ONLY:
            return [a for a in assets if a.eligible_for_submission]
        
        if filter_type == EligibilityFilter.OUT_OF_SCOPE:
            return [a for a in assets if not a.eligible_for_submission]
        
        return assets
    
    @staticmethod
    def filter_by_type(assets: List[Asset], asset_types: List[str]) -> List[Asset]:
        """
        Filter assets by type (URL, DOMAIN, WILDCARD, etc.).
        
        Args:
            assets: List of Asset objects
            asset_types: List of asset type strings
            
        Returns:
            Filtered list of assets
        """
        if not asset_types:
            return assets
        
        return [a for a in assets if a.asset_type in asset_types]
    
    @staticmethod
    def extract_targets(assets: List[Asset]) -> List[str]:
        """
        Extract scannable targets from assets.
        Handles wildcards, URLs, domains, and IPs.
        
        Args:
            assets: List of Asset objects
            
        Returns:
            List of target strings suitable for scanning
        """
        targets: Set[str] = set()
        
        for asset in assets:
            identifier = asset.identifier.strip()
            
            if not identifier:
                continue
            
            # Handle different asset types
            if asset.asset_type in ['URL', 'DOMAIN', 'WILDCARD']:
                # Clean up the identifier
                target = ScopeFilter._clean_target(identifier)
                if target:
                    targets.add(target)
            
            elif asset.asset_type == 'IP_ADDRESS':
                targets.add(identifier)
            
            elif asset.asset_type == 'CIDR':
                # For CIDR ranges, add the base IP
                # Note: Full CIDR scanning requires additional tools
                base_ip = identifier.split('/')[0]
                targets.add(base_ip)
        
        return sorted(list(targets))
    
    @staticmethod
    def _clean_target(identifier: str) -> Optional[str]:
        """
        Clean and normalize target identifiers.
        
        Args:
            identifier: Raw identifier from HackerOne
            
        Returns:
            Cleaned target string or None
        """
        # Remove protocols
        identifier = re.sub(r'^https?://', '', identifier)
        
        # Remove trailing slashes and paths for wildcard domains
        identifier = identifier.split('/')[0]
        
        # Remove port numbers for domain enumeration
        identifier = identifier.split(':')[0]
        
        # Handle wildcards: *.example.com -> example.com
        # (Subdomain enumeration tools will find subdomains)
        if identifier.startswith('*.'):
            identifier = identifier[2:]
        
        return identifier if identifier else None
    
    @staticmethod
    def filter_in_scope(assets: List[Asset]) -> List[Asset]:
        """
        Convenience method to get all in-scope, bounty-eligible assets.
        
        Args:
            assets: List of Asset objects
            
        Returns:
            Filtered list of bounty-eligible, in-scope assets
        """
        return [
            a for a in assets 
            if a.eligible_for_bounty and a.eligible_for_submission
        ]


class ScopeExporter:
    """
    Exports scope to various formats.
    """
    
    @staticmethod
    def to_text(assets: List[Asset], filepath: str):
        """
        Export assets to plain text file.
        
        Args:
            assets: List of Asset objects
            filepath: Output file path
        """
        targets = ScopeFilter.extract_targets(assets)
        
        with open(filepath, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
        
        print(f"[+] Exported {len(targets)} targets to {filepath}")
    
    @staticmethod
    def to_json(program: Program, filepath: str):
        """
        Export full program scope to JSON.
        
        Args:
            program: Program object
            filepath: Output file path
        """
        data = {
            'program_handle': program.handle,
            'program_name': program.name,
            'total_assets': len(program.assets),
            'assets': [
                {
                    'identifier': a.identifier,
                    'type': a.asset_type,
                    'bounty_eligible': a.eligible_for_bounty,
                    'in_scope': a.eligible_for_submission,
                    'instruction': a.instruction,
                    'max_severity': a.max_severity
                }
                for a in program.assets
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Exported program scope to {filepath}")
    
    @staticmethod
    def print_summary(program: Program):
        """
        Print program scope summary to console.
        
        Args:
            program: Program object
        """
        print(f"\n{'='*60}")
        print(f"Program: {program.name} ({program.handle})")
        print(f"{'='*60}\n")
        
        bounty_eligible = [a for a in program.assets if a.eligible_for_bounty]
        in_scope = [a for a in program.assets if a.eligible_for_submission]
        
        print(f"Total Assets: {len(program.assets)}")
        print(f"Bounty Eligible: {len(bounty_eligible)}")
        print(f"In Scope: {len(in_scope)}")
        print(f"\nScope Details:\n")
        
        for asset in program.assets:
            status = ""
            if asset.eligible_for_bounty:
                status = "[BOUNTY]"
            elif asset.eligible_for_submission:
                status = "[IN-SCOPE]"
            else:
                status = "[OUT-OF-SCOPE]"
            
            print(f"  {status} {asset.asset_type:20} {asset.identifier}")
            if asset.instruction:
                print(f"         → {asset.instruction}")
        
        print(f"\n{'='*60}\n")


# CLI Interface (if run directly)
if __name__ == "__main__":
    import argparse
    import os
    from dotenv import load_dotenv
    
    # Load environment variables from .env file
    load_dotenv()
    
    parser = argparse.ArgumentParser(
        description="Fetch HackerOne bug bounty program scope"
    )
    parser.add_argument(
        'program',
        help='Program handle (e.g., github, gitlab, shopify)'
    )
    parser.add_argument(
        '--username',
        help='HackerOne username (or set H1_USERNAME in .env)'
    )
    parser.add_argument(
        '--token',
        help='HackerOne API token (or set H1_TOKEN in .env)'
    )
    parser.add_argument(
        '--filter',
        choices=['all', 'bounty-eligible', 'in-scope', 'out-of-scope'],
        default='bounty-eligible',
        help='Filter assets by eligibility (default: bounty-eligible)'
    )
    parser.add_argument(
        '--export',
        help='Export targets to text file'
    )
    parser.add_argument(
        '--export-json',
        help='Export full scope to JSON file'
    )
    
    args = parser.parse_args()
    
    # Get credentials from args or environment
    username = args.username or os.getenv('H1_USERNAME')
    token = args.token or os.getenv('H1_TOKEN')
    
    if username and token:
        print(f"[+] Using HackerOne API credentials for user: {username}")
    else:
        print("[*] No credentials provided - accessing public programs only")
    
    # Initialize fetcher
    fetcher = HackerOneAPIScopeFetcher(
        username=username,
        api_token=token
    )
    
    # Fetch program
    print(f"[*] Fetching scope for program: {args.program}")
    program = fetcher.get_program_by_handle(args.program)
    
    if not program:
        print("[!] Failed to fetch program scope")
        exit(1)
    
    # Apply filters
    filter_type = EligibilityFilter(args.filter)
    filtered_assets = ScopeFilter.filter_by_eligibility(program.assets, filter_type)
    
    # Print summary
    filtered_program = Program(
        handle=program.handle,
        name=program.name,
        assets=filtered_assets
    )
    ScopeExporter.print_summary(filtered_program)
    
    # Export if requested
    if args.export:
        ScopeExporter.to_text(filtered_assets, args.export)
    
    if args.export_json:
        ScopeExporter.to_json(filtered_program, args.export_json)
    
    # Print scannable targets
    targets = ScopeFilter.extract_targets(filtered_assets)
    print(f"\n[+] Scannable Targets ({len(targets)}):")
    for target in targets:
        print(f"  - {target}")