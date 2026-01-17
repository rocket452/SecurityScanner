#!/usr/bin/env python3
"""
OWASP ZAP Scanner Module

Integrates ZAP vulnerability scanning with subdomain discovery tools.
Follows hybrid approach: Use Subfinder/Amass for discovery, then ZAP for scanning.
Uses ZAP's REST API directly (no Python library dependency).
"""

import time
import subprocess
import json
import os
import requests
from typing import List, Dict, Optional


class ZAPScanner:
    """
    OWASP ZAP scanner wrapper that integrates with existing subdomain discovery.
    Uses ZAP's REST API for communication.
    """
    
    def __init__(self, proxy_url='http://localhost:8080', api_key=None, timeout=300):
        """
        Initialize ZAP scanner.
        
        Args:
            proxy_url: ZAP proxy URL (default: http://localhost:8080)
            api_key: ZAP API key for authentication (optional, not needed if disabled)
            timeout: Default timeout for scans in seconds
        """
        self.proxy_url = proxy_url.rstrip('/')
        self.api_url = f"{self.proxy_url}"
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()
    
    def _api_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """
        Make a request to ZAP's REST API.
        
        Args:
            endpoint: API endpoint (e.g., '/JSON/core/view/version/')
            params: Query parameters
        
        Returns:
            API response as dictionary
        """
        if params is None:
            params = {}
        
        if self.api_key:
            params['apikey'] = self.api_key
        
        url = f"{self.api_url}{endpoint}"
        
        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"ZAP API request failed: {e}")
    
    def _api_action(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """
        Make an action request to ZAP's REST API.
        
        Args:
            endpoint: API endpoint for action
            params: Query parameters
        
        Returns:
            API response as dictionary
        """
        return self._api_request(endpoint, params)
    
    def check_zap_running(self) -> bool:
        """
        Check if ZAP proxy is running and accessible.
        
        Returns:
            bool: True if ZAP is running, False otherwise
        """
        try:
            response = self._api_request('/JSON/core/view/version/')
            if 'version' in response:
                print(f"[ZAP] Connected to ZAP version {response['version']}")
                return True
            return False
        except Exception:
            return False
    
    def access_url(self, url: str) -> bool:
        """
        Access a URL through ZAP proxy to add it to the sites tree.
        
        Args:
            url: URL to access
        
        Returns:
            bool: True if successful
        """
        try:
            self._api_action('/JSON/core/action/accessUrl/', {'url': url})
            return True
        except Exception as e:
            print(f"[ZAP] Error accessing URL {url}: {e}")
            return False
    
    def spider_url(self, url: str, max_depth: Optional[int] = 5) -> str:
        """
        Spider a URL to discover all pages and endpoints.
        
        Args:
            url: Target URL to spider
            max_depth: Maximum depth for spidering
        
        Returns:
            str: Scan ID for tracking progress
        """
        print(f'[ZAP] Starting spider on: {url}')
        
        # Access the URL through ZAP
        self.access_url(url)
        time.sleep(2)
        
        # Start spider
        params = {'url': url}
        if max_depth:
            params['maxDepth'] = max_depth
        
        response = self._api_action('/JSON/spider/action/scan/', params)
        scan_id = response.get('scan', '')
        
        # Wait for spider to complete
        while True:
            status_response = self._api_request('/JSON/spider/view/status/', {'scanId': scan_id})
            progress = int(status_response.get('status', 0))
            
            if progress >= 100:
                break
            
            print(f'[ZAP] Spider progress: {progress}%')
            time.sleep(5)
        
        print(f'[ZAP] Spider completed for {url}')
        return scan_id
    
    def passive_scan(self, url: str) -> List[Dict]:
        """
        Perform passive scanning (analyzes traffic without attacking).
        
        Args:
            url: Target URL
        
        Returns:
            List of passive scan alerts/vulnerabilities
        """
        print(f'[ZAP] Running passive scan on: {url}')
        
        # Access URL to generate traffic
        self.access_url(url)
        time.sleep(3)
        
        # Wait for passive scan to complete
        while True:
            records_response = self._api_request('/JSON/pscan/view/recordsToScan/')
            remaining = int(records_response.get('recordsToScan', 0))
            
            if remaining == 0:
                break
            
            print(f'[ZAP] Passive scan records remaining: {remaining}')
            time.sleep(2)
        
        # Get passive scan alerts
        alerts_response = self._api_request('/JSON/core/view/alerts/', {'baseurl': url})
        alerts = alerts_response.get('alerts', [])
        print(f'[ZAP] Passive scan found {len(alerts)} alert(s)')
        
        return alerts
    
    def active_scan(self, url: str, policy: Optional[str] = None) -> str:
        """
        Perform active scanning (attacks the target to find vulnerabilities).
        WARNING: Only use on targets you have permission to test!
        
        Args:
            url: Target URL
            policy: Scan policy name (optional)
        
        Returns:
            str: Scan ID for tracking progress
        """
        print(f'[ZAP] Starting active scan on: {url}')
        print('[ZAP] WARNING: Active scanning will attack the target!')
        
        # Start active scan
        params = {'url': url}
        if policy:
            params['scanPolicyName'] = policy
        
        response = self._api_action('/JSON/ascan/action/scan/', params)
        scan_id = response.get('scan', '')
        
        # Monitor progress
        start_time = time.time()
        while True:
            elapsed = time.time() - start_time
            if elapsed > self.timeout:
                print(f'[ZAP] Active scan timeout after {self.timeout}s')
                self._api_action('/JSON/ascan/action/stop/', {'scanId': scan_id})
                break
            
            status_response = self._api_request('/JSON/ascan/view/status/', {'scanId': scan_id})
            progress = int(status_response.get('status', 0))
            
            if progress >= 100:
                break
            
            print(f'[ZAP] Active scan progress: {progress}%')
            time.sleep(10)
        
        print(f'[ZAP] Active scan completed for {url}')
        return scan_id
    
    def get_alerts(self, url: Optional[str] = None, risk: Optional[str] = None) -> List[Dict]:
        """
        Retrieve all alerts/vulnerabilities found by ZAP.
        
        Args:
            url: Filter by specific URL (optional)
            risk: Filter by risk level: High, Medium, Low, Informational (optional)
        
        Returns:
            List of vulnerability alerts
        """
        params = {}
        if url:
            params['baseurl'] = url
        
        response = self._api_request('/JSON/core/view/alerts/', params)
        alerts = response.get('alerts', [])
        
        # Filter by risk level if specified
        if risk:
            alerts = [a for a in alerts if a.get('risk', '').lower() == risk.lower()]
        
        return alerts
    
    def scan_subdomain_list(self, subdomains: List[str], 
                           spider: bool = True, 
                           passive: bool = True, 
                           active: bool = False) -> Dict[str, List[Dict]]:
        """
        Scan a list of subdomains discovered by Subfinder/Amass.
        
        Args:
            subdomains: List of subdomain URLs to scan
            spider: Enable spidering (default: True)
            passive: Enable passive scanning (default: True)
            active: Enable active scanning (default: False, requires permission!)
        
        Returns:
            Dict mapping each subdomain to its vulnerabilities
        """
        results = {}
        
        for subdomain in subdomains:
            print(f'\n[ZAP] === Scanning: {subdomain} ===')
            
            try:
                # Add to ZAP context
                self.access_url(subdomain)
                time.sleep(1)
                
                # Spider the subdomain
                if spider:
                    self.spider_url(subdomain)
                
                # Passive scan
                if passive:
                    self.passive_scan(subdomain)
                
                # Active scan (optional, requires permission)
                if active:
                    self.active_scan(subdomain)
                
                # Collect all alerts for this subdomain
                alerts = self.get_alerts(url=subdomain)
                results[subdomain] = alerts
                
                print(f'[ZAP] Found {len(alerts)} issue(s) on {subdomain}')
                
            except Exception as e:
                print(f'[ZAP] Error scanning {subdomain}: {e}')
                results[subdomain] = []
        
        return results
    
    def generate_report(self, output_path: str, format: str = 'html') -> bool:
        """
        Generate ZAP scan report.
        
        Args:
            output_path: Path to save report
            format: Report format (html, json, xml, md)
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            print(f'[ZAP] Generating {format.upper()} report: {output_path}')
            
            endpoint_map = {
                'html': '/OTHER/core/other/htmlreport/',
                'json': '/OTHER/core/other/jsonreport/',
                'xml': '/OTHER/core/other/xmlreport/',
                'md': '/OTHER/core/other/mdreport/'
            }
            
            endpoint = endpoint_map.get(format.lower())
            if not endpoint:
                print(f'[ZAP] Unsupported format: {format}')
                return False
            
            # Get report data
            url = f"{self.api_url}{endpoint}"
            params = {}
            if self.api_key:
                params['apikey'] = self.api_key
            
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            print(f'[ZAP] Report saved to: {output_path}')
            return True
            
        except Exception as e:
            print(f'[ZAP] Error generating report: {e}')
            return False
    
    def parse_alerts_to_vulns(self, alerts: List[Dict]) -> List[Dict]:
        """
        Convert ZAP alerts to standardized vulnerability format.
        
        Args:
            alerts: List of ZAP alert dictionaries
        
        Returns:
            List of vulnerabilities in scanner.py format
        """
        vulns = []
        
        for alert in alerts:
            # Map ZAP risk levels to severity
            risk = alert.get('risk', 'Low')
            severity_map = {
                'High': 'high',
                'Medium': 'medium',
                'Low': 'low',
                'Informational': 'info'
            }
            severity = severity_map.get(risk, 'low')
            
            vuln = {
                'type': 'zap_' + alert.get('pluginId', 'unknown'),
                'description': f"[ZAP] {alert.get('alert', 'Unknown vulnerability')}: {alert.get('description', '')[:200]}",
                'severity': severity,
                'url': alert.get('url', ''),
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', '')
            }
            vulns.append(vuln)
        
        return vulns


def check_zap_docker() -> bool:
    """
    Check if ZAP is running in Docker and start it if not.
    
    Returns:
        bool: True if ZAP is available, False otherwise
    """
    try:
        # Check if ZAP container is running
        result = subprocess.run(
            ['docker', 'ps', '--filter', 'name=securityscanner-zap', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.stdout.strip():
            print('[ZAP] ZAP Docker container is running')
            return True
        
        print('[ZAP] ZAP not running. Start with: docker-compose up -d zap')
        return False
        
    except FileNotFoundError:
        print('[ZAP] Docker not installed')
        return False
    except Exception as e:
        print(f'[ZAP] Error checking Docker: {e}')
        return False


if __name__ == '__main__':
    # Test ZAP scanner
    print('Testing ZAP Scanner Module (REST API version)')
    
    # Check if ZAP is running
    if check_zap_docker():
        scanner = ZAPScanner()
        if scanner.check_zap_running():
            print('✅ ZAP is accessible and ready!')
        else:
            print('❌ ZAP is not accessible')
    else:
        print('⚠️  Start ZAP with: docker-compose up -d zap')
