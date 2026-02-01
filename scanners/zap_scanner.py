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
        self.api_timeout = 30  # Timeout for individual API requests
    
    def _api_request(self, endpoint: str, params: Optional[Dict] = None, timeout: Optional[int] = None) -> Dict:
        """
        Make a request to ZAP's REST API with improved error handling.
        
        Args:
            endpoint: API endpoint (e.g., '/JSON/core/view/version/')
            params: Query parameters
            timeout: Request timeout in seconds (default: self.api_timeout)
        
        Returns:
            API response as dictionary
        """
        if params is None:
            params = {}
        
        if self.api_key:
            params['apikey'] = self.api_key
        
        url = f"{self.api_url}{endpoint}"
        request_timeout = timeout or self.api_timeout
        
        try:
            response = self.session.get(url, params=params, timeout=request_timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            raise Exception(f"ZAP API timeout after {request_timeout}s")
        except requests.exceptions.ConnectionError as e:
            raise Exception(f"ZAP connection error: {e}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"ZAP API request failed: {e}")
    
    def _api_action(self, endpoint: str, params: Optional[Dict] = None, timeout: Optional[int] = None) -> Dict:
        """
        Make an action request to ZAP's REST API.
        
        Args:
            endpoint: API endpoint for action
            params: Query parameters
            timeout: Request timeout in seconds
        
        Returns:
            API response as dictionary
        """
        return self._api_request(endpoint, params, timeout)
    
    def check_zap_running(self) -> bool:
        """
        Check if ZAP proxy is running and accessible.
        
        Returns:
            bool: True if ZAP is running, False otherwise
        """
        try:
            response = self._api_request('/JSON/core/view/version/', timeout=5)
            if 'version' in response:
                print(f"[ZAP] Connected to ZAP version {response['version']}")
                return True
            return False
        except Exception as e:
            print(f"[ZAP] Cannot connect to ZAP: {e}")
            return False
    
    def access_url(self, url: str, retries: int = 3) -> bool:
        """
        Access a URL through ZAP proxy to add it to the sites tree.
        
        Args:
            url: URL to access
            retries: Number of retry attempts
        
        Returns:
            bool: True if successful
        """
        for attempt in range(retries):
            try:
                self._api_action('/JSON/core/action/accessUrl/', {'url': url}, timeout=20)
                return True
            except Exception as e:
                if attempt < retries - 1:
                    print(f"[ZAP] Error accessing URL {url} (attempt {attempt + 1}/{retries}): {e}")
                    time.sleep(2)
                else:
                    print(f"[ZAP] Failed to access URL {url} after {retries} attempts: {e}")
                    return False
        return False
    
    def spider_url(self, url: str, max_depth: Optional[int] = 5, max_duration: int = 300) -> Optional[str]:
        """
        Spider a URL to discover all pages and endpoints with timeout protection.
        
        Args:
            url: Target URL to spider
            max_depth: Maximum depth for spidering
            max_duration: Maximum time to wait for spider (seconds)
        
        Returns:
            str: Scan ID for tracking progress, or None if failed
        """
        print(f'[ZAP] Starting spider on: {url}')
        
        # Access the URL through ZAP
        if not self.access_url(url):
            print(f'[ZAP] Skipping spider for {url} - cannot access URL')
            return None
        
        time.sleep(2)
        
        try:
            # Start spider
            params = {'url': url}
            if max_depth:
                params['maxDepth'] = max_depth
            
            response = self._api_action('/JSON/spider/action/scan/', params, timeout=20)
            scan_id = response.get('scan', '')
            
            if not scan_id:
                print(f'[ZAP] Failed to start spider for {url}')
                return None
            
            # Wait for spider to complete with timeout
            start_time = time.time()
            last_progress = -1
            stuck_count = 0
            
            while True:
                elapsed = time.time() - start_time
                
                # Check overall timeout
                if elapsed > max_duration:
                    print(f'[ZAP] Spider timeout after {max_duration}s - stopping spider')
                    try:
                        self._api_action('/JSON/spider/action/stop/', {'scanId': scan_id}, timeout=10)
                    except:
                        pass
                    break
                
                try:
                    status_response = self._api_request('/JSON/spider/view/status/', {'scanId': scan_id}, timeout=10)
                    progress = int(status_response.get('status', 0))
                    
                    # Check if spider is stuck
                    if progress == last_progress:
                        stuck_count += 1
                        if stuck_count > 10:  # Stuck for 50 seconds (10 * 5s)
                            print(f'[ZAP] Spider appears stuck at {progress}% - stopping')
                            try:
                                self._api_action('/JSON/spider/action/stop/', {'scanId': scan_id}, timeout=10)
                            except:
                                pass
                            break
                    else:
                        stuck_count = 0
                        last_progress = progress
                    
                    if progress >= 100:
                        print(f'[ZAP] Spider completed for {url}')
                        break
                    
                    print(f'[ZAP] Spider progress: {progress}% (elapsed: {int(elapsed)}s)')
                    time.sleep(5)
                    
                except Exception as e:
                    print(f'[ZAP] Error checking spider status: {e}')
                    # Try to continue or timeout
                    if elapsed > max_duration / 2:
                        print(f'[ZAP] Giving up on spider for {url}')
                        break
                    time.sleep(5)
            
            return scan_id
            
        except Exception as e:
            print(f'[ZAP] Spider error for {url}: {e}')
            return None
    
    def passive_scan(self, url: str, max_wait: int = 120) -> List[Dict]:
        """
        Perform passive scanning (analyzes traffic without attacking).
        
        Args:
            url: Target URL
            max_wait: Maximum time to wait for passive scan (seconds)
        
        Returns:
            List of passive scan alerts/vulnerabilities
        """
        print(f'[ZAP] Running passive scan on: {url}')
        
        try:
            # Access URL to generate traffic
            if not self.access_url(url):
                print(f'[ZAP] Skipping passive scan for {url} - cannot access URL')
                return []
            
            time.sleep(3)
            
            # Wait for passive scan to complete with timeout
            start_time = time.time()
            while True:
                elapsed = time.time() - start_time
                
                if elapsed > max_wait:
                    print(f'[ZAP] Passive scan timeout after {max_wait}s')
                    break
                
                try:
                    records_response = self._api_request('/JSON/pscan/view/recordsToScan/', timeout=10)
                    remaining = int(records_response.get('recordsToScan', 0))
                    
                    if remaining == 0:
                        break
                    
                    print(f'[ZAP] Passive scan records remaining: {remaining}')
                    time.sleep(2)
                    
                except Exception as e:
                    print(f'[ZAP] Error checking passive scan status: {e}')
                    break
            
            # Get passive scan alerts
            try:
                alerts_response = self._api_request('/JSON/core/view/alerts/', {'baseurl': url}, timeout=20)
                alerts = alerts_response.get('alerts', [])
                print(f'[ZAP] Passive scan found {len(alerts)} alert(s)')
                return alerts
            except Exception as e:
                print(f'[ZAP] Error retrieving alerts: {e}')
                return []
                
        except Exception as e:
            print(f'[ZAP] Passive scan error for {url}: {e}')
            return []
    
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
        
        try:
            # Start active scan
            params = {'url': url}
            if policy:
                params['scanPolicyName'] = policy
            
            response = self._api_action('/JSON/ascan/action/scan/', params, timeout=30)
            scan_id = response.get('scan', '')
            
            if not scan_id:
                print(f'[ZAP] Failed to start active scan for {url}')
                return ''
            
            # Monitor progress
            start_time = time.time()
            while True:
                elapsed = time.time() - start_time
                if elapsed > self.timeout:
                    print(f'[ZAP] Active scan timeout after {self.timeout}s')
                    try:
                        self._api_action('/JSON/ascan/action/stop/', {'scanId': scan_id}, timeout=10)
                    except:
                        pass
                    break
                
                try:
                    status_response = self._api_request('/JSON/ascan/view/status/', {'scanId': scan_id}, timeout=10)
                    progress = int(status_response.get('status', 0))
                    
                    if progress >= 100:
                        print(f'[ZAP] Active scan completed for {url}')
                        break
                    
                    print(f'[ZAP] Active scan progress: {progress}%')
                    time.sleep(10)
                    
                except Exception as e:
                    print(f'[ZAP] Error checking active scan status: {e}')
                    if elapsed > self.timeout / 2:
                        break
                    time.sleep(10)
            
            return scan_id
            
        except Exception as e:
            print(f'[ZAP] Active scan error for {url}: {e}')
            return ''
    
    def get_alerts(self, url: Optional[str] = None, risk: Optional[str] = None) -> List[Dict]:
        """
        Retrieve all alerts/vulnerabilities found by ZAP.
        
        Args:
            url: Filter by specific URL (optional)
            risk: Filter by risk level: High, Medium, Low, Informational (optional)
        
        Returns:
            List of vulnerability alerts
        """
        try:
            params = {}
            if url:
                params['baseurl'] = url
            
            response = self._api_request('/JSON/core/view/alerts/', params, timeout=20)
            alerts = response.get('alerts', [])
            
            # Filter by risk level if specified
            if risk:
                alerts = [a for a in alerts if a.get('risk', '').lower() == risk.lower()]
            
            return alerts
            
        except Exception as e:
            print(f'[ZAP] Error getting alerts: {e}')
            return []
    
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
                if not self.access_url(subdomain):
                    print(f'[ZAP] Skipping {subdomain} - cannot access')
                    results[subdomain] = []
                    continue
                
                time.sleep(1)
                
                # Spider the subdomain
                if spider:
                    spider_result = self.spider_url(subdomain, max_duration=180)
                    if spider_result is None:
                        print(f'[ZAP] Spider failed for {subdomain}, continuing with passive scan')
                
                # Passive scan
                if passive:
                    self.passive_scan(subdomain, max_wait=60)
                
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
            
            response = self.session.get(url, params=params, timeout=60)
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
                'solution': alert.get('solution', ''),
                'sources': ['ZAP']
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
