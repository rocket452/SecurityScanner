#!/usr/bin/env python3
"""
OWASP ZAP Scanner Module

Integrates ZAP vulnerability scanning with subdomain discovery tools.
Follows hybrid approach: Use Subfinder/Amass for discovery, then ZAP for scanning.
"""

import time
import subprocess
import json
import os
from typing import List, Dict, Optional

try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False


class ZAPScanner:
    """
    OWASP ZAP scanner wrapper that integrates with existing subdomain discovery.
    """
    
    def __init__(self, proxy_url='http://localhost:8080', api_key=None, timeout=300):
        """
        Initialize ZAP scanner.
        
        Args:
            proxy_url: ZAP proxy URL (default: http://localhost:8080)
            api_key: ZAP API key for authentication (optional)
            timeout: Default timeout for scans in seconds
        """
        if not ZAP_AVAILABLE:
            raise ImportError("python-owasp-zap-v2.4 not installed. Run: pip install python-owasp-zap-v2.4")
        
        self.proxy_url = proxy_url
        self.timeout = timeout
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={'http': proxy_url, 'https': proxy_url}
        )
    
    def check_zap_running(self) -> bool:
        """
        Check if ZAP proxy is running and accessible.
        
        Returns:
            bool: True if ZAP is running, False otherwise
        """
        try:
            # Try to access ZAP core API
            version = self.zap.core.version
            return True
        except Exception:
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
        self.zap.urlopen(url)
        time.sleep(2)
        
        # Start spider
        scan_id = self.zap.spider.scan(url, maxdepth=max_depth)
        
        # Wait for spider to complete
        while int(self.zap.spider.status(scan_id)) < 100:
            progress = self.zap.spider.status(scan_id)
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
        self.zap.urlopen(url)
        time.sleep(3)
        
        # Wait for passive scan to complete
        while int(self.zap.pscan.records_to_scan) > 0:
            remaining = self.zap.pscan.records_to_scan
            print(f'[ZAP] Passive scan records remaining: {remaining}')
            time.sleep(2)
        
        # Get passive scan alerts
        alerts = self.zap.core.alerts(baseurl=url)
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
        if policy:
            scan_id = self.zap.ascan.scan(url, scanpolicyname=policy)
        else:
            scan_id = self.zap.ascan.scan(url)
        
        # Monitor progress
        start_time = time.time()
        while int(self.zap.ascan.status(scan_id)) < 100:
            elapsed = time.time() - start_time
            if elapsed > self.timeout:
                print(f'[ZAP] Active scan timeout after {self.timeout}s')
                self.zap.ascan.stop(scan_id)
                break
            
            progress = self.zap.ascan.status(scan_id)
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
        if url:
            alerts = self.zap.core.alerts(baseurl=url)
        else:
            alerts = self.zap.core.alerts()
        
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
                self.zap.urlopen(subdomain)
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
            
            if format.lower() == 'html':
                report_data = self.zap.core.htmlreport()
            elif format.lower() == 'json':
                report_data = self.zap.core.jsonreport()
            elif format.lower() == 'xml':
                report_data = self.zap.core.xmlreport()
            elif format.lower() == 'md':
                report_data = self.zap.core.mdreport()
            else:
                print(f'[ZAP] Unsupported format: {format}')
                return False
            
            with open(output_path, 'w') as f:
                f.write(report_data)
            
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
            ['docker', 'ps', '--filter', 'ancestor=zaproxy/zap-stable', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.stdout.strip():
            print('[ZAP] ZAP Docker container is running')
            return True
        
        print('[ZAP] ZAP not running. Start with: docker run -u zap -p 8080:8080 -d zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.disablekey=true')
        return False
        
    except FileNotFoundError:
        print('[ZAP] Docker not installed')
        return False
    except Exception as e:
        print(f'[ZAP] Error checking Docker: {e}')
        return False


if __name__ == '__main__':
    # Test ZAP scanner
    print('Testing ZAP Scanner Module')
    
    if not ZAP_AVAILABLE:
        print('ERROR: python-owasp-zap-v2.4 not installed')
        print('Install with: pip install python-owasp-zap-v2.4')
    else:
        print('ZAP library is available')
        
        # Check if ZAP is running
        if check_zap_docker():
            scanner = ZAPScanner()
            if scanner.check_zap_running():
                print('✅ ZAP is accessible and ready!')
            else:
                print('❌ ZAP is not accessible')
        else:
            print('⚠️  Start ZAP Docker container first')
