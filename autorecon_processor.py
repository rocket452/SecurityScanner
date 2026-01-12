#!/usr/bin/env python3
"""
AutoRecon Results Processor + Custom Checks
Builds on AutoRecon output with your high-value validators
"""

import os
import json
import glob
import subprocess
from checks.hardcoded_secrets import check_hardcoded_secrets
from checks.sql_injection import check_sql_injection

class AutoReconProcessor:
    def __init__(self, autorecon_dir):
        self.autorecon_dir = autorecon_dir
        self.findings = []

    def parse_autorecon_results(self):
        """Extract URLs and IPs from AutoRecon output"""
        urls = []
        # Parse Nmap XML for open ports
        for nmap_file in glob.glob(f'{self.autorecon_dir}/**/nmap/*.xml'):
            # Extract hosts with HTTP ports
            urls.extend(self._extract_http_hosts(nmap_file))
        return urls

    def _extract_http_hosts(self, nmap_xml):
        """Parse Nmap XML for web services"""
        # Simple regex/parser for HTTP ports 80,443,8080, etc.
        urls = []
        with open(nmap_xml, 'r') as f:
            content = f.read()
            # Extract host:port where service=http
            import re
            hosts = re.findall(r'<address addr="([^"]+)"/', content)
            for host in hosts:
                urls.append(f'http://{host}')
                urls.append(f'https://{host}')
        return list(set(urls))

    def run_custom_checks(self, urls):
        """Run your specialized checks"""
        print(f'[*] Running custom checks on {len(urls)} URLs...')
        for url in urls[:10]:  # Limit for demo
            print(f'[*] Checking {url}')
            # Fetch page content
            try:
                resp = requests.get(url, timeout=10)
                content = resp.text
                # Your checks
                secrets = check_hardcoded_secrets(url, content)
                sqli = check_sql_injection(url, content)
                self.findings.extend(secrets + sqli)
            except:
                pass

    def generate_report(self):
        """Prioritized report"""
        report = {
            'target': self.autorecon_dir.split('/')[-1],
            'high_value_findings': self.findings,
            'recommendations': []
        }
        # Add exploit chains
        if any('hardcoded_secret' in f['type'] for f in self.findings):
            report['recommendations'].append('Test API key exfiltration')
        
        with open('security_scanner_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        print('[+] Report: security_scanner_report.json')

if __name__ == '__main__':
    autorecon_dir = input('AutoRecon results dir (e.g. results/target.com): ')
    processor = AutoReconProcessor(autorecon_dir)
    urls = processor.parse_autorecon_results()
    processor.run_custom_checks(urls)
    processor.generate_report()