#!/usr/bin/env python3
import subprocess
import sys
import argparse
from urllib.parse import urlparse
import httpx
# Note: Replace with actual import from existing scanner.py or implement scan_vulnerabilities
def scan_vulnerabilities(url):
    # Placeholder: Integrate your existing scanner logic here
    # For example, check for common issues like open directories, etc.
    return [{'url': url, 'issue': 'Example vulnerability'}]

def run_subfinder(target):
    try:
        result = subprocess.run(['subfinder', '-d', target, '-silent'], capture_output=True, text=True, timeout=300)
        return set(line.strip() for line in result.stdout.split('\n') if line.strip())
    except Exception as e:
        print(f'Subfinder error: {e}')
        return set()

def run_amass(target):
    try:
        result = subprocess.run(['amass', 'enum', '-d', target, '-passive', '-silent'], capture_output=True, text=True, timeout=600)
        return set(line.strip() for line in result.stdout.split('\n') if line.strip())
    except Exception as e:
        print(f'Amass error: {e}')
        return set()

def scan_subdomains(subdomains):
    vulnerabilities = []
    with httpx.Client(timeout=httpx.Timeout(10.0)) as client:
        for sub in subdomains:
            try:
                url = f'https://{sub}'
                resp = client.get(url, follow_redirects=True)
                if resp.status_code == 200:
                    vulns = scan_vulnerabilities(url)
                    vulnerabilities.extend(vulns)
                    print(f'Live: {url} - Status: {resp.status_code}')
            except Exception:
                try:
                    url = f'http://{sub}'
                    resp = client.get(url, follow_redirects=True)
                    if resp.status_code == 200:
                        vulns = scan_vulnerabilities(url)
                        vulnerabilities.extend(vulns)
                        print(f'Live: {url} - Status: {resp.status_code}')
                except:
                    pass
    return vulnerabilities

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Subdomain scanner using Subfinder + Amass')
    parser.add_argument('target', help='Target domain e.g., example.com')
    args = parser.parse_args()
    
    print('Running Subfinder...')
    subs1 = run_subfinder(args.target)
    print('Running Amass...')
    subs2 = run_amass(args.target)
    all_subs = subs1.union(subs2)
    print(f'Found {len(all_subs)} unique subdomains')
    
    vulns = scan_subdomains(all_subs)
    print('\nVulnerabilities found:')
    for v in vulns:
        print(f'- {v}')
