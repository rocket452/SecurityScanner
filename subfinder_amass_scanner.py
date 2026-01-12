#!/usr/bin/env python3
import subprocess
import sys
import argparse
import httpx
import os
import yaml

def docker_available():
    return subprocess.run(['docker', '--version'], capture_output=True).returncode == 0

def run_subfinder(target):
    try:
        if docker_available():
            cmd = ['docker', 'run', '--rm', 'projectdiscovery/subfinder:latest', '-d', target, '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
            if subs:
                print('Subfinder via Docker OK')
                return subs
        result = subprocess.run(['subfinder', '-d', target, '-silent'], capture_output=True, text=True, timeout=300)
        return set(line.strip() for line in result.stdout.split('\n') if line.strip())
    except Exception as e:
        print(f'Subfinder failed (install or Docker): {e}')
        return set()

def run_amass(target):
    try:
        if docker_available():
            cmd = ['docker', 'run', '--rm', 'owaspamass/amass:latest', 'enum', '-passive', '-d', target, '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            subs = set(line.strip() for line in result.stdout.split('\n') if line.strip())
            if subs:
                print('Amass via Docker OK')
                return subs
        result = subprocess.run(['amass', 'enum', '-passive', '-d', target, '-silent'], capture_output=True, text=True, timeout=600)
        return set(line.strip() for line in result.stdout.split('\n') if line.strip())
    except Exception as e:
        print(f'Amass failed (install or Docker): {e}')
        return set()

def scan_vulnerabilities(url):
    vulns = []
    try:
        from admin_scanner import check_admin
        from backup_scanner import check_backup
        if check_admin(url):
            vulns.append({'url': url, 'issue': 'Admin panel detected'})
        if check_backup(url):
            vulns.append({'url': url, 'issue': 'Backup file exposed'})
    except ImportError as e:
        vulns.append({'url': url, 'issue': f'Scanner import error: {str(e)} - check file paths'})
    except Exception as e:
        vulns.append({'url': url, 'issue': f'Scan failed: {str(e)}'})
    return vulns

def scan_subdomains(subdomains):
    vulnerabilities = []
    with httpx.Client(timeout=httpx.Timeout(10.0)) as client:
        for sub in sorted(subdomains):
            for protocol in ['https', 'http']:
                try:
                    full_url = f'{protocol}://{sub}'
                    resp = client.get(full_url, follow_redirects=True)
                    if 200 <= resp.status_code < 400:
                        vulns = scan_vulnerabilities(full_url)
                        vulnerabilities.extend(vulns)
                        print(f'Live: {full_url} (Status: {resp.status_code})')
                        break
                except:
                    continue
    return vulnerabilities

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Subdomain/Vuln Scanner w/ Docker Fallback')
    parser.add_argument('target', help='Target domain e.g. av7bible.com')
    args = parser.parse_args()
    
    print(f'Scanning {args.target}...')
    print('Subfinder:')
    subs1 = run_subfinder(args.target)
    print('Amass:')
    subs2 = run_amass(args.target)
    all_subs = subs1.union(subs2)
    print(f'{len(all_subs)} unique subdomains: {sorted(all_subs)}')
    
    vulns = scan_subdomains(all_subs)
    print('\nVULNERABILITIES:')
    if vulns:
        for v in vulns:
            print(f'- {v["url"]}: {v["issue"]}')
    else:
        print('No vulnerabilities detected (add more scanners).')
