#!/usr/bin/env python3
import subprocess
import sys
import argparse
import httpx
import os
import yaml

def docker_available():
    return subprocess.run(['docker', '--version'], capture_output=True).returncode == 0

def run_tool_docker(tool, target):
    cmd = ['docker', 'run', '--rm', f'{tool}-image', target]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    return set(line.strip() for line in result.stdout.split('\n') if line.strip())

def run_subfinder(target):
    try:
        if docker_available():
            return run_tool_docker('projectdiscovery/subfinder', f'-d {target} -silent')
        result = subprocess.run(['subfinder', '-d', target, '-silent'], capture_output=True, text=True, timeout=300)
        return set(line.strip() for line in result.stdout.split('\n') if line.strip())
    except FileNotFoundError:
        print('Subfinder: Use local install or Docker')
        return set()
    except Exception as e:
        print(f'Subfinder error: {e}')
        return set()

def run_amass(target):
    try:
        if docker_available():
            return run_tool_docker('owasp/amass', f'enum -passive -d {target} -silent')
        result = subprocess.run(['amass', 'enum', '-d', target, '-passive', '-silent'], capture_output=True, text=True, timeout=600)
        return set(line.strip() for line in result.stdout.split('\n') if line.strip())
    except FileNotFoundError:
        print('Amass: Use local install or Docker')
        return set()
    except Exception as e:
        print(f'Amass error: {e}')
        return set()

def scan_vulnerabilities(url):
    vulns = []
    try:
        # Integrate existing local scanners
        from admin_scanner import check_admin
        from backup_scanner import check_backup
        if check_admin(url):
            vulns.append({'url': url, 'issue': 'Admin panel exposed'})
        if check_backup(url):
            vulns.append({'url': url, 'issue': 'Backup file found'})
    except ImportError:
        vulns.append({'url': url, 'issue': 'Local scanner integration pending - add imports'})
    except Exception as e:
        vulns.append({'url': url, 'issue': f'Scan error: {str(e)}'})
    return vulns

def scan_subdomains(subdomains):
    vulnerabilities = []
    with httpx.Client(timeout=httpx.Timeout(10.0)) as client:
        for sub in subdomains:
            for protocol in ['https', 'http']:
                try:
                    full_url = f'{protocol}://{sub}'
                    resp = client.get(full_url, follow_redirects=True)
                    if 200 <= resp.status_code < 400:
                        vulns = scan_vulnerabilities(full_url)
                        vulnerabilities.extend(vulns)
                        print(f'Live: {full_url} - Status: {resp.status_code}')
                        break
                except Exception:
                    continue
    return vulnerabilities

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Subdomain + Vuln Scanner (Docker/Local)')
    parser.add_argument('target', help='Target domain (e.g., av7bible.com)')
    args = parser.parse_args()
    
    print('Running Subfinder...')
    subs1 = run_subfinder(args.target)
    print('Running Amass...')
    subs2 = run_amass(args.target)
    all_subs = subs1.union(subs2)
    print(f'Found {len(all_subs)} unique subdomains: {sorted(all_subs)}')
    
    vulns = scan_subdomains(all_subs)
    print('\nVulnerabilities:')
    for v in vulns:
        print(f'- {v}')
