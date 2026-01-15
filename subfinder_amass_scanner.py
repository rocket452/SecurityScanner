#!/usr/bin/env python3
import subprocess
import sys
import argparse
import httpx
import yaml

# ============================================================================
# LOGGING UTILITIES
# ============================================================================

def log(msg, level='INFO'):
    """Centralized logging function"""
    print(f'[{level}] {msg}')

# ============================================================================
# SUBDOMAIN ENUMERATION
# ============================================================================

def retrieve_sub_domains_from_subfinder(target):
    """
    Use Subfinder to discover subdomains for the target domain.
    Returns a list of discovered subdomains.
    """
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
    """
    Use Amass to discover subdomains for the target domain.
    Returns a list of discovered subdomains.
    """
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
    """
    Remove duplicate domains from the list and return sorted unique domains.
    """
    unique_domains = sorted(set(domains))
    log(f'Deduplicated to {len(unique_domains)} unique domain(s)', 'INFO')
    return unique_domains

# ============================================================================
# VULNERABILITY SCANNING
# ============================================================================

def scan_single_domain_for_vulnerabilities(url):
    """
    Perform comprehensive vulnerability scanning on a single URL.
    Returns a list of vulnerabilities found.
    """
    vulns = []
    
    try:
        # Import scanners
        from admin_scanner import check_admin
        from backup_scanner import check_backup
        from directory_scanner import check_exposed_buckets, fuzz_directories
        
        # Admin panel detection
        if check_admin(url):
            vulns.append('Admin panel exposed')
            log(f'ADMIN on {url}', 'VULN')
        
        # Backup file detection
        if check_backup(url):
            vulns.append('Backup file found')
            log(f'BACKUP on {url}', 'VULN')
        
        # Exposed buckets/storage detection
        log(f'Checking for exposed buckets/storage on {url}', 'INFO')
        bucket_results = check_exposed_buckets(url)
        
        if bucket_results:
            for path, status, vuln_type in bucket_results:
                if vuln_type == 'DIRECTORY_LISTING':
                    vulns.append(f'Exposed directory listing: {path} [{status}]')
                    log(f'BUCKET EXPOSED: {path} [{status}] - {vuln_type}', 'VULN')
                elif vuln_type == 'ACCESSIBLE':
                    vulns.append(f'Accessible path: {path} [{status}]')
                    log(f'ACCESSIBLE PATH: {path} [{status}]', 'VULN')
                elif vuln_type == 'FORBIDDEN_BUT_EXISTS':
                    vulns.append(f'Path exists (forbidden): {path} [{status}]')
                    log(f'PATH EXISTS: {path} [{status}]', 'INFO')
        
        # Recursive directory fuzzing
        log(f'Starting recursive directory fuzzing on {url}', 'INFO')
        discovered = fuzz_directories(url, timeout=180, recursive=True, max_depth=3)
        
        if discovered:
            log(f'Discovered {len(discovered)} total paths via recursive fuzzing', 'OK')
            for path, status in discovered:
                vulns.append(f'Discovered path: /{path} [{status}]')
                # Only log first 20 to avoid spam
                if len([v for v in vulns if 'Discovered path' in v]) <= 20:
                    log(f'FUZZ: /{path} [{status}]', 'VULN')
            
            if len(discovered) > 20:
                log(f'... and {len(discovered) - 20} more paths (check report for full list)', 'INFO')
        else:
            log('No paths discovered via recursive fuzzing', 'INFO')
        
        # Nuclei vulnerability scanning
        log(f'Running Nuclei on {url}', 'INFO')
        result = subprocess.run(
            ['nuclei', '-u', url, '-silent', '-nc', '-severity', 'critical,high,medium'],
            capture_output=True, text=True, timeout=180
        )
        
        if result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    vulns.append(f'Nuclei: {line.strip()}')
                    log(f'NUCLEI: {line.strip()}', 'VULN')
                    
    except subprocess.TimeoutExpired:
        log('Nuclei timeout', 'WARN')
    except FileNotFoundError:
        log('Nuclei not installed', 'WARN')
    except Exception as e:
        log(f'Scanner error: {e}', 'WARN')
    
    return vulns

def probe_live_domains(domains):
    """
    Test which domains are live and accessible via HTTP/HTTPS.
    Returns a list of tuples: (url, is_live, status_code)
    """
    live_domains = []
    
    with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
        for domain in sorted(domains):
            for proto in ['https', 'http']:
                try:
                    url = f'{proto}://{domain}'
                    resp = client.get(url)
                    
                    # Accept any 2xx, 3xx, or 4xx status code (scan reachable hosts even if blocked)
                    if 200 <= resp.status_code < 500:
                        live_domains.append((url, True, resp.status_code))
                        print(f'✅ {url} ({resp.status_code})')
                        break
                    else:
                        log(f'{url} returned {resp.status_code}', 'DEBUG')
                        
                except Exception as e:
                    log(f'{url} unreachable: {str(e)[:50]}', 'DEBUG')
    
    return live_domains

def scan_domains_for_vulnerabilities(domains):
    """
    Main vulnerability scanning function.
    Probes domains for liveness, then scans live domains for vulnerabilities.
    Returns a list of tuples: (url, vulnerabilities)
    """
    # Probe which domains are live
    live_domains = probe_live_domains(domains)
    
    # Scan each live domain for vulnerabilities
    scan_results = []
    for url, is_live, status_code in live_domains:
        if is_live:
            vulns = scan_single_domain_for_vulnerabilities(url)
            scan_results.append((url, vulns))
    
    return scan_results

# ============================================================================
# REPORTING
# ============================================================================

def print_vulnerability_report(scan_results):
    """
    Print the final vulnerability report.
    """
    print('\n🚨 VULNERABILITIES:')
    
    has_vulns = False
    for url, vulns in scan_results:
        if vulns:
            has_vulns = True
            for vuln in vulns:
                print(f'{url}: {vuln}')
    
    if not has_vulns:
        print('No vulnerabilities detected.')

def print_scan_summary(domains, target):
    """
    Print a summary of domains to be scanned.
    """
    print('\n' + '=' * 60)
    print(f'📊 SUMMARY: {len(domains)} total target(s) to scan')
    print('=' * 60)
    for domain in domains:
        print(f'  • {domain}')
    print('=' * 60 + '\n')

# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """
    Main entry point for the security scanner.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Security Scanner with Nuclei Integration')
    parser.add_argument('target', help='Target domain')
    args = parser.parse_args()
    
    target_url = args.target
    
    # Print header
    print(f'\n🔍 {target_url}')
    print('=' * 60)
    
    # Initialize an empty list for subdomains
    sub_domains = []
    
    # Add domains from Subfinder
    sub_domains.extend(retrieve_sub_domains_from_subfinder(target_url))
    
    # Add domains from Amass
    sub_domains.extend(retrieve_sub_domains_from_amass(target_url))
    
    # Always include the base domain
    sub_domains.append(target_url)
    log(f'Including base domain in scan: {target_url}', 'INFO')
    
    # Deduplicate the domains
    sub_domains = deduplicate_domains(sub_domains)
    
    # Print summary of domains to scan
    print_scan_summary(sub_domains, target_url)
    
    # Scan domains for vulnerabilities
    scan_results = scan_domains_for_vulnerabilities(sub_domains)
    
    # Print vulnerability report
    print_vulnerability_report(scan_results)

if __name__ == '__main__':
    main()
