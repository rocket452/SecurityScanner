#!/usr/bin/env python3
import subprocess
import urllib.parse
import re
import httpx

def log(msg, level='INFO'):
    print(f'[{level}] {msg}')

def check_exposed_buckets(url):
    """
    Check for common exposed bucket/storage paths
    Returns list of exposed paths with status codes
    """
    exposed = []
    
    # Common exposed bucket patterns
    bucket_patterns = [
        '/file-service/static/',
        '/file-service/',
        '/uploads/',
        '/static/',
        '/assets/',
        '/media/',
        '/files/',
        '/storage/',
        '/public/',
        '/download/',
        '/documents/',
        '/resources/',
        '/content/',
        '/data/',
        '/s3/',
        '/bucket/',
        '/cdn/',
        '/images/',
    ]
    
    log(f'Checking for exposed buckets/storage on {url}', 'INFO')
    
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True, verify=False) as client:
            for pattern in bucket_patterns:
                try:
                    test_url = f'{url.rstrip("/")}{pattern}'
                    resp = client.get(test_url)
                    
                    # Check if we got a directory listing or accessible bucket
                    if resp.status_code in [200, 201, 202, 203]:
                        content = resp.text.lower()
                        
                        # Indicators of directory listing or bucket exposure
                        indicators = [
                            'index of',
                            '<title>directory listing',
                            'parent directory',
                            '<pre>',  # Common in Apache/nginx listings
                            'listbucketresult',  # S3 bucket listing
                            '<?xml version',  # S3 XML response
                            'last modified',  # Directory listing
                            '<table>',  # Often used in listings
                        ]
                        
                        if any(indicator in content for indicator in indicators):
                            exposed.append((pattern, resp.status_code, 'DIRECTORY_LISTING'))
                            log(f'🚨 EXPOSED BUCKET: {test_url} [{resp.status_code}]', 'VULN')
                        elif len(content) > 0:  # Accessible but not obvious listing
                            exposed.append((pattern, resp.status_code, 'ACCESSIBLE'))
                            log(f'⚠️  Accessible path: {test_url} [{resp.status_code}]', 'WARN')
                    
                    elif resp.status_code == 403:
                        # 403 means the path exists but is forbidden - still worth noting
                        log(f'🔒 Forbidden (exists): {test_url} [403]', 'INFO')
                        exposed.append((pattern, 403, 'FORBIDDEN_BUT_EXISTS'))
                        
                except httpx.HTTPError as e:
                    log(f'Error checking {pattern}: {str(e)[:50]}', 'DEBUG')
                    continue
                    
    except Exception as e:
        log(f'Bucket check error: {str(e)[:100]}', 'ERROR')
    
    if exposed:
        log(f'Found {len(exposed)} exposed/accessible paths', 'INFO')
    
    return exposed

def fuzz_directories(url, wordlist='/app/wordlist.txt', timeout=120):
    """
    Use ffuf to discover hidden directories and files
    Returns list of discovered paths with status codes
    """
    discovered = []
    try:
        # First run: more permissive (without aggressive auto-calibration)
        log(f'Running ffuf with relaxed filtering against {url}', 'INFO')
        result = subprocess.run([
            'ffuf',
            '-u', f'{url.rstrip("/")}/FUZZ',
            '-w', wordlist,
            '-mc', '200,201,202,203,204,301,302,307,308,401,403',  # Include 403 (exists but forbidden)
            '-fc', '404',  # Only filter 404s
            '-t', '40',    # 40 threads
            '-timeout', '3',
            '-v',          # Verbose to get detailed output
            '-s'           # Silent mode: suppress banner
        ], capture_output=True, text=True, timeout=timeout)
        
        log(f'ffuf completed with exit code {result.returncode}', 'DEBUG')
        
        # Parse verbose format
        lines = result.stdout.split('\n')
        current_status = None
        
        for line in lines:
            # Extract status from [Status: XXX, ...] lines
            status_match = re.search(r'\[Status:\s*(\d+),', line)
            if status_match:
                current_status = status_match.group(1)
            
            # Extract path from * FUZZ: path lines
            fuzz_match = re.search(r'\*\s+FUZZ:\s+(\S+)', line)
            if fuzz_match and current_status:
                path = fuzz_match.group(1)
                discovered.append((path, current_status))
                current_status = None  # Reset for next entry
        
        if discovered:
            log(f'Found {len(discovered)} paths via fuzzing', 'INFO')
            # Show first 10 as examples
            for path, status in discovered[:10]:
                log(f'  {path} [{status}]', 'INFO')
            if len(discovered) > 10:
                log(f'  ... and {len(discovered) - 10} more', 'INFO')
        else:
            log('No paths found via fuzzing', 'INFO')
        
        return discovered
        
    except subprocess.TimeoutExpired:
        log(f'ffuf timeout after {timeout}s', 'WARN')
        return discovered
    except FileNotFoundError:
        log('ffuf not found in PATH', 'WARN')
        return discovered
    except Exception as e:
        log(f'ffuf error: {str(e)[:100]}', 'ERROR')
        return discovered

if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    
    # Check for exposed buckets first
    print('\n=== Checking for Exposed Buckets ===')
    bucket_results = check_exposed_buckets(url)
    if bucket_results:
        print(f'\nFound {len(bucket_results)} exposed/accessible paths:')
        for path, status, vuln_type in bucket_results:
            print(f'  [{status}] {path} - {vuln_type}')
    else:
        print('No exposed buckets detected')
    
    # Then run directory fuzzing
    print('\n=== Directory Fuzzing ===')
    fuzz_results = fuzz_directories(url)
    if fuzz_results:
        print(f'\nDiscovered {len(fuzz_results)} paths via fuzzing:')
        for path, status in fuzz_results:
            print(f'  [{status}] {path}')
    else:
        print('No paths discovered via fuzzing')
