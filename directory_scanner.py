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

def fuzz_directories_recursive(url, wordlist='/app/wordlist.txt', timeout=120, max_depth=3, current_depth=0):
    """
    Recursively fuzz directories using ffuf
    Returns list of all discovered paths with status codes
    """
    all_discovered = []
    
    if current_depth >= max_depth:
        log(f'Max depth {max_depth} reached, stopping recursion', 'INFO')
        return all_discovered
    
    depth_prefix = '  ' * current_depth
    log(f'{depth_prefix}Fuzzing at depth {current_depth}: {url}', 'INFO')
    
    try:
        # Run ffuf on current level
        result = subprocess.run([
            'ffuf',
            '-u', f'{url.rstrip("/")}/FUZZ',
            '-w', wordlist,
            '-mc', '200,201,202,203,204,301,302,307,308,401,403',
            '-fc', '404',
            '-t', '50',
            '-timeout', '3',
            '-v',
            '-s'
        ], capture_output=True, text=True, timeout=timeout)
        
        # Parse results
        lines = result.stdout.split('\n')
        current_status = None
        discovered_this_level = []
        
        for line in lines:
            status_match = re.search(r'\[Status:\s*(\d+),', line)
            if status_match:
                current_status = status_match.group(1)
            
            fuzz_match = re.search(r'\*\s+FUZZ:\s+(\S+)', line)
            if fuzz_match and current_status:
                path = fuzz_match.group(1)
                full_path = f'{url.rstrip("/")}/{path}'
                discovered_this_level.append((path, current_status, full_path))
                all_discovered.append((path, current_status))
                log(f'{depth_prefix}  └─ {path} [{current_status}]', 'OK')
                current_status = None
        
        # Recursive fuzzing on discovered directories (status 200, 301, 302, 403)
        if current_depth < max_depth - 1:
            directories_to_recurse = [
                (path, full_path) for path, status, full_path in discovered_this_level
                if status in ['200', '301', '302', '403']  # Likely directories
            ]
            
            if directories_to_recurse:
                log(f'{depth_prefix}Found {len(directories_to_recurse)} potential directories to recurse into', 'INFO')
                
                for path, full_path in directories_to_recurse[:10]:  # Limit recursion to first 10 paths
                    log(f'{depth_prefix}Recursing into: {path}', 'INFO')
                    recursive_results = fuzz_directories_recursive(
                        full_path,
                        wordlist=wordlist,
                        timeout=timeout,
                        max_depth=max_depth,
                        current_depth=current_depth + 1
                    )
                    # Add parent path to recursive results
                    for rpath, rstatus in recursive_results:
                        all_discovered.append((f'{path}/{rpath}', rstatus))
        
        return all_discovered
        
    except subprocess.TimeoutExpired:
        log(f'{depth_prefix}ffuf timeout at depth {current_depth}', 'WARN')
        return all_discovered
    except FileNotFoundError:
        log('ffuf not found in PATH', 'WARN')
        return all_discovered
    except Exception as e:
        log(f'{depth_prefix}ffuf error at depth {current_depth}: {str(e)[:100]}', 'ERROR')
        return all_discovered

def fuzz_directories(url, wordlist='/app/wordlist.txt', timeout=120, recursive=True, max_depth=3):
    """
    Main entry point for directory fuzzing
    If recursive=True, performs recursive fuzzing up to max_depth
    If recursive=False, performs single-level fuzzing only
    """
    if recursive:
        log(f'Starting recursive directory fuzzing (max depth: {max_depth})', 'INFO')
        discovered = fuzz_directories_recursive(url, wordlist, timeout, max_depth, current_depth=0)
        
        if discovered:
            log(f'Total paths discovered across all depths: {len(discovered)}', 'OK')
        else:
            log('No paths discovered via recursive fuzzing', 'INFO')
        
        return discovered
    else:
        # Original single-level fuzzing
        log(f'Running single-level ffuf against {url}', 'INFO')
        discovered = []
        try:
            result = subprocess.run([
                'ffuf',
                '-u', f'{url.rstrip("/")}/FUZZ',
                '-w', wordlist,
                '-mc', '200,201,202,203,204,301,302,307,308,401,403',
                '-fc', '404',
                '-t', '40',
                '-timeout', '3',
                '-v',
                '-s'
            ], capture_output=True, text=True, timeout=timeout)
            
            lines = result.stdout.split('\n')
            current_status = None
            
            for line in lines:
                status_match = re.search(r'\[Status:\s*(\d+),', line)
                if status_match:
                    current_status = status_match.group(1)
                
                fuzz_match = re.search(r'\*\s+FUZZ:\s+(\S+)', line)
                if fuzz_match and current_status:
                    path = fuzz_match.group(1)
                    discovered.append((path, current_status))
                    current_status = None
            
            if discovered:
                log(f'Found {len(discovered)} paths', 'INFO')
            else:
                log('No paths found', 'INFO')
            
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
    
    # Then run recursive directory fuzzing
    print('\n=== Recursive Directory Fuzzing ===')
    fuzz_results = fuzz_directories(url, recursive=True, max_depth=3)
    if fuzz_results:
        print(f'\nDiscovered {len(fuzz_results)} paths via recursive fuzzing:')
        for path, status in fuzz_results:
            print(f'  [{status}] {path}')
    else:
        print('No paths discovered via fuzzing')
