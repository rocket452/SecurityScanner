#!/usr/bin/env python3
import subprocess
import urllib.parse
import re

def log(msg, level='INFO'):
    print(f'[{level}] {msg}')

def fuzz_directories(url, wordlist='/app/wordlist.txt', timeout=120):
    """
    Use ffuf to discover hidden directories and files
    Returns list of discovered paths with status codes
    """
    discovered = []
    try:
        # ffuf with auto-calibration to filter out default responses
        log(f'Running ffuf with auto-calibration against {url}', 'INFO')
        result = subprocess.run([
            'ffuf',
            '-u', f'{url.rstrip("/")}/FUZZ',
            '-w', wordlist,
            '-mc', 'all',  # Match all status codes
            '-fc', '404',  # Filter out 404s
            '-ac',         # Auto-calibration: filters default/repeated responses
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
            log(f'Found {len(discovered)} unique paths after auto-calibration', 'INFO')
            # Show first 10 as examples
            for path, status in discovered[:10]:
                log(f'  {path} [{status}]', 'INFO')
            if len(discovered) > 10:
                log(f'  ... and {len(discovered) - 10} more', 'INFO')
        else:
            log('No unique paths found (auto-calibration filtered everything)', 'INFO')
        
        return discovered
        
    except subprocess.TimeoutExpired:
        log(f'ffuf timeout after {timeout}s', 'WARN')
        return discovered
    except FileNotFoundError:
        log('ffuf not found in PATH', 'ERROR')
        return discovered
    except Exception as e:
        log(f'ffuf error: {str(e)[:100]}', 'ERROR')
        return discovered

if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    results = fuzz_directories(url)
    print(f'Discovered {len(results)} paths:')
    for path, status in results:
        print(f'  [{status}] {path}')
