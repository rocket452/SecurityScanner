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
        # ffuf command: -u URL/FUZZ -w wordlist -mc all -fc 404 -t 40 -timeout 3 -ac (auto-calibration)
        log(f'Running ffuf with {wordlist} against {url}', 'DEBUG')
        result = subprocess.run([
            'ffuf',
            '-u', f'{url.rstrip("/")}/FUZZ',
            '-w', wordlist,
            '-mc', 'all',  # Match all status codes
            '-fc', '404',  # Filter out 404s
            '-t', '40',    # 40 threads for faster scanning
            '-timeout', '3',
            '-ac'          # Auto-calibration to filter default responses
        ], capture_output=True, text=True, timeout=timeout)
        
        log(f'ffuf exit code: {result.returncode}', 'DEBUG')
        if result.stderr:
            log(f'ffuf stderr: {result.stderr[:200]}', 'WARN')
        
        # Parse ffuf output - format: path [Status: XXX, Size: YYY, ...]
        lines = result.stdout.strip().split('\n')
        log(f'ffuf output lines: {len(lines)}', 'DEBUG')
        
        for line in lines:
            # Use regex to extract path and status from lines like: admin [Status: 403, Size: ...]
            m = re.match(r'^(\S+)\s+\[Status:\s*(\d+),', line.strip())
            if m:
                path = m.group(1)
                status = m.group(2)
                discovered.append((path, status))
        
        log(f'Parsed {len(discovered)} paths from ffuf output', 'DEBUG')
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
