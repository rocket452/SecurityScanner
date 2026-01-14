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
        # ffuf command with verbose output to see what's happening
        log(f'Running ffuf with {wordlist} against {url}', 'DEBUG')
        result = subprocess.run([
            'ffuf',
            '-u', f'{url.rstrip("/")}/FUZZ',
            '-w', wordlist,
            '-mc', 'all',  # Match all status codes
            '-fc', '404',  # Filter out 404s only (let 403s through to see them)
            '-t', '40',    # 40 threads for faster scanning
            '-timeout', '3',
            '-v'           # Verbose output to see full responses
        ], capture_output=True, text=True, timeout=timeout)
        
        log(f'ffuf exit code: {result.returncode}', 'DEBUG')
        
        # Show first 500 chars of stdout for debugging
        if result.stdout:
            log(f'ffuf stdout preview: {result.stdout[:500]}', 'DEBUG')
        
        if result.stderr:
            log(f'ffuf stderr: {result.stderr[:200]}', 'DEBUG')
        
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
                log(f'Found: {path} -> {status}', 'DEBUG')
        
        log(f'Parsed {len(discovered)} paths from ffuf output', 'INFO')
        
        # If we got nothing, try again without -v flag (different output format)
        if not discovered:
            log('No results with -v flag, trying without verbose...', 'DEBUG')
            result2 = subprocess.run([
                'ffuf',
                '-u', f'{url.rstrip("/")}/FUZZ',
                '-w', wordlist,
                '-mc', 'all',
                '-fc', '404',
                '-t', '40',
                '-timeout', '3',
                '-ac'  # Try auto-calibration on second attempt
            ], capture_output=True, text=True, timeout=timeout)
            
            if result2.stdout:
                log(f'Second attempt output: {result2.stdout[:500]}', 'DEBUG')
                lines2 = result2.stdout.strip().split('\n')
                for line in lines2:
                    m = re.match(r'^(\S+)\s+\[Status:\s*(\d+),', line.strip())
                    if m:
                        path = m.group(1)
                        status = m.group(2)
                        discovered.append((path, status))
        
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
