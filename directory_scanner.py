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
        # ffuf command with verbose output
        log(f'Running ffuf with {wordlist} against {url}', 'DEBUG')
        result = subprocess.run([
            'ffuf',
            '-u', f'{url.rstrip("/")}/FUZZ',
            '-w', wordlist,
            '-mc', 'all',  # Match all status codes
            '-fc', '404',  # Filter out 404s
            '-t', '40',    # 40 threads
            '-timeout', '3',
            '-v'           # Verbose output
        ], capture_output=True, text=True, timeout=timeout)
        
        log(f'ffuf exit code: {result.returncode}', 'DEBUG')
        
        if result.stderr:
            log(f'ffuf stderr: {result.stderr[:200]}', 'DEBUG')
        
        # Parse verbose format:
        # [Status: 403, Size: 4514, Words: 620, Lines: 94, Duration: 152ms]
        # 
        # | URL | https://prime.platacard.mx/media
        # 
        #     * FUZZ: media
        
        lines = result.stdout.split('\n')
        log(f'ffuf output lines: {len(lines)}', 'DEBUG')
        
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
                log(f'Found: {path} -> {current_status}', 'DEBUG')
                current_status = None  # Reset for next entry
        
        log(f'Parsed {len(discovered)} paths from ffuf output', 'INFO')
        
        # If still nothing, try non-verbose with auto-calibration
        if not discovered:
            log('No results with -v flag, trying -ac (auto-calibration)...', 'DEBUG')
            result2 = subprocess.run([
                'ffuf',
                '-u', f'{url.rstrip("/")}/FUZZ',
                '-w', wordlist,
                '-mc', 'all',
                '-fc', '404',
                '-t', '40',
                '-timeout', '3',
                '-ac'  # Auto-calibration filters out repeated responses
            ], capture_output=True, text=True, timeout=timeout)
            
            if result2.stdout:
                # Non-verbose format: path [Status: XXX, Size: YYY]
                lines2 = result2.stdout.strip().split('\n')
                for line in lines2:
                    m = re.match(r'^(\S+)\s+\[Status:\s*(\d+),', line.strip())
                    if m:
                        path = m.group(1)
                        status = m.group(2)
                        discovered.append((path, status))
                        log(f'Found (AC): {path} -> {status}', 'DEBUG')
        
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
