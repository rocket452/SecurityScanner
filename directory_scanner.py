#!/usr/bin/env python3
import subprocess
import urllib.parse

def fuzz_directories(url, wordlist='/app/common.txt', timeout=60):
    """
    Use ffuf to discover hidden directories and files
    Returns list of discovered paths with status codes
    """
    discovered = []
    try:
        # ffuf command: -u URL/FUZZ -w wordlist -mc all -fc 404 -t 20 -timeout 5 -s (silent)
        result = subprocess.run([
            'ffuf',
            '-u', f'{url.rstrip("/")}/FUZZ',
            '-w', wordlist,
            '-mc', 'all',  # Match all status codes
            '-fc', '404',  # Filter out 404s
            '-t', '20',    # 20 threads
            '-timeout', '5',
            '-s'           # Silent mode
        ], capture_output=True, text=True, timeout=timeout)
        
        # Parse ffuf output - format: [Status: XXX] [Size: YYY] path
        for line in result.stdout.strip().split('\n'):
            if line.strip() and '[Status:' in line:
                parts = line.split(']')
                if len(parts) >= 3:
                    status = parts[0].replace('[Status:', '').strip()
                    path = parts[-1].strip()
                    if path:
                        discovered.append((path, status))
        
        return discovered
    except subprocess.TimeoutExpired:
        return discovered
    except Exception as e:
        return discovered

if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    results = fuzz_directories(url)
    print(f'Discovered {len(results)} paths:')
    for path, status in results:
        print(f'  [{status}] {path}')