#!/usr/bin/env python3
import hashlib
import subprocess
import urllib.parse
import re
import httpx
import yaml
import time
import os
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Load configuration
def load_config():
    config_path = os.getenv('SECURITYSCANNER_CONFIG', 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except:
        # Return defaults if config file not found
        return {
            'rate_limiting': {
                'ffuf_threads': 20,
                'http_timeout': 10,
                'request_delay': 0
            }
        }

CONFIG = load_config()

def log(msg, level='INFO'):
    print(f'[{level}] {msg}')


class _LinkExtractor(HTMLParser):
    """Extract candidate internal URLs from common HTML attributes."""

    def __init__(self):
        super().__init__()
        self.urls: List[str] = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs or [])

        # Common navigational/resource attributes that often contain interesting paths.
        if tag in ('a', 'link'):
            val = attrs_dict.get('href')
            if val:
                self.urls.append(val)
        elif tag in ('script', 'img', 'iframe', 'source', 'video', 'audio'):
            val = attrs_dict.get('src')
            if val:
                self.urls.append(val)
        elif tag == 'form':
            val = attrs_dict.get('action')
            if val:
                self.urls.append(val)


def _extract_internal_paths_from_html(base_url: str, html: str, max_candidates: int = 250) -> List[str]:
    """
    Parse HTML and extract unique internal paths (e.g. "/feedback") for the same origin.
    """
    if not html:
        return []

    try:
        base = urllib.parse.urlparse(base_url)
    except Exception:
        return []

    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        # HTMLParser can throw on some malformed input; best-effort only.
        return []

    # Filter out obvious static assets, but keep "page-like" endpoints (e.g. .php).
    static_exts = {
        'css', 'js', 'map',
        'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'ico',
        'woff', 'woff2', 'ttf', 'eot', 'otf',
        'mp4', 'mp3', 'wav', 'avi', 'mov', 'mpeg', 'webm',
        'pdf', 'zip', 'gz', 'tgz', 'rar', '7z',
    }

    paths: Set[str] = set()
    for raw in parser.urls[: max_candidates * 3]:
        raw = (raw or '').strip()
        if not raw:
            continue

        # Skip non-HTTP navigations.
        lowered = raw.lower()
        if lowered.startswith(('javascript:', 'mailto:', 'tel:', 'data:')):
            continue

        # Resolve relative URLs against base.
        abs_url = urllib.parse.urljoin(base_url, raw)
        try:
            parsed = urllib.parse.urlparse(abs_url)
        except Exception:
            continue

        # Keep only same-origin URLs (avoid probing external domains).
        if parsed.scheme not in ('http', 'https'):
            continue
        if parsed.netloc and parsed.netloc != base.netloc:
            continue

        path = parsed.path or '/'
        if not path.startswith('/'):
            path = '/' + path

        # Normalize some noise.
        if path == '//':
            path = '/'

        # Always add the first path segment as a "subdirectory guess" (e.g. "/resources", "/feedback").
        # This catches cases where only a deep static asset is linked ("/resources/css/app.css"),
        # but the top-level directory is still useful to discover.
        seg = path.strip('/').split('/', 1)[0] if path.strip('/') else ''
        if seg:
            paths.add('/' + seg)

        # Also keep the full path when it doesn't look like a static asset.
        last = path.rsplit('/', 1)[-1]
        ext = last.rsplit('.', 1)[-1].lower() if '.' in last else ''
        is_static_asset = bool(ext) and ext in static_exts

        if path != '/' and not is_static_asset:
            paths.add(path)

    # Prefer shorter paths first (more likely to be top-level endpoints like /feedback).
    return sorted(paths, key=lambda p: (p.count('/'), len(p), p))


def discover_paths_from_links(
    url: str,
    timeout: Optional[int] = None,
    headers: Optional[Dict[str, str]] = None,
    max_probe: int = 60,
) -> List[Tuple[str, str]]:
    """
    Fetch a page, extract internal link/form/resource paths, then probe them.

    Returns: list of (path, status_code_str) for paths that appear to exist (non-404).
    """
    discovered: List[Tuple[str, str]] = []
    timeout = timeout or CONFIG.get('rate_limiting', {}).get('http_timeout', 10)
    request_delay = CONFIG.get('rate_limiting', {}).get('request_delay', 0) / 1000.0  # ms -> s

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
            resp = client.get(url)
            html = resp.text if resp.status_code < 500 else ''

            # SPA detection: if a junk URL returns 200 with similar content, all paths are noise
            root_body = resp.text or ''
            root_hash = hashlib.md5(root_body.encode()).hexdigest()
            is_spa = False
            try:
                junk_resp = client.get(f'{url.rstrip("/")}/definitely-not-real-xzqy9173')
                if junk_resp.status_code == 200:
                    junk_hash = hashlib.md5((junk_resp.text or '').encode()).hexdigest()
                    if junk_hash == root_hash or abs(len(junk_resp.text or '') - len(root_body)) < 200:
                        is_spa = True
                        log('Link-based discovery: SPA detected — skipping path probing (all paths return 200)', 'INFO')
                        return discovered
            except Exception:
                pass

            candidates = _extract_internal_paths_from_html(url, html)
            if not candidates:
                log('Link-based discovery: extracted 0 internal paths', 'INFO')
                return discovered

            probe = candidates[:max_probe]
            log(f'Link-based discovery: extracted {len(candidates)} internal paths, probing {len(probe)}', 'INFO')

            # Extensions that suggest security-interesting files even when served as HTML
            _interesting_exts = {
                'php', 'asp', 'aspx', 'cgi', 'pl', 'rb', 'py',
                'json', 'xml', 'yaml', 'yml', 'txt', 'env', 'cfg',
                'config', 'conf', 'ini', 'bak', 'sql', 'log',
            }
            _api_patterns = ('/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/rpc/', '/ws/')

            for path in probe:
                try:
                    if request_delay > 0:
                        time.sleep(request_delay)

                    test_url = urllib.parse.urljoin(url.rstrip('/') + '/', path.lstrip('/'))
                    r = client.get(test_url)
                    if r.status_code != 404:
                        # Skip if content is identical to root (SPA catch-all returning index page)
                        if root_hash:
                            path_hash = hashlib.md5((r.text or '').encode()).hexdigest()
                            if path_hash == root_hash:
                                continue
                        # Skip plain HTML pages with no security-interesting extension or API pattern.
                        # These are almost always rendered pages (SPA routes, CMS pages) rather
                        # than exposed resources. Real findings have non-HTML content or known
                        # interesting extensions (.php, .json, .env, etc.).
                        resp_ct = r.headers.get('content-type', '').lower()
                        if 'text/html' in resp_ct:
                            last_seg = path.rsplit('/', 1)[-1]
                            ext = last_seg.rsplit('.', 1)[-1].lower() if '.' in last_seg else ''
                            if ext not in _interesting_exts and not any(p in path.lower() for p in _api_patterns):
                                continue
                        discovered.append((path, str(r.status_code)))
                except httpx.HTTPError:
                    continue

    except Exception as e:
        log(f'Link-based discovery error: {str(e)[:100]}', 'WARN')

    if discovered:
        log(f'Link-based discovery: found {len(discovered)} existing path(s)', 'OK')
    else:
        log('Link-based discovery: no existing paths found (non-404) from probed candidates', 'INFO')

    return discovered

def check_exposed_buckets(url, headers=None):
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

    rl = CONFIG.get('rate_limiting', {})
    timeout = rl.get('bucket_timeout') or rl.get('http_timeout', 10)

    indicators = [
        'index of',
        '<title>directory listing',
        'parent directory',
        '<pre>',
        'listbucketresult',
        '<?xml version',
        'last modified',
        '<table>',
    ]

    # SPA detection: probe root and a junk URL to see if all 200s are catch-all
    root_hash = None
    is_spa = False
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as _spa_client:
            root_resp = _spa_client.get(url)
            root_body = root_resp.text or ''
            root_hash = hashlib.md5(root_body.encode()).hexdigest()
            junk_resp = _spa_client.get(f'{url.rstrip("/")}/definitely-not-real-xzqy9173.zip')
            if junk_resp.status_code == 200:
                junk_hash = hashlib.md5((junk_resp.text or '').encode()).hexdigest()
                if junk_hash == root_hash or abs(len(junk_resp.text or '') - len(root_body)) < 200:
                    is_spa = True
                    log(f'SPA detected on {url} — suppressing generic ACCESSIBLE findings', 'INFO')
    except Exception:
        pass

    def _probe(pattern):
        test_url = f'{url.rstrip("/")}{pattern}'
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, headers=headers) as client:
                resp = client.get(test_url)
            if resp.status_code in [200, 201, 202, 203]:
                # On SPAs, every URL returns 200 — skip generic ACCESSIBLE findings
                if is_spa:
                    return None
                # Skip if content is identical to root (SPA catch-all)
                if root_hash:
                    path_hash = hashlib.md5((resp.text or '').encode()).hexdigest()
                    if path_hash == root_hash:
                        return None
                resp_ct = resp.headers.get('content-type', '').lower()
                content = resp.text.lower()
                if any(ind in content for ind in indicators):
                    log(f'EXPOSED BUCKET: {test_url} [{resp.status_code}]', 'VULN')
                    return (pattern, resp.status_code, 'DIRECTORY_LISTING')
                # Real exposed storage/directories return security-interesting content types.
                # HTML, images, fonts, CSS, and JS are normal web assets — not findings.
                _uninteresting_ct = (
                    'text/html', 'image/', 'font/', 'text/css',
                    'application/javascript', 'text/javascript',
                )
                if not resp_ct or any(resp_ct.startswith(u) for u in _uninteresting_ct):
                    return None
                if content:
                    log(f'Accessible path: {test_url} [{resp.status_code}]', 'WARN')
                    return (pattern, resp.status_code, 'ACCESSIBLE')
            elif resp.status_code == 403:
                log(f'Forbidden (exists): {test_url} [403]', 'INFO')
                return (pattern, 403, 'FORBIDDEN_BUT_EXISTS')
        except httpx.HTTPError as e:
            log(f'Error checking {pattern}: {str(e)[:50]}', 'DEBUG')
        return None

    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=min(8, len(bucket_patterns))) as executor:
            futures = {executor.submit(_probe, p): p for p in bucket_patterns}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    exposed.append(result)
    except Exception as e:
        log(f'Bucket check error: {str(e)[:100]}', 'ERROR')
    
    if exposed:
        log(f'Found {len(exposed)} exposed/accessible paths', 'INFO')
    
    return exposed

def fuzz_directories_recursive(url, wordlist='/app/wordlist.txt', timeout=120, max_depth=3, current_depth=0, headers=None):
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
    
    # Get thread count from config
    ffuf_threads = CONFIG.get('rate_limiting', {}).get('ffuf_threads', 20)
    
    try:
        # Run ffuf on current level with configurable thread count
        ffuf_cmd = [
            'ffuf',
            '-u', f'{url.rstrip("/")}/FUZZ',
            '-w', wordlist,
            '-mc', '200,201,202,203,204,301,302,307,308,401,403',
            '-fc', '404',
            '-t', str(ffuf_threads),  # Use configured thread count
            '-timeout', '3',
            '-v',
            '-s'
        ]
        if headers:
            for key, value in headers.items():
                ffuf_cmd.extend(['-H', f'{key}: {value}'])

        result = subprocess.run(
            ffuf_cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
        )
        
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
                dirs_limited = directories_to_recurse[:10]

                from concurrent.futures import ThreadPoolExecutor, as_completed

                def _recurse(item):
                    path, full_path = item
                    log(f'{depth_prefix}Recursing into: {path}', 'INFO')
                    return path, fuzz_directories_recursive(
                        full_path,
                        wordlist=wordlist,
                        timeout=timeout,
                        max_depth=max_depth,
                        current_depth=current_depth + 1,
                        headers=headers,
                    )

                with ThreadPoolExecutor(max_workers=min(4, len(dirs_limited))) as executor:
                    futures = {executor.submit(_recurse, item): item for item in dirs_limited}
                    for future in as_completed(futures):
                        try:
                            path, recursive_results = future.result()
                            for rpath, rstatus in recursive_results:
                                all_discovered.append((f'{path}/{rpath}', rstatus))
                        except Exception as e:
                            log(f'{depth_prefix}Recursion error: {str(e)[:80]}', 'WARN')
        
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

def fuzz_directories(url, wordlist='/app/wordlist.txt', timeout=120, recursive=True, max_depth=3, headers=None):
    """
    Main entry point for directory fuzzing
    If recursive=True, performs recursive fuzzing up to max_depth
    If recursive=False, performs single-level fuzzing only
    """
    if recursive:
        log(f'Starting recursive directory fuzzing (max depth: {max_depth})', 'INFO')
        ffuf_threads = CONFIG.get('rate_limiting', {}).get('ffuf_threads', 20)
        log(f'Using {ffuf_threads} threads for ffuf', 'INFO')
        
        discovered = fuzz_directories_recursive(url, wordlist, timeout, max_depth, current_depth=0, headers=headers)
        
        if discovered:
            log(f'Total paths discovered across all depths: {len(discovered)}', 'OK')
        else:
            log('No paths discovered via recursive fuzzing', 'INFO')
        
        return discovered
    else:
        # Original single-level fuzzing
        log(f'Running single-level ffuf against {url}', 'INFO')
        ffuf_threads = CONFIG.get('rate_limiting', {}).get('ffuf_threads', 20)
        discovered = []
        try:
            ffuf_cmd = [
                'ffuf',
                '-u', f'{url.rstrip("/")}/FUZZ',
                '-w', wordlist,
                '-mc', '200,201,202,203,204,301,302,307,308,401,403',
                '-fc', '404',
                '-t', str(ffuf_threads),
                '-timeout', '3',
                '-v',
                '-s'
            ]
            if headers:
                for key, value in headers.items():
                    ffuf_cmd.extend(['-H', f'{key}: {value}'])

            result = subprocess.run(
                ffuf_cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout,
            )
            
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
