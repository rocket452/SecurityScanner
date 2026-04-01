#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Known SaaS/third-party platforms that always have login/admin paths — not real findings
_SAAS_DOMAINS = (
    'atlassian.net', 'atlassian.com', 'jira.com',
    'github.com', 'github.io',
    'okta.com', 'okta-emea.com', 'oktapreview.com',
    'salesforce.com', 'force.com',
    'zendesk.com',
    'hubspot.com', 'hubspotpagebuilder.com',
    'shopify.com', 'myshopify.com',
    'wordpress.com', 'wpengine.com',
    'squarespace.com',
    'cloudflare.com',
    'fastly.net',
    'amazonaws.com', 'awsapps.com',
    'azure.com', 'azurewebsites.net',
    'google.com', 'googleapis.com', 'googleusercontent.com',
)

# Paths that are only worth flagging on self-hosted apps, not on generic login pages
_HIGH_VALUE_PATHS = [
    '/admin', '/administrator', '/wp-admin', '/cpanel',
    '/phpmyadmin', '/adminer', '/panel',
]
# These are lower confidence — only report if the content is unambiguously admin UI
_LOW_CONF_PATHS = ['/login', '/dashboard', '/webmail']

# Signals that strongly suggest a real self-hosted admin panel (not a SaaS login page).
# NOTE: 'wp-admin' intentionally excluded — the /wp-admin path naturally contains
# "wp-admin" everywhere (form actions, links, classes), so it's a circular signal.
# WordPress admin login pages are normal; only the dashboard without auth is a finding.
_STRONG_ADMIN_SIGNALS = [
    'phpmyadmin', 'cpanel', 'whm', 'webmin',
    'adminer', 'drupal', 'joomla',
    'django administration', 'flask admin',
    'site administration', 'admin console',
    'management console', 'control panel',
]

# If the page title matches this pattern, the path is a user profile on a social platform
# (e.g. Tumblr routes /{username} → "@username on Tumblr"), not an admin panel.
_USER_PROFILE_TITLE_RE = re.compile(
    r'@\S+\s+on\s+\w+|^\s*\S+\s+\|\s+tumblr',
    re.IGNORECASE,
)


def _is_saas_domain(url: str) -> bool:
    from urllib.parse import urlparse
    host = urlparse(url).netloc.lower().split(':')[0]
    return any(host == d or host.endswith('.' + d) for d in _SAAS_DOMAINS)


def check_admin(url, headers=None, max_workers=8):
    """Check for common admin panels/backdoors.

    Avoids false positives on SaaS platforms (Atlassian, Okta, etc.) that
    always expose login pages with admin-sounding titles.
    """
    import hashlib

    # Skip known SaaS platforms entirely — their login pages are not findings
    if _is_saas_domain(url):
        return False

    # First check if root is accessible to establish baseline
    root_status = None
    root_body = ''
    root_hash = None
    try:
        root_resp = requests.get(url, timeout=5, verify=False, headers=headers)
        root_status = root_resp.status_code
        root_body = (root_resp.text or '').lower()
        root_hash = hashlib.md5((root_resp.text or '').encode()).hexdigest()
    except Exception:
        pass

    if root_status == 403:
        return False

    # SPA detection: probe a guaranteed-nonexistent path.
    # If it returns 200 with similar content to root, this is a SPA/catch-all
    # router and every path will return 200 — 200s are unreliable here.
    is_spa = False
    try:
        junk_resp = requests.get(
            f'{url.rstrip("/")}/definitely-not-real-xzqy9173',
            timeout=5, verify=False, headers=headers,
        )
        if junk_resp.status_code == 200:
            junk_hash = hashlib.md5((junk_resp.text or '').encode()).hexdigest()
            # If junk path returns same content as root (or very similar length),
            # treat as SPA — only trust strong signals, never 200-based heuristics
            if junk_hash == root_hash or abs(len(junk_resp.text or '') - len(root_body)) < 200:
                is_spa = True
    except Exception:
        pass

    try:
        workers = int(max_workers)
    except (TypeError, ValueError):
        workers = 8

    all_paths = _HIGH_VALUE_PATHS + _LOW_CONF_PATHS
    workers = max(1, min(workers, len(all_paths)))

    from urllib.parse import urlparse as _urlparse
    target_host = _urlparse(url).netloc.lower().split(':')[0]

    def probe_admin_path(path):
        test_url = f'{url.rstrip("/")}{path}'
        is_high_value = path in _HIGH_VALUE_PATHS
        try:
            resp = requests.get(test_url, timeout=5, verify=False, headers=headers)
        except Exception:
            return False

        # If the response redirected to a completely different domain, it's a platform
        # redirect (e.g. simplenote.com/admin → wordpress.com), not a self-hosted panel.
        final_host = _urlparse(resp.url).netloc.lower().split(':')[0]
        if final_host and final_host != target_host and not final_host.endswith('.' + target_host):
            return False

        body = (resp.text or '').lower()
        title_match = re.search(r'<title[^>]*>([^<]+)', resp.text or '', re.I)
        title = title_match.group(1).strip().lower() if title_match else ''

        if resp.status_code == 200:
            # User-profile routing false positive: social platforms (Tumblr, etc.) route
            # /{username} to a profile page — "@wp-admin on Tumblr" is not an admin panel.
            if _USER_PROFILE_TITLE_RE.search(title):
                return False

            # WordPress login page: the /wp-admin path serves a standard login form.
            # Having a WP login page accessible is normal — only flag if dashboard
            # content is visible WITHOUT auth (no password input on the page).
            if path in ('/wp-admin', '/wp-admin/') and '<input' in (resp.text or ''):
                if 'type="password"' in (resp.text or '').lower() or "type='password'" in (resp.text or '').lower():
                    return False  # Just the login page — not a finding

            # If this is a SPA, a 200 means nothing — the router caught the request.
            # Only trust responses whose content genuinely differs from both root
            # and the known-404 junk response.
            path_hash = hashlib.md5((resp.text or '').encode()).hexdigest()
            if is_spa and path_hash == root_hash:
                return False

            # Must have a strong admin signal in the page TITLE only — not the full body.
            # Checking the full body causes false positives when the admin signal word
            # appears in an embedded URL (e.g. "back=https://site.com/cpanel" in a script).
            # Real admin interfaces (phpMyAdmin, cPanel, Adminer) always put the product
            # name in the <title> tag.
            has_strong_signal = any(sig in title for sig in _STRONG_ADMIN_SIGNALS)
            if has_strong_signal:
                return True

            # Skip 200-based heuristics entirely on SPA sites to avoid false positives
            if is_spa:
                return False

            # For high-value paths, also flag if the page looks different from root
            # (suggests it's a dedicated admin interface, not the main login)
            if is_high_value and body != root_body and len(body) > 100:
                generic_login_signals = ['sign in', 'sign up', 'forgot password', 'create account', 'log in', 'log-in']
                is_generic_login = any(s in body for s in generic_login_signals)
                if not is_generic_login:
                    return any(kw in body or kw in title for kw in ['admin', 'cpanel', 'panel'])

        elif resp.status_code == 403 and root_status not in (403, None) and is_high_value:
            # 403 on a high-value path means the resource exists but is protected
            return True

        return 'directory listing' in body

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(probe_admin_path, path) for path in all_paths]
        for future in as_completed(futures):
            try:
                if future.result():
                    return True
            except Exception:
                continue
    return False

if __name__ == '__main__':
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    print(f'{check_admin(url)=}')
