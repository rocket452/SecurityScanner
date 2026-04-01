#!/usr/bin/env python3
"""
Vulnerability Deduplication Module

Deduplicates findings from multiple scanners (ZAP, Nuclei, custom scanners)
by creating fingerprints based on vulnerability characteristics.
"""

import hashlib
import re
from typing import List, Dict, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def _normalize_url(url: str) -> str:
    """Strip tracking/noise query params and normalize the URL for fingerprinting."""
    try:
        parsed = urlparse(url.lower().strip())
        # Drop fragment and tracking params that don't change the resource identity
        noise_params = {'ref', 'utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid', '_ga'}
        qs = parse_qs(parsed.query, keep_blank_values=True)
        filtered = {k: v for k, v in qs.items() if k not in noise_params}
        # Sort params so order doesn't matter
        normalized_query = urlencode(sorted(filtered.items()))
        normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', normalized_query, ''))
        return normalized
    except Exception:
        return url.lower().strip()


def _extract_param(vuln: Dict) -> str:
    """Best-effort extraction of the affected parameter name from a vuln dict."""
    # Explicit param field
    for key in ('param', 'parameter', 'param_name'):
        if vuln.get(key):
            return str(vuln[key]).lower().strip()
    # Try to parse it from description: 'param "foo"', 'parameter: foo', etc.
    desc = vuln.get('description', '')
    m = re.search(r'param(?:eter)?[:\s"\']+(\w+)', desc, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return ''


def _severity_rank(vuln: Dict) -> int:
    rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    return rank.get(str(vuln.get('severity', 'low')).lower(), 0)


def create_vuln_fingerprint(vuln: Dict) -> str:
    """
    Create a unique fingerprint for a vulnerability to detect duplicates.

    Uses vulnerability type + normalized URL + parameter name so that:
    - Two findings on the same URL but different params are NOT merged
    - URL query-param ordering and tracking params are ignored
    - Scanner prefix noise in descriptions is ignored
    """
    vuln_type = vuln.get('type', 'unknown').lower().strip()
    # Broad type normalisation: collapse scanner-specific prefixes
    vuln_type = re.sub(r'^(zap_|nuclei_)', '', vuln_type)

    url = _normalize_url(vuln.get('url', ''))
    param = _extract_param(vuln)

    fingerprint_data = f"{vuln_type}|{url}|{param}"
    return hashlib.md5(fingerprint_data.encode()).hexdigest()


def determine_source(vuln: Dict) -> str:
    """Determine which scanner detected this vulnerability."""
    vuln_type = vuln.get('type', '').lower()
    sources_hint = vuln.get('sources', [])

    if sources_hint:
        return sources_hint[0] if isinstance(sources_hint, list) else str(sources_hint)
    if vuln_type.startswith('zap') or 'zap' in vuln_type:
        return 'ZAP'
    if vuln_type == 'nuclei' or 'nuclei' in vuln_type:
        return 'Nuclei'
    if 'xss' in vuln_type:
        return 'XSS Scanner'
    if vuln_type == 'admin_panel':
        return 'Admin Scanner'
    if vuln_type == 'backup_file':
        return 'Backup Scanner'
    if 'storage' in vuln_type or 'bucket' in vuln_type:
        return 'Storage Scanner'
    if 'path' in vuln_type or 'directory' in vuln_type:
        return 'Directory Scanner'
    return 'Custom Scanner'


def _merge_into(existing: Dict, incoming: Dict) -> None:
    """Merge a duplicate finding into the existing record, keeping the best data."""
    # Upgrade severity to the higher of the two
    if _severity_rank(incoming) > _severity_rank(existing):
        existing['severity'] = incoming.get('severity', existing.get('severity'))

    # Merge confidence: keep the higher value
    if incoming.get('confidence', 0) > existing.get('confidence', 0):
        existing['confidence'] = incoming['confidence']

    # Merge exploitation details
    if 'exploitation' in incoming:
        if 'exploitation' not in existing:
            existing['exploitation'] = incoming['exploitation']
        else:
            for k, v in incoming['exploitation'].items():
                if k not in existing['exploitation']:
                    existing['exploitation'][k] = v
                elif isinstance(v, list) and isinstance(existing['exploitation'].get(k), list):
                    seen = set(map(str, existing['exploitation'][k]))
                    for item in v:
                        if str(item) not in seen:
                            existing['exploitation'][k].append(item)
                            seen.add(str(item))

    # Prefer a description with more detail
    if len(str(incoming.get('description', ''))) > len(str(existing.get('description', ''))):
        existing['description'] = incoming['description']


def deduplicate_vulnerabilities(vulnerabilities: List[Dict]) -> Tuple[List[Dict], int]:
    """
    Remove duplicate vulnerabilities and track which scanners found them.

    When a duplicate is found:
    - The source scanner is added to the 'sources' list
    - Severity is upgraded to the higher of the two findings
    - Exploitation details are merged
    - The higher-confidence description is kept
    """
    if not vulnerabilities:
        return [], 0

    seen_fingerprints: Dict[str, Dict] = {}
    deduplicated: List[Dict] = []
    duplicates_count = 0

    for vuln in vulnerabilities:
        fingerprint = create_vuln_fingerprint(vuln)
        source = determine_source(vuln)

        if fingerprint not in seen_fingerprints:
            vuln = dict(vuln)  # shallow copy so we don't mutate the caller's data
            vuln['sources'] = [source]
            seen_fingerprints[fingerprint] = vuln
            deduplicated.append(vuln)
        else:
            duplicates_count += 1
            existing = seen_fingerprints[fingerprint]
            if source not in existing['sources']:
                existing['sources'].append(source)
            _merge_into(existing, vuln)

    return deduplicated, duplicates_count


def deduplicate_scan_results(scan_results: List[tuple]) -> List[tuple]:
    """
    Deduplicate vulnerabilities across all scanned URLs.

    Args:
        scan_results: List of (url, vulnerabilities) tuples

    Returns:
        List of (url, deduplicated_vulnerabilities) tuples
    """
    deduplicated_results = []
    total_duplicates = 0

    for url, vulns in scan_results:
        deduplicated_vulns, dup_count = deduplicate_vulnerabilities(vulns)
        deduplicated_results.append((url, deduplicated_vulns))
        total_duplicates += dup_count

    if total_duplicates > 0:
        print(f'[INFO] Removed {total_duplicates} duplicate finding(s) across all targets')

    return deduplicated_results
