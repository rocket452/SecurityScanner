#!/usr/bin/env python3
"""
Vulnerability Deduplication Module

Deduplicates findings from multiple scanners (ZAP, Nuclei, custom scanners)
by creating fingerprints based on vulnerability characteristics.
"""

import hashlib
from typing import List, Dict


def create_vuln_fingerprint(vuln: Dict) -> str:
    """
    Create a unique fingerprint for a vulnerability to detect duplicates.
    
    Args:
        vuln: Vulnerability dictionary with keys: type, description, url
    
    Returns:
        str: MD5 hash fingerprint of the vulnerability
    """
    # Normalize fields for comparison
    vuln_type = vuln.get('type', 'unknown').lower().strip()
    description = vuln.get('description', '').lower().strip()
    url = vuln.get('url', '').lower().strip()
    
    # Remove common scanner prefixes to improve matching
    for prefix in ['[zap]', '[nuclei]', '[xss]', '[scanner]']:
        description = description.replace(prefix, '').strip()
    
    # Create fingerprint from normalized data
    fingerprint_data = f"{vuln_type}|{description}|{url}"
    return hashlib.md5(fingerprint_data.encode()).hexdigest()


def determine_source(vuln: Dict) -> str:
    """
    Determine which scanner detected this vulnerability.
    
    Args:
        vuln: Vulnerability dictionary
    
    Returns:
        str: Scanner name (ZAP, Nuclei, XSS Scanner, etc.)
    """
    vuln_type = vuln.get('type', '').lower()
    
    if vuln_type.startswith('zap_'):
        return 'ZAP'
    elif vuln_type == 'nuclei':
        return 'Nuclei'
    elif vuln_type == 'xss' or 'xss' in vuln_type:
        return 'XSS Scanner'
    elif vuln_type == 'admin_panel':
        return 'Admin Scanner'
    elif vuln_type == 'backup_file':
        return 'Backup Scanner'
    elif 'storage' in vuln_type or 'bucket' in vuln_type:
        return 'Storage Scanner'
    elif 'path' in vuln_type or 'directory' in vuln_type:
        return 'Directory Scanner'
    else:
        return 'Custom Scanner'


def deduplicate_vulnerabilities(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Remove duplicate vulnerabilities and track which scanners found them.
    
    When a duplicate is found, the source scanner is added to the 'sources'
    list of the original finding. This helps understand if multiple scanners
    independently discovered the same issue.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
    
    Returns:
        List of deduplicated vulnerabilities with 'sources' field added
    """
    if not vulnerabilities:
        return []
    
    seen_fingerprints = {}
    deduplicated = []
    duplicates_count = 0
    
    for vuln in vulnerabilities:
        fingerprint = create_vuln_fingerprint(vuln)
        
        if fingerprint not in seen_fingerprints:
            # First occurrence of this vulnerability
            source = determine_source(vuln)
            vuln['sources'] = [source]
            seen_fingerprints[fingerprint] = vuln
            deduplicated.append(vuln)
        else:
            # Duplicate found - add source to existing vulnerability
            duplicates_count += 1
            existing_vuln = seen_fingerprints[fingerprint]
            source = determine_source(vuln)
            
            # Only add if not already tracked
            if source not in existing_vuln['sources']:
                existing_vuln['sources'].append(source)
    
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
