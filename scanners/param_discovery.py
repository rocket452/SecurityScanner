#!/usr/bin/env python3
"""
Parameter Discovery Scanner using Arjun

Finds hidden GET/POST parameters that may be vulnerable to injection attacks.
Arjun tests thousands of common parameter names to discover hidden attack surface.
"""

import subprocess
import json
import os
import tempfile
from typing import List, Dict, Optional
from .xss_scanner import log


def discover_parameters(url: str, 
                       method: str = 'GET',
                       wordlist: Optional[str] = None,
                       threads: int = 5,
                       timeout: int = 30) -> Dict[str, List[str]]:
    """
    Discover hidden parameters using Arjun
    
    Args:
        url: Target URL to scan
        method: HTTP method (GET or POST)
        wordlist: Custom wordlist path (optional)
        threads: Number of threads for parallel testing
        timeout: Request timeout in seconds
    
    Returns:
        Dictionary with 'parameters' list and 'method'
    """
    log(f"Starting parameter discovery on {url} (method: {method})", 'INFO')
    
    # Create temporary output file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
        output_file = tmp_file.name
    
    try:
        # Build Arjun command
        cmd = [
            'arjun',
            '-u', url,
            '-m', method,
            '-oJ', output_file,  # JSON output
            '-t', str(threads),
            '--stable',  # Use stable HTTP requests
            '-q'  # Quiet mode
        ]
        
        if wordlist:
            cmd.extend(['-w', wordlist])
        
        log(f"Running: {' '.join(cmd)}", 'DEBUG')
        
        # Run Arjun
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Parse results
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                try:
                    arjun_results = json.load(f)
                    
                    # Arjun output format: {"url": {"method": ["param1", "param2"]}}
                    if url in arjun_results:
                        params = arjun_results[url].get(method, [])
                        
                        if params:
                            log(f"Arjun discovered {len(params)} hidden parameters: {', '.join(params)}", 'INFO')
                            return {
                                'parameters': params,
                                'method': method,
                                'url': url
                            }
                        else:
                            log("Arjun found no additional parameters", 'INFO')
                            return {'parameters': [], 'method': method, 'url': url}
                    else:
                        log("Arjun completed but found no parameters", 'INFO')
                        return {'parameters': [], 'method': method, 'url': url}
                        
                except json.JSONDecodeError:
                    log(f"Failed to parse Arjun output", 'WARN')
                    return {'parameters': [], 'method': method, 'url': url}
        else:
            log("Arjun produced no output", 'INFO')
            return {'parameters': [], 'method': method, 'url': url}
    
    except subprocess.TimeoutExpired:
        log(f"Arjun timeout after {timeout}s", 'WARN')
        return {'parameters': [], 'method': method, 'url': url}
    
    except FileNotFoundError:
        log("Arjun not installed. Install with: pip install arjun", 'ERROR')
        return {'parameters': [], 'method': method, 'url': url}
    
    except Exception as e:
        log(f"Arjun error: {str(e)}", 'ERROR')
        return {'parameters': [], 'method': method, 'url': url}
    
    finally:
        # Cleanup temp file
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except:
                pass


def discover_all_parameters(url: str, 
                           methods: List[str] = ['GET', 'POST'],
                           threads: int = 5) -> Dict[str, List[str]]:
    """
    Discover parameters for multiple HTTP methods
    
    Args:
        url: Target URL
        methods: List of HTTP methods to test
        threads: Number of threads
    
    Returns:
        Dictionary mapping methods to discovered parameters
    """
    all_params = {}
    
    for method in methods:
        result = discover_parameters(url, method=method, threads=threads)
        if result['parameters']:
            all_params[method] = result['parameters']
    
    return all_params


def merge_discovered_params(existing_params: Dict[str, List[str]], 
                           discovered_params: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Merge discovered parameters with existing ones
    
    Args:
        existing_params: Parameters already known (from URL parsing)
        discovered_params: Parameters found by Arjun
    
    Returns:
        Merged parameter dictionary
    """
    merged = existing_params.copy()
    
    for method, params in discovered_params.items():
        if method in merged:
            # Add new params, avoid duplicates
            existing = set(merged[method])
            merged[method] = list(existing.union(set(params)))
        else:
            merged[method] = params
    
    return merged
