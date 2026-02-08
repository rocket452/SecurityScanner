# Breakout XSS Detection Guide

This guide explains how to use the enhanced XSS Breakout Detection feature in SecurityScanner.

## Overview

Breakout XSS occurs when user input is embedded within a restrictive context (like a JavaScript string or HTML attribute) where simple XSS payloads are blocked, but context-specific "breakout" payloads can escape the context and execute arbitrary code.

### What Makes This Different?

Traditional XSS scanners test if payloads like `<script>alert(1)</script>` work. Breakout detection identifies scenarios where:

1. **Simple payloads are blocked** (HTML-encoded or filtered)
2. **Context-aware payloads succeed** by breaking out of the embedding context

### Example Breakout Scenarios

#### JavaScript String Context
```javascript
// Vulnerable code:
var search = 'USER_INPUT';

// Simple payload fails:
var search = '<script>alert(1)</script>';  // Just a string, doesn't execute

// Breakout payload succeeds:
var search = ''; alert(1); //';
```

#### HTML Attribute Context
```html
<!-- Vulnerable code: -->
<input value="USER_INPUT">

<!-- Simple payload fails (HTML encoded): -->
<input value="&lt;script&gt;alert(1)&lt;/script&gt;">

<!-- Breakout payload succeeds: -->
<input value="" onload="alert(1)">
```

## Features

### Supported Context Detection

- **JavaScript string contexts** (single/double quotes)
- **JavaScript template literals** (backticks)
- **JSON value contexts**
- **Script tag content**
- **HTML attribute values**
- **Event handler attributes**

### Advanced Capabilities

1. **Multi-layer encoding detection** - Identifies URL, HTML, Unicode, and JS escaping
2. **WAF bypass payloads** - Includes encoded variations to bypass filters
3. **Callback-based blind XSS** - Test with external callback URLs
4. **Comprehensive parameter discovery** - Integrates with Arjun for hidden params
5. **Detailed exploitation steps** - Generates curl commands and browser instructions

## Usage

### Basic Breakout XSS Scan

```bash
# Scan a single URL with breakout detection
python scanner.py example.com --xss-deep
```

### With Blind XSS Callback

```bash
# Use callback URL for blind XSS detection
python scanner.py example.com --xss-deep --xss-callback https://webhook.site/your-id
```

### Scan HackerOne Program

```bash
# Scan entire bug bounty program scope
python scanner.py --fetch-scope --h1-program github --xss-deep
```

### Integration with Existing Code

If you're integrating the breakout detector into your own scanner:

```python
from scanners.xss_breakout_detector import detect_breakout_xss

# Test a specific parameter
vuln = detect_breakout_xss(
    url='https://example.com/search',
    param_name='q',
    method='GET',
    timeout=10,
    callback_url='https://your-callback.com'
)

if vuln:
    print(f"Found breakout XSS in {vuln['context_type']} context")
    print(f"Payload: {vuln['successful_payload']}")
    print(f"Curl: {vuln['exploitation']['curl_command']}")
```

### Use the Integration Module

For comprehensive scanning with parameter discovery:

```python
from scanners.xss_breakout_integration import scan_url_for_breakout_xss

# Automatically discover and test all parameters
vulns = scan_url_for_breakout_xss(
    url='https://example.com/page',
    use_arjun=True,  # Discover hidden parameters
    timeout=10,
    callback_url=None
)

for vuln in vulns:
    print(f"Breakout XSS: {vuln['parameter']} ({vuln['method']})")
    print(f"Context: {vuln['context_description']}")
```

## Modifying scanner.py

To integrate breakout detection into your main scanner, update `scan_single_domain_for_vulnerabilities()`:

```python
def scan_single_domain_for_vulnerabilities(url, args, skip_nuclei=False):
    vulns = []
    
    # ... existing scanner code ...
    
    # XSS vulnerability detection - Use breakout scanner if --xss-deep is enabled
    if args.xss_deep:
        from scanners.xss_breakout_scanner_patch import scan_for_breakout_xss
        
        # Get XSS configuration
        xss_timeout = CONFIG.get('xss', {}).get('timeout', 10)
        xss_callback = args.xss_callback or CONFIG.get('xss', {}).get('callback_url')
        
        log(f'Running advanced breakout XSS scan on {url}', 'INFO')
        
        breakout_vulns = scan_for_breakout_xss(
            url=url,
            args=args,
            timeout=xss_timeout,
            callback_url=xss_callback
        )
        
        vulns.extend(breakout_vulns)
    else:
        # Use basic XSS scanner
        from scanners.xss_scanner import check_xss
        xss_vulns = check_xss(url)
        if xss_vulns:
            for xss_vuln in xss_vulns:
                xss_vuln['url'] = url
            vulns.extend(xss_vulns)
    
    # ... rest of scanner code ...
    
    return vulns
```

## Understanding the Output

### Vulnerability Report Fields

When a breakout XSS is detected, the report includes:

- **context_type** - The specific context (e.g., `js_string_single`, `html_attribute_double`)
- **context_description** - Human-readable explanation
- **surrounding_code** - The actual code pattern found in the response
- **context_snippet** - 100 chars before/after showing input position
- **required_escape** - What needs to be escaped to break out
- **successful_payload** - The exact payload that worked
- **encoding_layers** - List of detected encodings (URL, HTML, Unicode, etc.)
- **exploitation.curl_command** - Ready-to-use curl command
- **exploitation.browser_steps** - Step-by-step browser reproduction
- **remediation** - Context-specific fix recommendations

### Example Report Output

```json
{
  "vulnerability_type": "breakout_xss",
  "context_type": "js_string_single",
  "context_description": "JavaScript string with single quotes (e.g., var x = 'USER_INPUT')",
  "parameter": "search",
  "method": "GET",
  "surrounding_code": "var searchTerm = 'user input here';",
  "context_snippet": "<script>var searchTerm = '>>>__BREAKOUT_TEST_MARKER_abc123__<<<'; </script>",
  "required_escape": "Single quote (') and script tag closure",
  "successful_payload": "'</script><script>alert('XSS')</script>",
  "encoding_layers": [],
  "severity": "high",
  "cvss_score": 7.5,
  "remediation": "Properly escape JavaScript strings using JSON.stringify()...",
  "exploitation": {
    "curl_command": "curl -X GET 'https://example.com/search?q=%27%3C/script%3E...'",
    "explanation": "This vulnerability requires breaking out of a JavaScript string...",
    "browser_steps": [
      "Open browser and navigate to: https://example.com/search?q=...",
      "Observe that the XSS payload executes despite context restrictions"
    ]
  }
}
```

## Payload Examples

### Template Literal Breakout
```javascript
// Context: const name = `USER_INPUT`;
${alert(1)}
${document.location="javascript:alert(1)"}
```

### JSON Context Breakout
```javascript
// Context: {"name": "USER_INPUT"}
\"></script><script>alert(1)</script><script x=\"
```

### Event Handler Breakout
```html
<!-- Context: <div onclick="handler('USER_INPUT')"> -->
');alert(1);//
```

## Configuration

Add to your `config.yaml`:

```yaml
xss:
  mode: advanced  # basic, advanced, or exploitation
  timeout: 10
  callback_url: https://your-callback-server.com/endpoint
```

## Tips for Bug Bounty Hunters

1. **Always test with --xss-deep** on forms and search functionality
2. **Use callback URLs** for blind XSS detection on delayed/async contexts
3. **Check the encoding_layers field** - multiple encodings often indicate complex filters
4. **Read the surrounding_code field** - helps understand the application's context
5. **Use the curl_command** in your report for easy reproduction

## Troubleshooting

### No Parameters Detected

If no parameters are found:
- Ensure the URL contains query parameters (`?param=value`)
- Enable Arjun with `--xss-deep` (enabled by default)
- Check if the page has forms (POST parameters auto-detected)

### False Negatives

If you suspect XSS but it's not detected:
- Try manual testing with the generated payloads
- Check if WAF/filtering is too aggressive
- Review the context_snippet to understand how input is embedded
- Consider DOM-based XSS (requires browser testing)

### Performance

Breakout detection is thorough but slower than basic XSS scanning:
- Each parameter requires 3-10 HTTP requests
- Use `--skip-nuclei` to speed up overall scans
- Limit scope with specific URLs rather than entire domains

## Architecture

### Module Structure

```
scanners/
├── xss_breakout_detector.py       # Core detection engine
├── xss_breakout_integration.py    # Parameter discovery & workflow
├── xss_breakout_scanner_patch.py  # Main scanner integration
└── param_discovery.py             # Arjun integration for hidden params
```

### Detection Workflow

1. **Marker Injection** - Send unique marker to identify reflection
2. **Context Analysis** - Regex patterns identify embedding context
3. **Encoding Detection** - Check for URL/HTML/Unicode/JS escaping
4. **Simple Payload Test** - Verify simple payloads are blocked
5. **Breakout Payload Test** - Try context-specific escape sequences
6. **Validation** - Confirm payload appears unencoded in response
7. **Report Generation** - Create detailed exploitation guide

## Contributing

To add new context patterns:

1. Add detection regex to `BreakoutContextAnalyzer.find_reflection_context()`
2. Create payload generator method in `BreakoutPayloadGenerator`
3. Add context description to `get_context_description()`
4. Add remediation advice to `generate_remediation()`
5. Update `is_breakout_successful()` validation logic

## References

- [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
- [PortSwigger XSS Contexts](https://portswigger.net/web-security/cross-site-scripting/contexts)
- [HackerOne XSS Reports](https://hackerone.com/hacktivity?querystring=xss)

## License

Part of SecurityScanner - see main repository LICENSE
