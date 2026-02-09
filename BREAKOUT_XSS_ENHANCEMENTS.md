# Breakout XSS Detection - Implementation Summary

## What Was Implemented

This branch adds comprehensive **context-aware XSS breakout detection** to SecurityScanner. The implementation identifies XSS vulnerabilities that only work by escaping restrictive contexts where user input is embedded.

## New Files Added

### 1. Enhanced Core Detector
**File:** `scanners/xss_breakout_detector.py` (updated)

**Enhancements:**
- ✅ Template literal detection for modern JavaScript (backticks)
- ✅ JSON context detection and breakout payloads
- ✅ Multi-layer encoding detection (URL, HTML, Unicode, JS)
- ✅ WAF bypass payloads with encoding variations
- ✅ Callback URL support for blind XSS testing
- ✅ Enhanced context patterns for `const`/`let` variables
- ✅ Browser reproduction step generation
- ✅ CVSS scoring for breakout vulnerabilities

**Key Methods:**
```python
# Main detection function
detect_breakout_xss(url, param_name, method, form_data, timeout, callback_url)

# Context analysis with encoding detection
BreakoutContextAnalyzer.find_reflection_context(html, marker, response_headers)

# Multi-layer encoding detection
BreakoutContextAnalyzer.detect_encoding_layers(html, marker)

# New payload generators
BreakoutPayloadGenerator.get_template_literal_breakouts()
BreakoutPayloadGenerator.get_json_context_breakouts()
BreakoutPayloadGenerator.get_encoded_breakout_payloads()
```

### 2. Integration Module
**File:** `scanners/xss_breakout_integration.py` (new)

**Features:**
- Automatic parameter extraction from URLs
- HTML form field discovery
- Arjun integration for hidden parameter discovery
- Comprehensive parameter testing workflow
- Vulnerability formatting for main scanner

**Key Functions:**
```python
# Main scanning function
scan_url_for_breakout_xss(url, use_arjun, timeout, callback_url)

# Parameter discovery
extract_url_parameters(url)
discover_form_parameters(url, timeout)

# Report formatting
format_breakout_vuln_for_report(vuln)
```

### 3. Scanner Patch Module
**File:** `scanners/xss_breakout_scanner_patch.py` (new)

**Purpose:** Drop-in integration with main `scanner.py`

**Usage:**
```python
from scanners.xss_breakout_scanner_patch import scan_for_breakout_xss

# In scan_single_domain_for_vulnerabilities():
if args.xss_deep:
    breakout_vulns = scan_for_breakout_xss(url, args, timeout, callback_url)
    vulns.extend(breakout_vulns)
```

### 4. Documentation
**File:** `docs/BREAKOUT_XSS_GUIDE.md` (new)

Comprehensive 300+ line guide covering:
- Feature overview and examples
- Usage instructions
- Integration guide
- Payload examples for each context
- Troubleshooting tips
- Architecture documentation

## Enhanced Context Detection

### New Contexts Added

1. **JavaScript Template Literals**
   ```javascript
   const search = `USER_INPUT`;
   // Payload: ${alert(1)}
   ```

2. **JSON Value Contexts**
   ```json
   {"search": "USER_INPUT"}
   // Payload: \"></script><script>alert(1)</script><script x=\"
   ```

3. **Modern Variable Declarations**
   - Now detects `const` and `let` in addition to `var`
   - Improved regex patterns for complex scenarios

### Existing Contexts Enhanced

- JavaScript strings (single/double quotes) - **improved patterns**
- Script tag content - **case variation bypasses**
- HTML attributes - **additional injection techniques**
- Event handlers - **expression-based payloads**

## Encoding Detection System

### Detected Encoding Layers

1. **URL Encoding** - `%3C` instead of `<`
2. **HTML Encoding** - `&lt;` and `&#60;` variations
3. **Unicode Escaping** - `\u003c` in JavaScript
4. **JS String Escaping** - `\'` for quotes

### WAF Bypass Payloads

Added encoded payload variations:
```python
"'%3C/script%3E%3Cscript%3Ealert(1)%3C/script%3E"  # URL encoded
"'\\u003c/script\\u003e..."  # Unicode escaped
"';alert(String.fromCharCode(88,83,83));//"  # Character codes
"\"\x3c/script\x3e..."  # Hex encoded
```

## Blind XSS Support

Callback URL integration for testing delayed/async XSS:

```python
vuln = detect_breakout_xss(
    url='https://example.com',
    param_name='comment',
    callback_url='https://webhook.site/your-id'
)
# Replaces alert(1) with fetch(callback_url) in payloads
```

## Report Enhancements

### New Vulnerability Fields

```json
{
  "encoding_layers": ["url_encoded", "html_encoded"],
  "cvss_score": 7.5,
  "exploitation": {
    "curl_command": "curl -X GET '...'  ",
    "browser_steps": [
      "Step 1: Navigate to...",
      "Step 2: Enter payload..."
    ],
    "explanation": "Detailed how-it-works..."
  },
  "context_snippet": "Code showing input position with >>> markers <<<"
}
```

## Integration with Main Scanner

### Option 1: Manual Integration (Recommended)

Edit `scanner.py` function `scan_single_domain_for_vulnerabilities()` around line 1100:

```python
# BEFORE (existing code):
if args.xss_deep:
    from scanners.xss_advanced import advanced_xss_scan
    xss_vulns = advanced_xss_scan(url, mode=xss_mode, ...)

# AFTER (with breakout detection):
if args.xss_deep:
    from scanners.xss_breakout_scanner_patch import scan_for_breakout_xss
    
    xss_timeout = CONFIG.get('xss', {}).get('timeout', 10)
    xss_callback = args.xss_callback or CONFIG.get('xss', {}).get('callback_url')
    
    breakout_vulns = scan_for_breakout_xss(
        url=url,
        args=args,
        timeout=xss_timeout,
        callback_url=xss_callback
    )
    
    vulns.extend(breakout_vulns)
```

### Option 2: Standalone Usage

Use the modules directly without modifying scanner.py:

```python
from scanners.xss_breakout_integration import scan_url_for_breakout_xss

vulns = scan_url_for_breakout_xss(
    url='https://target.com/search?q=test',
    use_arjun=True,
    timeout=10,
    callback_url=None
)

for vuln in vulns:
    print(f"Found: {vuln['parameter']} in {vuln['context_type']} context")
```

## Testing

### Test the Enhanced Detector

```bash
# Test on a single URL with breakout detection
python -c "
from scanners.xss_breakout_detector import detect_breakout_xss

vuln = detect_breakout_xss(
    url='https://example.com/search?q=test',
    param_name='q',
    method='GET',
    timeout=10
)

if vuln:
    print('Breakout XSS found!')
    print(f'Context: {vuln[\"context_type\"]}')
    print(f'Payload: {vuln[\"successful_payload\"]}')
else:
    print('No breakout XSS detected')
"
```

### Test the Integration Module

```bash
# Comprehensive scan with parameter discovery
python -c "
from scanners.xss_breakout_integration import scan_url_for_breakout_xss

vulns = scan_url_for_breakout_xss(
    url='https://example.com/page',
    use_arjun=True,
    timeout=10
)

print(f'Found {len(vulns)} breakout XSS vulnerabilities')
for vuln in vulns:
    print(f'  - {vuln[\"parameter\"]} ({vuln[\"method\"]}): {vuln[\"context_type\"]}')
"
```

## Command-Line Usage

Once integrated with scanner.py:

```bash
# Basic breakout XSS scan
python scanner.py example.com --xss-deep

# With blind XSS callback
python scanner.py example.com --xss-deep --xss-callback https://webhook.site/your-id

# Scan HackerOne program with breakout detection
python scanner.py --fetch-scope --h1-program shopify --xss-deep

# Custom payload file + breakout detection
python scanner.py example.com --xss-deep --xss-payloads custom.txt
```

## Performance Considerations

### Request Overhead

- **Marker injection:** 1 request
- **Simple payload tests:** 4 requests (one per basic payload)
- **Breakout payload tests:** 3-8 requests (context-specific)
- **Total per parameter:** ~8-13 requests

### Optimization Tips

1. **Limit parameter scope** - Test specific parameters instead of full discovery
2. **Disable Arjun** - If you know the parameters, skip discovery
3. **Reduce timeout** - Use shorter timeouts for faster scanning
4. **Parallel scanning** - Process multiple URLs concurrently

## Key Improvements Over Basic XSS Scanning

| Feature | Basic XSS | Breakout XSS |
|---------|-----------|-------------|
| Context detection | ❌ No | ✅ Yes |
| Template literals | ❌ No | ✅ Yes |
| JSON contexts | ❌ No | ✅ Yes |
| Encoding detection | ❌ No | ✅ Yes |
| WAF bypass payloads | ❌ No | ✅ Yes |
| Blind XSS callbacks | ❌ No | ✅ Yes |
| Browser steps | ❌ No | ✅ Yes |
| CVSS scoring | ❌ No | ✅ Yes |
| Context remediation | ❌ Generic | ✅ Specific |

## Example Findings

### JavaScript String Breakout

**Detected Context:**
```javascript
var searchTerm = 'USER_INPUT';
```

**Successful Payload:**
```
'</script><script>alert(1)</script>
```

**Report Output:**
- Context Type: `js_string_single`
- Severity: High
- CVSS: 7.5
- Remediation: "Use JSON.stringify() for JavaScript string escaping"

### Template Literal Breakout

**Detected Context:**
```javascript
const message = `Welcome, USER_INPUT`;
```

**Successful Payload:**
```
${alert(1)}
```

**Report Output:**
- Context Type: `js_template_literal`
- Severity: High
- CVSS: 7.5
- Remediation: "Avoid template literals with user input; use textContent"

## Future Enhancements

### Planned Features

- [ ] DOM-based XSS detection with headless browser (Selenium/Playwright)
- [ ] React/Vue.js framework-specific contexts
- [ ] Custom regex pattern configuration
- [ ] Machine learning for context classification
- [ ] Automated CSP bypass detection

### Contributing

To add new contexts:
1. Add regex pattern to `find_reflection_context()`
2. Create payload generator method
3. Update context descriptions
4. Add test cases

## Credits

Enhancements implemented by SecurityScanner team
Based on OWASP XSS Prevention Cheat Sheet and PortSwigger research

## Support

For issues or questions:
- Check `docs/BREAKOUT_XSS_GUIDE.md` for detailed usage
- Review existing issues on GitHub
- Open new issue with reproducible example

---

**Branch:** `breakoutXSS`  
**Status:** Ready for testing and integration  
**Last Updated:** February 8, 2026
