# SecurityScanner Tests

## Breakout XSS Integration Test

This directory contains comprehensive tests for the breakout XSS detection system.

### Running the Test Suite

```bash
# From the SecurityScanner root directory
python3 tests/test_breakout_xss_integration.py
python3 -m unittest tests/test_svg_allowlist_strategy.py
```

### What the Tests Cover

The test suite verifies:

1. **Detector Initialization** - Ensures the BreakoutXSSDetector class can be instantiated
2. **Context Detection** - Tests detection of various injection contexts:
   - HTML attributes (with quotes)
   - JavaScript strings
   - JSON contexts
   - HTML text nodes
   - Template literals
   - URL contexts

3. **Encoding Detection** - Verifies detection of encoding layers:
   - HTML entity encoding
   - Hex encoding
   - URL encoding
   - Unicode encoding

4. **Payload Generation** - Tests context-aware payload generation for different scenarios

5. **Vulnerability Formatting** - Ensures vulnerabilities include all required fields:
   - Basic fields (type, description, severity, URL, parameter)
   - Enhanced fields (context_snippet, encoding_layers, exploitation details)
   - CVSS scoring

6. **Scanner Integration** - Verifies the integration with the main scanner works correctly

7. **HTML Report Template** - Checks that HTML reports include breakout XSS specific fields

### Expected Output

```
======================================================================
  BREAKOUT XSS INTEGRATION TEST SUITE
======================================================================

======================================================================
  TEST 1: Detector Initialization
======================================================================
✅ PASS: BreakoutXSSDetector initialization
✅ PASS: Has detect_context method
✅ PASS: Has analyze_response method
✅ PASS: Has test_breakout method

... (more test output) ...

======================================================================
  TEST SUMMARY
======================================================================
✅ PASS: Detector Initialization
✅ PASS: Context Detection
✅ PASS: Encoding Detection
✅ PASS: Payload Generation
✅ PASS: Vulnerability Formatting
✅ PASS: Scanner Integration
✅ PASS: HTML Report Template

======================================================================
  OVERALL: 7/7 tests passed (100.0%)
======================================================================

🎉 ALL TESTS PASSED! Breakout XSS detection is fully integrated.
```

### Test Results Interpretation

- **100% Pass**: Breakout XSS detection is fully integrated and working
- **70-99% Pass**: Integration is mostly working with minor issues
- **Below 70%**: Significant integration problems that need attention

### Testing Against Live Targets

To test the actual scanner against a vulnerable target:

```bash
# Test basic XSS detection
python3 scanner.py http://testphp.vulnweb.com --xss-deep

# Test with HTML report generation
python3 scanner.py http://testphp.vulnweb.com --xss-deep -f html

# Test exploitation mode with callback
python3 scanner.py http://testphp.vulnweb.com --xss-deep --xss-mode exploitation --xss-callback https://webhook.site/your-id
```

### Debugging Test Failures

If tests fail, check:

1. **Import Errors**: Ensure all dependencies are installed
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Missing Modules**: Verify all scanner modules exist:
   - `scanners/xss_breakout_detector.py`
   - `scanners/xss_breakout_integration.py`
   - `scanners/xss_breakout_scanner_patch.py`

3. **Python Version**: Tests require Python 3.8+
   ```bash
   python3 --version
   ```

### Creating Additional Tests

To add new tests, follow this pattern:

```python
def test_new_feature():
    """Test description"""
    print_header("TEST N: Feature Name")
    
    try:
        # Your test code here
        result = some_function()
        
        if result == expected:
            print_result("Test name", True)
            return True
        else:
            print_result("Test name", False, "Details")
            return False
    except Exception as e:
        print_result("Test name", False, str(e))
        return False
```

Then add it to the `tests` list in `run_all_tests()`.

### CI/CD Integration

To integrate with CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Breakout XSS Tests
  run: |
    python3 tests/test_breakout_xss_integration.py
    if [ $? -eq 0 ]; then
      echo "All tests passed"
    else
      echo "Tests failed"
      exit 1
    fi
```

### Troubleshooting

**Issue**: ImportError for scanner modules  
**Solution**: Run tests from the root directory, not from within tests/

**Issue**: Tests pass but scanner doesn't show enhanced details  
**Solution**: Ensure you're using the `--xss-deep` flag when running the scanner

**Issue**: Context detection tests failing  
**Solution**: This might indicate the detector logic needs adjustment for specific contexts

### Support

For issues or questions about the tests, check:
- `docs/BREAKOUT_XSS_GUIDE.md` - Comprehensive usage guide
- `BREAKOUT_XSS_ENHANCEMENTS.md` - Feature documentation
- Scanner integration code at line ~1100 in `scanner.py`
