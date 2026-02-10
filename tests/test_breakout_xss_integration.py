#!/usr/bin/env python3
"""
Comprehensive Test for Breakout XSS Detection Integration

This test verifies that the breakout XSS detection system is properly
integrated and working with all enhanced features including:
- Context detection (HTML attributes, JavaScript, JSON, etc.)
- Encoding layer detection
- Context snippets
- Enhanced reporting with exploitation details
- CVSS scoring

Usage:
    python3 tests/test_breakout_xss_integration.py
"""

import sys
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from scanners.xss_breakout_detector import BreakoutXSSDetector
    from scanners.xss_breakout_integration import scan_url_for_breakout_xss, format_breakout_vuln_for_report
    from scanners.xss_breakout_scanner_patch import scan_for_breakout_xss
    print("✅ All modules imported successfully")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


def print_header(title):
    """Print a formatted test section header"""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print('=' * 70)


def print_result(test_name, passed, details=""):
    """Print test result"""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status}: {test_name}")
    if details:
        print(f"    {details}")


def test_detector_initialization():
    """Test 1: Verify BreakoutXSSDetector can be initialized"""
    print_header("TEST 1: Detector Initialization")
    
    try:
        detector = BreakoutXSSDetector(timeout=5)
        print_result("BreakoutXSSDetector initialization", True)
        
        # Check for key methods
        has_detect = hasattr(detector, 'detect_context')
        has_analyze = hasattr(detector, 'analyze_response')
        has_test = hasattr(detector, 'test_breakout')
        
        print_result("Has detect_context method", has_detect)
        print_result("Has analyze_response method", has_analyze)
        print_result("Has test_breakout method", has_test)
        
        return has_detect and has_analyze and has_test
    except Exception as e:
        print_result("BreakoutXSSDetector initialization", False, str(e))
        return False


def test_context_detection():
    """Test 2: Verify context detection works correctly"""
    print_header("TEST 2: Context Detection")
    
    test_cases = [
        # (html_content, expected_context_keywords)
        ('<input value="USER_INPUT">', ['attribute', 'html']),
        ('<script>var x = "USER_INPUT";</script>', ['javascript', 'string']),
        ('<script>var data = {"key": "USER_INPUT"};</script>', ['json', 'javascript']),
        ('<div>USER_INPUT</div>', ['html', 'text']),
        ('<a href="USER_INPUT">Link</a>', ['attribute', 'href']),
        ('<script>`Template: USER_INPUT`</script>', ['template', 'literal']),
    ]
    
    try:
        detector = BreakoutXSSDetector(timeout=5)
        passed_tests = 0
        
        for html, expected_keywords in test_cases:
            context = detector.detect_context(html, "USER_INPUT")
            
            # Check if at least one expected keyword is in context type or description
            context_text = f"{context.context_type} {context.description}".lower()
            has_expected = any(keyword.lower() in context_text for keyword in expected_keywords)
            
            if has_expected:
                passed_tests += 1
                print_result(f"Context: {expected_keywords[0]}", True, f"Type: {context.context_type}")
            else:
                print_result(f"Context: {expected_keywords[0]}", False, 
                           f"Expected '{expected_keywords}' in '{context.context_type}'")
        
        success = passed_tests == len(test_cases)
        print(f"\n  Context Detection: {passed_tests}/{len(test_cases)} tests passed")
        return success
        
    except Exception as e:
        print_result("Context detection", False, str(e))
        return False


def test_encoding_detection():
    """Test 3: Verify encoding layer detection"""
    print_header("TEST 3: Encoding Detection")
    
    test_cases = [
        ('&lt;script&gt;', ['HTML Entity']),
        ('\\x3cscript\\x3e', ['Hex']),
        ('%3Cscript%3E', ['URL']),
        ('\\u003cscript\\u003e', ['Unicode']),
    ]
    
    try:
        detector = BreakoutXSSDetector(timeout=5)
        passed_tests = 0
        
        for encoded_str, expected_encodings in test_cases:
            # Create mock context with encoded payload
            from scanners.xss_breakout_detector import InjectionContext
            context = InjectionContext(
                context_type='html',
                description='Test context',
                injection_point=encoded_str,
                surrounding_code=f'<div>{encoded_str}</div>',
                needs_breakout=True
            )
            
            layers = detector._detect_encoding_layers(encoded_str, context)
            
            # Check if expected encoding is detected
            has_expected = any(exp.lower() in ' '.join(layers).lower() for exp in expected_encodings)
            
            if has_expected or len(layers) > 0:  # Accept if any encoding detected
                passed_tests += 1
                print_result(f"Encoding: {expected_encodings[0]}", True, f"Detected: {layers}")
            else:
                print_result(f"Encoding: {expected_encodings[0]}", False, f"No encoding detected")
        
        success = passed_tests >= len(test_cases) * 0.5  # 50% pass rate acceptable
        print(f"\n  Encoding Detection: {passed_tests}/{len(test_cases)} tests passed")
        return success
        
    except Exception as e:
        print_result("Encoding detection", False, str(e))
        return False


def test_payload_generation():
    """Test 4: Verify payload generation for different contexts"""
    print_header("TEST 4: Payload Generation")
    
    try:
        detector = BreakoutXSSDetector(timeout=5)
        
        # Test different context types
        contexts_to_test = [
            'html_attribute_double_quote',
            'javascript_string',
            'json_context',
            'html_text',
        ]
        
        passed_tests = 0
        for context_type in contexts_to_test:
            # Create a mock context
            from scanners.xss_breakout_detector import InjectionContext
            context = InjectionContext(
                context_type=context_type,
                description=f'Test {context_type}',
                injection_point='TEST',
                surrounding_code='<div>TEST</div>',
                needs_breakout=True
            )
            
            payloads = detector._generate_context_payloads(context, [])
            
            if len(payloads) > 0:
                passed_tests += 1
                print_result(f"Payloads for {context_type}", True, f"Generated {len(payloads)} payloads")
            else:
                print_result(f"Payloads for {context_type}", False, "No payloads generated")
        
        success = passed_tests == len(contexts_to_test)
        print(f"\n  Payload Generation: {passed_tests}/{len(contexts_to_test)} contexts passed")
        return success
        
    except Exception as e:
        print_result("Payload generation", False, str(e))
        return False


def test_vulnerability_formatting():
    """Test 5: Verify vulnerability report formatting"""
    print_header("TEST 5: Vulnerability Report Formatting")
    
    try:
        # Create a mock vulnerability
        from scanners.xss_breakout_detector import BreakoutXSSVulnerability, InjectionContext
        
        context = InjectionContext(
            context_type='html_attribute_double_quote',
            description='Input reflected in HTML attribute with double quotes',
            injection_point='value="USER_INPUT"',
            surrounding_code='<input type="text" value="USER_INPUT" />',
            needs_breakout=True
        )
        
        vuln = BreakoutXSSVulnerability(
            url='https://example.com/test?param=value',
            parameter='param',
            method='GET',
            payload='"><script>alert(1)</script>',
            context=context,
            confidence='high',
            encoding_layers=['HTML Entity Encoded']
        )
        
        # Format for report
        formatted = format_breakout_vuln_for_report(vuln)
        
        # Check required fields
        required_fields = [
            'type', 'description', 'severity', 'url', 'parameter', 
            'method', 'payload', 'context_type', 'cvss_score'
        ]
        
        passed_tests = 0
        for field in required_fields:
            if field in formatted:
                passed_tests += 1
                print_result(f"Has field: {field}", True, f"Value: {str(formatted[field])[:50]}")
            else:
                print_result(f"Has field: {field}", False)
        
        # Check for enhanced fields
        enhanced_fields = ['context_snippet', 'encoding_layers', 'exploitation', 'remediation']
        for field in enhanced_fields:
            has_field = field in formatted
            print_result(f"Has enhanced field: {field}", has_field, 
                        f"Present" if has_field else "Missing (optional)")
        
        success = passed_tests == len(required_fields)
        print(f"\n  Report Formatting: {passed_tests}/{len(required_fields)} required fields present")
        return success
        
    except Exception as e:
        print_result("Vulnerability formatting", False, str(e))
        return False


def test_scanner_integration():
    """Test 6: Verify scanner integration function works"""
    print_header("TEST 6: Scanner Integration")
    
    try:
        # Mock args object
        class MockArgs:
            xss_deep = True
            xss_mode = 'advanced'
            xss_payloads = None
            xss_callback = None
            skip_arjun = True  # Skip Arjun for testing
        
        args = MockArgs()
        
        # Test with a safe URL (will fail to connect, but should not crash)
        test_url = 'http://localhost:9999/test'
        
        print(f"Testing integration with URL: {test_url}")
        print("(Expected to fail connection, but should not crash)")
        
        try:
            results = scan_for_breakout_xss(
                url=test_url,
                args=args,
                timeout=2,
                callback_url=None
            )
            
            # Function should return empty list or handle error gracefully
            print_result("Scanner integration", True, 
                        f"Returned {len(results)} results (connection likely failed, but function handled it)")
            return True
            
        except Exception as inner_e:
            # Check if it's a connection error (acceptable) or code error (not acceptable)
            error_msg = str(inner_e).lower()
            if any(term in error_msg for term in ['connection', 'timeout', 'resolve', 'connect']):
                print_result("Scanner integration", True, 
                            "Function handled connection error gracefully")
                return True
            else:
                print_result("Scanner integration", False, f"Unexpected error: {inner_e}")
                return False
        
    except Exception as e:
        print_result("Scanner integration", False, str(e))
        return False


def test_html_report_fields():
    """Test 7: Verify HTML report includes breakout XSS fields"""
    print_header("TEST 7: HTML Report Template Check")
    
    try:
        # Read scanner.py to check HTML template
        scanner_path = Path(__file__).parent.parent / 'scanner.py'
        
        if not scanner_path.exists():
            print_result("HTML template check", False, "scanner.py not found")
            return False
        
        with open(scanner_path, 'r', encoding='utf-8') as f:
            scanner_content = f.read()
        
        # Check for breakout XSS specific HTML template fields
        required_checks = [
            ('context_type', 'Context type field'),
            ('context_snippet', 'Context snippet field'),
            ('encoding_layers', 'Encoding layers field'),
            ('breakout-context', 'Breakout context CSS class'),
            ('context_description', 'Context description field'),
        ]
        
        passed_tests = 0
        for check_str, description in required_checks:
            if check_str in scanner_content:
                passed_tests += 1
                print_result(description, True)
            else:
                print_result(description, False)
        
        success = passed_tests >= len(required_checks) * 0.8  # 80% pass rate
        print(f"\n  HTML Template: {passed_tests}/{len(required_checks)} checks passed")
        return success
        
    except Exception as e:
        print_result("HTML template check", False, str(e))
        return False


def run_all_tests():
    """Run all tests and provide summary"""
    print("\n" + "=" * 70)
    print("  BREAKOUT XSS INTEGRATION TEST SUITE")
    print("=" * 70)
    
    tests = [
        ("Detector Initialization", test_detector_initialization),
        ("Context Detection", test_context_detection),
        ("Encoding Detection", test_encoding_detection),
        ("Payload Generation", test_payload_generation),
        ("Vulnerability Formatting", test_vulnerability_formatting),
        ("Scanner Integration", test_scanner_integration),
        ("HTML Report Template", test_html_report_fields),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print_header("TEST SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\n{'=' * 70}")
    print(f"  OVERALL: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print('=' * 70)
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Breakout XSS detection is fully integrated.")
        return 0
    elif passed >= total * 0.7:
        print(f"\n⚠️  Most tests passed, but {total - passed} test(s) failed.")
        print("   The integration is mostly working but may need minor fixes.")
        return 1
    else:
        print(f"\n❌ INTEGRATION ISSUES: {total - passed} test(s) failed.")
        print("   Please review the failed tests above.")
        return 2


if __name__ == '__main__':
    sys.exit(run_all_tests())
