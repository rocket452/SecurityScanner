#!/usr/bin/env python3
"""
Comprehensive Test for Breakout XSS Detection Integration

This test verifies that the breakout XSS detection system is properly
integrated and working with all enhanced features.

Usage:
    python3 tests/test_breakout_xss_integration.py
"""

import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


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


def test_module_imports():
    """Test 1: Verify all required modules can be imported"""
    print_header("TEST 1: Module Imports")
    
    modules_to_test = [
        ('scanners.xss_breakout_detector', 'detect_breakout_xss'),
        ('scanners.xss_breakout_integration', 'scan_url_for_breakout_xss'),
        ('scanners.xss_breakout_integration', 'format_breakout_vuln_for_report'),
        ('scanners.xss_breakout_scanner_patch', 'scan_for_breakout_xss'),
    ]
    
    passed = 0
    total = len(modules_to_test)
    
    for module_name, func_name in modules_to_test:
        try:
            module = __import__(module_name, fromlist=[func_name])
            if hasattr(module, func_name):
                print_result(f"{module_name}.{func_name}", True)
                passed += 1
            else:
                print_result(f"{module_name}.{func_name}", False, "Function not found")
        except ImportError as e:
            print_result(f"{module_name}.{func_name}", False, str(e))
        except Exception as e:
            print_result(f"{module_name}.{func_name}", False, f"Unexpected error: {e}")
    
    print(f"\n  Module Imports: {passed}/{total} successful")
    return passed == total


def test_scanner_integration_in_main():
    """Test 2: Verify scanner.py uses breakout XSS detection"""
    print_header("TEST 2: Scanner.py Integration")
    
    try:
        scanner_path = Path(__file__).parent.parent / 'scanner.py'
        
        if not scanner_path.exists():
            print_result("scanner.py exists", False, "File not found")
            return False
        
        with open(scanner_path, 'r', encoding='utf-8') as f:
            scanner_content = f.read()
        
        checks = [
            ('xss_breakout_scanner_patch import', 'from scanners.xss_breakout_scanner_patch import'),
            ('scan_for_breakout_xss call', 'scan_for_breakout_xss'),
            ('--xss-deep argument', '--xss-deep'),
            ('xss_deep flag check', 'if args.xss_deep:'),
        ]
        
        passed = 0
        for check_name, search_str in checks:
            if search_str in scanner_content:
                print_result(check_name, True)
                passed += 1
            else:
                print_result(check_name, False, f"'{search_str}' not found")
        
        print(f"\n  Scanner Integration: {passed}/{len(checks)} checks passed")
        return passed == len(checks)
        
    except Exception as e:
        print_result("Scanner integration check", False, str(e))
        return False


def test_html_report_template():
    """Test 3: Verify HTML report includes breakout XSS fields"""
    print_header("TEST 3: HTML Report Template")
    
    try:
        scanner_path = Path(__file__).parent.parent / 'scanner.py'
        
        if not scanner_path.exists():
            print_result("scanner.py exists", False)
            return False
        
        with open(scanner_path, 'r', encoding='utf-8') as f:
            scanner_content = f.read()
        
        # Check for breakout XSS specific HTML template fields
        checks = [
            ('context_type field', 'context_type'),
            ('context_snippet field', 'context_snippet'),
            ('encoding_layers field', 'encoding_layers'),
            ('breakout-context CSS', 'breakout-context'),
            ('context_description field', 'context_description'),
            ('Breakout Context header', 'Breakout Context'),
        ]
        
        passed = 0
        for check_name, search_str in checks:
            if search_str in scanner_content:
                print_result(check_name, True)
                passed += 1
            else:
                print_result(check_name, False, f"'{search_str}' not in template")
        
        print(f"\n  HTML Template: {passed}/{len(checks)} fields present")
        return passed >= len(checks) * 0.8  # 80% pass rate
        
    except Exception as e:
        print_result("HTML template check", False, str(e))
        return False


def test_integration_functions():
    """Test 4: Test the integration functions with mock data"""
    print_header("TEST 4: Integration Functions")
    
    try:
        from scanners.xss_breakout_integration import (
            format_breakout_vuln_for_report,
            extract_url_parameters
        )
        
        # Test URL parameter extraction
        test_url = "https://example.com/page?id=123&name=test&search=query"
        params = extract_url_parameters(test_url)
        
        if len(params) == 3:
            print_result("URL parameter extraction", True, f"Found {len(params)} parameters")
        else:
            print_result("URL parameter extraction", False, f"Expected 3, got {len(params)}")
        
        # Test vulnerability formatting
        mock_vuln = {
            'url': 'https://example.com/test',
            'parameter': 'search',
            'method': 'GET',
            'successful_payload': '"><script>alert(1)</script>',
            'context_type': 'html_attribute',
            'context_description': 'Reflected in HTML attribute',
            'context_snippet': '<input value="PAYLOAD">',
            'severity': 'high',
            'cvss_score': 7.5,
            'encoding_layers': ['HTML Entity'],
            'remediation': 'Use proper output encoding',
            'surrounding_code': '<div><input value="PAYLOAD"></div>'
        }
        
        formatted = format_breakout_vuln_for_report(mock_vuln)
        
        required_fields = ['type', 'description', 'severity', 'url', 'parameter', 
                          'method', 'payload', 'context_type']
        
        missing_fields = [f for f in required_fields if f not in formatted]
        
        if not missing_fields:
            print_result("Vulnerability formatting", True, "All required fields present")
            return True
        else:
            print_result("Vulnerability formatting", False, f"Missing: {missing_fields}")
            return False
        
    except Exception as e:
        print_result("Integration functions", False, str(e))
        return False


def test_file_structure():
    """Test 5: Verify all required files exist"""
    print_header("TEST 5: File Structure")
    
    base_path = Path(__file__).parent.parent
    
    required_files = [
        'scanner.py',
        'scanners/xss_breakout_detector.py',
        'scanners/xss_breakout_integration.py',
        'scanners/xss_breakout_scanner_patch.py',
        'scanners/xss_scanner.py',
        'scanners/xss_advanced.py',
    ]
    
    passed = 0
    for file_path in required_files:
        full_path = base_path / file_path
        if full_path.exists():
            size = full_path.stat().st_size
            print_result(file_path, True, f"{size:,} bytes")
            passed += 1
        else:
            print_result(file_path, False, "File not found")
    
    print(f"\n  File Structure: {passed}/{len(required_files)} files found")
    return passed == len(required_files)


def test_xss_mode_argument():
    """Test 6: Verify XSS mode arguments are properly configured"""
    print_header("TEST 6: XSS Mode Arguments")
    
    try:
        scanner_path = Path(__file__).parent.parent / 'scanner.py'
        
        with open(scanner_path, 'r', encoding='utf-8') as f:
            scanner_content = f.read()
        
        checks = [
            ('--xss-mode argument', '--xss-mode'),
            ('XSS mode choices', "choices=['basic', 'advanced', 'exploitation']"),
            ('--xss-payloads argument', '--xss-payloads'),
            ('--xss-callback argument', '--xss-callback'),
            ('XSS mode logging', 'Enhanced Breakout XSS scanning'),
        ]
        
        passed = 0
        for check_name, search_str in checks:
            if search_str in scanner_content:
                print_result(check_name, True)
                passed += 1
            else:
                print_result(check_name, False)
        
        print(f"\n  XSS Arguments: {passed}/{len(checks)} configured")
        return passed >= len(checks) * 0.8
        
    except Exception as e:
        print_result("XSS mode arguments check", False, str(e))
        return False


def test_documentation_exists():
    """Test 7: Verify documentation files exist"""
    print_header("TEST 7: Documentation")
    
    base_path = Path(__file__).parent.parent
    
    doc_files = [
        'BREAKOUT_XSS_ENHANCEMENTS.md',
        'docs/BREAKOUT_XSS_GUIDE.md',
        'tests/README.md',
    ]
    
    passed = 0
    for doc_file in doc_files:
        full_path = base_path / doc_file
        if full_path.exists():
            size = full_path.stat().st_size
            print_result(doc_file, True, f"{size:,} bytes")
            passed += 1
        else:
            print_result(doc_file, False, "Not found (optional)")
    
    print(f"\n  Documentation: {passed}/{len(doc_files)} files found")
    return passed >= 1  # At least one doc file should exist


def run_all_tests():
    """Run all tests and provide summary"""
    print("\n" + "=" * 70)
    print("  BREAKOUT XSS INTEGRATION TEST SUITE")
    print("  Testing integration on codexBranch")
    print("=" * 70)
    
    tests = [
        ("Module Imports", test_module_imports),
        ("Scanner.py Integration", test_scanner_integration_in_main),
        ("HTML Report Template", test_html_report_template),
        ("Integration Functions", test_integration_functions),
        ("File Structure", test_file_structure),
        ("XSS Mode Arguments", test_xss_mode_argument),
        ("Documentation", test_documentation_exists),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Test '{test_name}' crashed: {e}")
            import traceback
            traceback.print_exc()
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
        print("\nYou can now use: python scanner.py <target> --xss-deep")
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
