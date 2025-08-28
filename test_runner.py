#!/usr/bin/env python3
"""
Test runner for pyIKEv2
"""

import sys
import os
import unittest

# Add the project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_tests():
    """Run all tests and report results"""
    
    print("="*60)
    print("pyIKEv2 Test Suite")
    print("="*60)
    
    # Import the test module directly
    from pyikev2 import tests
    
    # Load tests from the module
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    print("Test Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed!")
        
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(run_tests())