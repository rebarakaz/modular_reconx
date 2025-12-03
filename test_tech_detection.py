#!/usr/bin/env python3
"""
Test script for the enhanced technology detection features
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.comprehensive_tech_detection import comprehensive_tech_detection

def test_comprehensive_tech_detection():
    """Test the comprehensive technology detection"""
    print("Testing comprehensive technology detection...")
    
    # Test with a known domain
    url = "https://github.com"
    domain = "github.com"
    
    print(f"Testing technology detection for {url}")
    results = comprehensive_tech_detection(url, domain)
    
    print(f"\nResults for {url}:")
    print(f"Domain: {results.get('domain', 'N/A')}")
    
    # Show consolidated results
    consolidated = results.get("consolidated", {})
    if consolidated:
        print("\nConsolidated Results:")
        for category, items in consolidated.items():
            if items:
                print(f"  {category.capitalize()}: {', '.join(items)}")
    
    # Show method-specific results
    methods = results.get("methods", {})
    print("\nMethod-Specific Results:")
    for method, method_results in methods.items():
        if isinstance(method_results, dict) and "error" not in method_results:
            print(f"  {method}: Success")
        elif isinstance(method_results, dict) and "error" in method_results:
            print(f"  {method}: Error - {method_results['error']}")
        else:
            print(f"  {method}: {method_results}")
    
    print("\nComprehensive technology detection tests completed!")

if __name__ == "__main__":
    test_comprehensive_tech_detection()