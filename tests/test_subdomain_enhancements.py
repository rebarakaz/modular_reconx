#!/usr/bin/env python3
"""
Test script for the enhanced subdomain enumeration features
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.subdomain_enum import enumerate_subdomains
from app.modules.subdomain_permutation import discover_permutation_subdomains
from app.modules.utils import get_resource_path

def test_enhanced_subdomain_enum():
    """Test the enhanced subdomain enumeration features"""
    print("Testing enhanced subdomain enumeration...")
    
    # Test with a known domain
    domain = "github.com"
    
    # Test regular enumeration with enhanced wordlist
    print(f"Testing regular enumeration with enhanced wordlist for {domain}")
    result = enumerate_subdomains(
        domain=domain,
        use_enhanced_wordlist=True,
        workers=10,  # Use fewer workers for testing
        record_types=["A", "AAAA", "CNAME", "MX"]
    )
    
    if "found" in result:
        print(f"Found {len(result['found'])} subdomains")
        for subdomain in result["found"][:5]:  # Show first 5
            print(f"  - {subdomain['subdomain']}: {subdomain.get('ips', [])}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")
    
    # Test permutation-based discovery
    print(f"\nTesting permutation-based discovery for {domain}")
    result = discover_permutation_subdomains(
        domain=domain,
        wordlist_path=get_resource_path("data/subdomains.txt"),
        workers=10,  # Use fewer workers for testing
        record_types=["A", "AAAA", "CNAME"]
    )
    
    if "found" in result:
        print(f"Found {len(result['found'])} permutation subdomains")
        for subdomain in result["found"][:5]:  # Show first 5
            print(f"  - {subdomain['subdomain']}: {subdomain.get('ips', [])}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")
    
    print("Enhanced subdomain enumeration tests completed!")

if __name__ == "__main__":
    test_enhanced_subdomain_enum()