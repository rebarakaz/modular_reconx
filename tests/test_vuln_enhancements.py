#!/usr/bin/env python3
"""
Test script for the enhanced vulnerability scanning features
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.exploit_db import search_exploits_by_technology, search_exploits_by_cve
from app.modules.vuln_scanner import check_versioned_vulnerabilities

def test_exploit_database():
    """Test the local exploit database functionality"""
    print("Testing local exploit database...")
    
    # Test searching exploits by technology
    print("\n1. Testing search by technology:")
    exploits = search_exploits_by_technology("apache", "2.4.49")
    print(f"Found {len(exploits)} exploits for Apache 2.4.49")
    for exploit in exploits:
        print(f"  - {exploit['title']} ({exploit['id']})")
    
    # Test searching exploits by CVE
    print("\n2. Testing search by CVE:")
    exploits = search_exploits_by_cve("CVE-2021-44228")
    print(f"Found {len(exploits)} exploits for CVE-2021-44228")
    for exploit in exploits:
        print(f"  - {exploit['title']} ({exploit['id']})")
    
    print("\nLocal exploit database tests completed!")

def test_enhanced_vuln_scanning():
    """Test the enhanced vulnerability scanning"""
    print("\nTesting enhanced vulnerability scanning...")
    
    # Mock technology data
    tech_info = {
        "web-servers": ["Apache/2.4.49"]
    }
    
    tech_stack = {
        "server": "Apache/2.4.49"
    }
    
    # Test versioned vulnerability checking
    print("\n1. Testing versioned vulnerability checking:")
    results = check_versioned_vulnerabilities(tech_info, tech_stack)
    
    if "note" in results:
        print(f"Note: {results['note']}")
    else:
        vulns = results.get("vulnerabilities", {})
        exploits = results.get("exploits", {})
        
        print(f"Found {sum(len(v) for v in vulns.values() if isinstance(v, list))} vulnerabilities")
        print(f"Found {sum(len(v) for v in exploits.values() if isinstance(v, list))} exploits")
        
        # Show some results
        for tech, vuln_list in vulns.items():
            if isinstance(vuln_list, list) and vuln_list:
                print(f"\nVulnerabilities for {tech}:")
                for vuln in vuln_list[:2]:  # Show first 2
                    print(f"  - {vuln.get('title', 'N/A')} ({vuln.get('id', 'N/A')})")
        
        for tech, exploit_list in exploits.items():
            if isinstance(exploit_list, list) and exploit_list:
                print(f"\nExploits for {tech}:")
                for exploit in exploit_list[:2]:  # Show first 2
                    print(f"  - {exploit.get('title', 'N/A')} ({exploit.get('id', 'N/A')})")
    
    print("\nEnhanced vulnerability scanning tests completed!")

if __name__ == "__main__":
    test_exploit_database()
    test_enhanced_vuln_scanning()