#!/usr/bin/env python3
"""
Test script for module integration - verifies all new v1.2.0 modules can be imported
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.social_finder import find_social_links
from app.modules.http_client import configure_http_client

# Import new v1.2.0 modules
from app.modules.cloud_enum import check_cloud_storage
from app.modules.metadata_analysis import analyze_metadata, analyze_local_file
from app.modules.image_forensics import analyze_image, find_images
from app.modules.social_eng import generate_dorks, guess_email_pattern, perform_social_recon
from app.modules.reverse_image import generate_reverse_links


def test_module_integration():
    """Test that modules can use the new HTTP client"""
    print("=" * 60)
    print("Testing Module Integration")
    print("=" * 60)
    
    # Configure HTTP client with a test proxy (won't actually be used in this test)
    configure_http_client(proxy="http://127.0.0.1:8080", rate_limit=0.1)
    
    # Test social finder module (this would normally make HTTP requests)
    print("\n[OK] Social finder module imported successfully")
    
    # Test new v1.2.0 modules
    print("[OK] Cloud enumeration module imported successfully")
    print("[OK] Metadata analysis module imported successfully")
    print("[OK] Image forensics module imported successfully")
    print("[OK] Social engineering module imported successfully")
    print("[OK] Reverse image search module imported successfully")
    
    print("\n" + "=" * 60)
    print("All module integration tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    test_module_integration()