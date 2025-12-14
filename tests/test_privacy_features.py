#!/usr/bin/env python3
"""
Test script for the privacy and security enhancements in Modular ReconX
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.http_client import HTTPClient, configure_http_client, get_http_client

def test_http_client():
    """Test the HTTP client with privacy features"""
    print("Testing HTTP client with privacy features...")
    
    # Test default client
    client = get_http_client()
    print(f"Default client: {type(client)}")
    
    # Test configuring client with proxy
    configure_http_client(proxy="http://127.0.0.1:8080", rate_limit=1.0)
    client = get_http_client()
    print(f"Configured client proxy: {client.proxy}")
    print(f"Configured client rate_limit: {client.rate_limit}")
    
    print("HTTP client tests completed successfully!")

if __name__ == "__main__":
    test_http_client()