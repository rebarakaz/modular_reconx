"""
API Endpoint Discovery Module for Modular ReconX
Discovers API endpoints and analyzes their security
"""

import re
import logging
from typing import Dict, Any, List
from .http_client import get_http_client

logger = logging.getLogger(__name__)

# Common API endpoint patterns
API_PATTERNS = [
    r"/api/v\d+/",
    r"/api/[a-zA-Z0-9_]+/",
    r"/rest/v\d+/",
    r"/v\d+/api/",
    r"/v\d+/[a-zA-Z0-9_]+/",
    r"/api/\w+",
    r"/rest/\w+",
    r"/graphql",
    r"/swagger",
    r"/docs",
    r"/openapi"
]

# Common HTTP methods
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Common API response content types
API_CONTENT_TYPES = [
    "application/json",
    "application/xml",
    "application/hal+json",
    "application/vnd.api+json"
]

def discover_api_endpoints_from_js(js_content: str) -> List[str]:
    """
    Discover API endpoints from JavaScript content.
    
    Args:
        js_content: JavaScript content to analyze
        
    Returns:
        List of discovered API endpoints
    """
    endpoints = []
    
    # Look for URL patterns in JavaScript
    url_patterns = [
        r"[\'\"](\/api\/[^\s\'\"<>]+)[\'\"]",
        r"[\'\"](\/v\d+\/[^\s\'\"<>]+)[\'\"]",
        r"[\'\"](\/rest\/[^\s\'\"<>]+)[\'\"]",
        r"[\'\"](\/graphql[^\s\'\"<>]*)[\'\"]"
    ]
    
    for pattern in url_patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        endpoints.extend(matches)
    
    # Remove duplicates and clean up
    endpoints = list(set(endpoints))
    endpoints = [endpoint for endpoint in endpoints if len(endpoint) > 1]
    
    return endpoints

def discover_api_endpoints_from_html(html_content: str) -> List[str]:
    """
    Discover API endpoints from HTML content.
    
    Args:
        html_content: HTML content to analyze
        
    Returns:
        List of discovered API endpoints
    """
    endpoints = []
    
    # Look for data-api attributes
    data_api_pattern = r"data-api=[\'\"]([^\'\"]+)[\'\"]"
    matches = re.findall(data_api_pattern, html_content, re.IGNORECASE)
    endpoints.extend(matches)
    
    # Look for comment references to APIs
    comment_pattern = r"<!--.*?(\/api\/[^\s]+).*?-->"
    matches = re.findall(comment_pattern, html_content, re.IGNORECASE | re.DOTALL)
    endpoints.extend(matches)
    
    # Remove duplicates
    endpoints = list(set(endpoints))
    
    return endpoints

def test_api_endpoint(base_url: str, endpoint: str) -> Dict[str, Any]:
    """
    Test an API endpoint for basic information.
    
    Args:
        base_url: Base URL of the application
        endpoint: API endpoint to test
        
    Returns:
        Dictionary containing endpoint test results
    """
    from urllib.parse import urljoin
    
    results = {
        "endpoint": endpoint,
        "full_url": "",
        "methods": {},
        "response_info": {}
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Construct full URL
        full_url = urljoin(base_url, endpoint)
        results["full_url"] = full_url
        
        # Test each HTTP method
        for method in HTTP_METHODS:
            try:
                if method == "GET":
                    response = http_client.get(full_url)
                elif method == "POST":
                    response = http_client.post(full_url, data={"test": "test"})
                elif method == "HEAD":
                    response = http_client.head(full_url)
                else:
                    # For other methods, we'll just check if OPTIONS works
                    if method == "OPTIONS":
                        response = http_client.session.options(full_url)
                    else:
                        continue
                
                # Record successful method
                results["methods"][method] = {
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "content_length": len(response.content),
                    "allows_cors": "access-control-allow-origin" in response.headers
                }
                
                # Capture response info for first successful method
                if not results["response_info"]:
                    results["response_info"] = {
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "server": response.headers.get("server", ""),
                        "content_length": len(response.content)
                    }
                    
            except Exception as e:
                # Record failed method
                results["methods"][method] = {
                    "error": str(e)
                }
    
    except Exception as e:
        logger.error(f"Error testing API endpoint {endpoint}: {e}")
        results["error"] = str(e)
    
    return results

def discover_api_endpoints(base_url: str) -> Dict[str, Any]:
    """
    Discover API endpoints through various methods.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing API discovery results
    """
    print("[*] Discovering API endpoints...")
    
    results = {
        "base_url": base_url,
        "endpoints": [],
        "discovered_endpoints": [],
        "tested_endpoints": [],
        "total_endpoints": 0
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Fetch main page
        response = http_client.get(base_url)
        html_content = response.text
        
        # Discover endpoints from HTML
        html_endpoints = discover_api_endpoints_from_html(html_content)
        results["discovered_endpoints"].extend(html_endpoints)
        
        # Extract JavaScript files and discover endpoints from them
        js_urls = extract_js_urls(html_content, base_url)
        
        for js_url in js_urls:
            try:
                js_response = http_client.get(js_url)
                js_content = js_response.text
                js_endpoints = discover_api_endpoints_from_js(js_content)
                results["discovered_endpoints"].extend(js_endpoints)
            except Exception as e:
                logger.error(f"Error analyzing JavaScript file {js_url}: {e}")
        
        # Remove duplicates
        results["discovered_endpoints"] = list(set(results["discovered_endpoints"]))
        results["total_endpoints"] = len(results["discovered_endpoints"])
        
        print(f"  [*] Found {results['total_endpoints']} potential API endpoints")
        
        # Test a sample of discovered endpoints
        sample_endpoints = results["discovered_endpoints"][:10]  # Limit to first 10
        
        for endpoint in sample_endpoints:
            endpoint_test = test_api_endpoint(base_url, endpoint)
            results["tested_endpoints"].append(endpoint_test)
        
        print(f"  [+] API endpoint discovery completed (tested {len(results['tested_endpoints'])} endpoints)")
        
    except Exception as e:
        logger.error(f"Error discovering API endpoints for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def extract_js_urls(content: str, base_url: str) -> List[str]:
    """
    Extract JavaScript file URLs from HTML content.
    
    Args:
        content: HTML content to analyze
        base_url: Base URL for resolving relative paths
        
    Returns:
        List of JavaScript file URLs
    """
    js_urls = []
    
    # Pattern to match script tags with src attribute
    script_pattern = r"<script[^>]+src=[\"']([^\"']+)[\"'][^>]*>"
    matches = re.findall(script_pattern, content, re.IGNORECASE)
    
    from urllib.parse import urljoin
    
    for match in matches:
        # Resolve relative URLs
        full_url = urljoin(base_url, match)
        js_urls.append(full_url)
    
    return js_urls

def comprehensive_api_discovery(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive API endpoint discovery and analysis.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing comprehensive API discovery results
    """
    print("[*] Performing comprehensive API discovery...")
    
    # Run main discovery
    discovery_results = discover_api_endpoints(base_url)
    
    # Additional analysis could be added here:
    # - Authentication analysis
    # - Rate limiting checks
    # - Input validation testing
    # - Error message analysis
    
    # Add security recommendations
    discovery_results["security_recommendations"] = [
        "Verify that API endpoints require proper authentication",
        "Check that sensitive endpoints are not exposed publicly",
        "Ensure rate limiting is implemented on API endpoints",
        "Validate that error messages do not leak sensitive information",
        "Verify that API documentation is not publicly accessible"
    ]
    
    print("  [+] Comprehensive API discovery completed")
    
    return discovery_results