"""
JavaScript Analysis Module for Modular ReconX
Analyzes JavaScript files for security issues and sensitive information
"""

import re
import logging
from typing import Dict, Any, List
from .http_client import get_http_client

logger = logging.getLogger(__name__)

# Patterns for identifying sensitive information in JavaScript
SENSITIVE_PATTERNS = {
    "api_keys": r"[\'\"]([A-Za-z0-9_\-]{32,})[\'\"]",
    "jwt_tokens": r"[\'\"](eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)[\'\"]",
    "urls": r"(https?://[^\s\'\"<>]+)",
    "aws_keys": r"(AKIA[0-9A-Z]{16})",
    "google_api_keys": r"[\'\"](AIza[0-9A-Za-z_-]{35})[\'\"]",
    "firebase_configs": r"firebaseConfig\s*=\s*\{[^}]+\}",
    "hardcoded_passwords": r"[\'\"](password|passwd|pwd)[\'\"]\s*[:=]\s*[\'\"][^\'\"]+[\'\"]",
    "debug_statements": r"(console\.log|alert|document\.write)\s*\(",
    "eval_usage": r"\beval\s*\(",
    "document_write": r"document\.write",
    "innerHTML_usage": r"\.innerHTML\s*=",
    "local_storage": r"localStorage\.(getItem|setItem|removeItem)",
    "session_storage": r"sessionStorage\.(getItem|setItem|removeItem)"
}

# Vulnerable JavaScript libraries and versions
VULNERABLE_LIBRARIES = {
    "jquery": ["<1.9.0", "<3.0.0"],
    "angular": ["<1.6.0"],
    "react": ["<16.0.0"],
    "vue": ["<2.5.0"]
}

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

def find_api_endpoints(js_content: str) -> List[str]:
    """
    Find potential API endpoints in JavaScript content.
    """
    endpoints = []
    
    # improved patterns for API endpoint discovery
    patterns = [
        r"['\"](/api/v\d+/[a-zA-Z0-9_\-/]+)['\"]",  # /api/v1/users
        r"['\"](/api/[a-zA-Z0-9_\-/]+)['\"]",       # /api/users
        r"['\"](https?://api\.[a-zA-Z0-9_\-]+\.[a-z]+/[a-zA-Z0-9_\-/]+)['\"]", # https://api.example.com/v1
        r"['\"](/graphql)['\"]",                    # /graphql
        r"\.get\(['\"]([^'\"]+)['\"]",              # axios.get('/users')
        r"\.post\(['\"]([^'\"]+)['\"]",             # .post('/login')
        r"\.put\(['\"]([^'\"]+)['\"]",
        r"\.delete\(['\"]([^'\"]+)['\"]",
        r"fetch\(['\"]([^'\"]+)['\"]",              # fetch('/api/data')
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        endpoints.extend(matches)
    
    # Filter out common false positives
    filtered = []
    for ep in set(endpoints):
        if len(ep) < 4 or len(ep) > 100: continue
        if ep.startswith(("//", "#", "javascript:")): continue
        if ep in ["/"]: continue
        filtered.append(ep)
            
    return sorted(filtered)

def analyze_js_content(js_content: str, url: str) -> Dict[str, Any]:
    """
    Analyze JavaScript content for security issues.
    
    Args:
        js_content: JavaScript content to analyze
        url: URL of the JavaScript file
        
    Returns:
        Dictionary containing analysis results
    """
    results = {
        "url": url,
        "sensitive_data": {},
        "security_issues": [],
        "vulnerable_patterns": [],
        "size": len(js_content),
        "lines_of_code": len(js_content.split('\n')),
        "endpoints": find_api_endpoints(js_content)
    }
    
    # Check for sensitive patterns
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        if matches:
            results["sensitive_data"][pattern_name] = matches[:5]  # Limit to first 5 matches
    
    # Check for security issues
    if results["sensitive_data"].get("eval_usage"):
        results["security_issues"].append("Use of eval() function detected")
    
    if results["sensitive_data"].get("document_write"):
        results["security_issues"].append("Use of document.write() detected")
    
    if results["sensitive_data"].get("innerHTML_usage"):
        results["security_issues"].append("Direct innerHTML assignment detected")
    
    if results["sensitive_data"].get("debug_statements"):
        results["security_issues"].append("Debug statements found in production code")
    
    # Check for vulnerable library usage (simplified)
    for lib, versions in VULNERABLE_LIBRARIES.items():
        if lib in js_content.lower():
            results["vulnerable_patterns"].append(f"Potential {lib} library usage detected")
    
    return results

def analyze_javascript_files(base_url: str) -> Dict[str, Any]:
    """
    Analyze JavaScript files for security issues and sensitive information.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing JavaScript analysis results
    """
    print("[*] Analyzing JavaScript files for security issues...")
    
    results = {
        "base_url": base_url,
        "js_files": [],
        "total_files": 0,
        "files_with_issues": 0,
        "files_with_issues": 0,
        "sensitive_data_found": False,
        "api_endpoints": {
            "discovered": [],
            "count": 0
        }
    }
    
    try:
        # Get HTTP client with appropriate settings
        http_client = get_http_client()
        
        # Fetch the main page
        response = http_client.get(base_url)
        content = response.text
        
        # Extract JavaScript file URLs
        js_urls = extract_js_urls(content, base_url)
        results["total_files"] = len(js_urls)
        
        print(f"  [*] Found {len(js_urls)} JavaScript files to analyze")
        
        # Analyze each JavaScript file
        for js_url in js_urls:
            try:
                js_response = http_client.get(js_url)
                js_content = js_response.text
                
                js_analysis = analyze_js_content(js_content, js_url)
                results["js_files"].append(js_analysis)
                
                # Check if this file has issues
                if (js_analysis["sensitive_data"] or 
                    js_analysis["security_issues"] or 
                    js_analysis["vulnerable_patterns"]):
                    results["files_with_issues"] += 1
                
                # Check for sensitive data
                if js_analysis["sensitive_data"]:
                    results["sensitive_data_found"] = True
                    
                # Aggregate endpoints
                if js_analysis.get("endpoints"):
                    results["api_endpoints"]["discovered"].extend(js_analysis["endpoints"])
                    
            except Exception as e:
                logger.error(f"Error analyzing JavaScript file {js_url}: {e}")
                results["js_files"].append({
                    "url": js_url,
                    "error": str(e)
                })
        
        # Deduplicate endpoints
        results["api_endpoints"]["discovered"] = sorted(list(set(results["api_endpoints"]["discovered"])))
        results["api_endpoints"]["count"] = len(results["api_endpoints"]["discovered"])
        
        print(f"  [+] JavaScript analysis completed ({results['files_with_issues']} files with issues)")
        print(f"  [+] Discovered {results['api_endpoints']['count']} potential API endpoints")
        
    except Exception as e:
        logger.error(f"Error analyzing JavaScript files for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def comprehensive_js_analysis(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive JavaScript analysis.
    """
    print("[*] Performing comprehensive JavaScript analysis...")
    
    # The main analysis now includes endpoint discovery
    js_results = analyze_javascript_files(base_url)
    
    print("  [+] Comprehensive JavaScript analysis completed")
    
    return js_results