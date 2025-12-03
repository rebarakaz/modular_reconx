"""
Cookie Security Analysis Module for Modular ReconX
Analyzes HTTP cookies for security misconfigurations
"""

import logging
import re
from typing import Dict, Any, List
from .http_client import get_http_client

logger = logging.getLogger(__name__)

# Security attributes that cookies should have
REQUIRED_COOKIE_ATTRIBUTES = [
    "Secure",
    "HttpOnly",
    "SameSite"
]

# Potentially sensitive cookie names
SENSITIVE_COOKIE_NAMES = [
    "session", "sess", "auth", "token", "jwt", "apikey", "password", "pass", "user",
    "login", "uid", "userid", "admin", "remember", "credential", "secret"
]

def analyze_cookies(base_url: str) -> Dict[str, Any]:
    """
    Analyze HTTP cookies for security misconfigurations.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing cookie analysis results
    """
    print("[*] Analyzing HTTP cookies for security issues...")
    
    results = {
        "url": base_url,
        "cookies": [],
        "security_issues": [],
        "sensitive_cookies": [],
        "missing_security_attributes": [],
        "risk_score": 0
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Make request to get cookies
        response = http_client.get(base_url)
        
        # Check for Set-Cookie headers
        set_cookie_headers = []
        for header, value in response.headers.items():
            if header.lower() == "set-cookie":
                set_cookie_headers.append(value)
        
        # Analyze each cookie
        for i, cookie_header in enumerate(set_cookie_headers):
            cookie_info = {
                "id": i,
                "raw_header": cookie_header,
                "name": "",
                "value": "",
                "attributes": {},
                "security_analysis": {
                    "missing_attributes": [],
                    "sensitive_name": False,
                    "issues": []
                }
            }
            
            # Parse cookie name and value
            cookie_parts = cookie_header.split(";")
            if cookie_parts:
                # First part is name=value
                name_value = cookie_parts[0].split("=", 1)
                if len(name_value) == 2:
                    cookie_info["name"] = name_value[0].strip()
                    cookie_info["value"] = name_value[1].strip()
                elif len(name_value) == 1:
                    cookie_info["name"] = name_value[0].strip()
                    cookie_info["value"] = ""
                
                # Parse attributes
                for part in cookie_parts[1:]:
                    attr_parts = part.split("=", 1)
                    attr_name = attr_parts[0].strip()
                    attr_value = attr_parts[1].strip() if len(attr_parts) > 1 else ""
                    cookie_info["attributes"][attr_name.lower()] = attr_value
            
            # Check for sensitive cookie names
            cookie_name_lower = cookie_info["name"].lower()
            for sensitive_name in SENSITIVE_COOKIE_NAMES:
                if sensitive_name in cookie_name_lower:
                    cookie_info["security_analysis"]["sensitive_name"] = True
                    cookie_info["security_analysis"]["issues"].append("Sensitive cookie name detected")
                    results["sensitive_cookies"].append(cookie_info["name"])
                    break
            
            # Check for missing security attributes
            cookie_attrs = [attr.lower() for attr in cookie_info["attributes"].keys()]
            for required_attr in REQUIRED_COOKIE_ATTRIBUTES:
                if required_attr.lower() not in cookie_attrs:
                    cookie_info["security_analysis"]["missing_attributes"].append(required_attr)
                    results["missing_security_attributes"].append({
                        "cookie": cookie_info["name"],
                        "missing_attribute": required_attr
                    })
            
            # Check specific attribute values
            # Check SameSite attribute
            if "samesite" in cookie_info["attributes"]:
                samesite_value = cookie_info["attributes"]["samesite"].lower()
                if samesite_value not in ["lax", "strict", "none"]:
                    cookie_info["security_analysis"]["issues"].append(f"Invalid SameSite value: {samesite_value}")
            else:
                cookie_info["security_analysis"]["issues"].append("SameSite attribute missing")
            
            # Check Secure attribute for cookies with sensitive names
            if cookie_info["security_analysis"]["sensitive_name"] and "secure" not in cookie_attrs:
                cookie_info["security_analysis"]["issues"].append("Secure attribute missing for sensitive cookie")
            
            # Check HttpOnly attribute for cookies with sensitive names
            if cookie_info["security_analysis"]["sensitive_name"] and "httponly" not in cookie_attrs:
                cookie_info["security_analysis"]["issues"].append("HttpOnly attribute missing for sensitive cookie")
            
            # Add cookie to results
            results["cookies"].append(cookie_info)
        
        # Calculate risk score
        sensitive_cookie_count = len(results["sensitive_cookies"])
        missing_attrs_count = len(results["missing_security_attributes"])
        results["risk_score"] = sensitive_cookie_count * 3 + missing_attrs_count
        
        # Add security issues summary
        if results["sensitive_cookies"]:
            results["security_issues"].append({
                "type": "sensitive_cookies",
                "count": len(results["sensitive_cookies"]),
                "description": f"Found {len(results['sensitive_cookies'])} potentially sensitive cookies"
            })
        
        if results["missing_security_attributes"]:
            results["security_issues"].append({
                "type": "missing_attributes",
                "count": len(results["missing_security_attributes"]),
                "description": f"Found {len(results['missing_security_attributes'])} missing security attributes"
            })
        
        print(f"  [+] Cookie analysis completed ({len(results['cookies'])} cookies analyzed, Risk Score: {results['risk_score']})")
        
    except Exception as e:
        logger.error(f"Error analyzing cookies for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def check_cookie_security_features(base_url: str) -> Dict[str, Any]:
    """
    Check for advanced cookie security features.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing advanced cookie security analysis
    """
    print("[*] Checking advanced cookie security features...")
    
    results = {
        "url": base_url,
        "cookie_prefixes": {
            "secure_prefix": False,
            "host_prefix": False
        },
        "cookie_lifetime": {
            "session_cookies": 0,
            "persistent_cookies": 0,
            "long_lived_cookies": []
        },
        "domain_attributes": {
            "domain_specific": [],
            "domain_wildcard": [],
            "domain_missing": []
        }
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Make request to get cookies
        response = http_client.get(base_url)
        
        # Check for Set-Cookie headers
        set_cookie_headers = []
        for header, value in response.headers.items():
            if header.lower() == "set-cookie":
                set_cookie_headers.append(value)
        
        for cookie_header in set_cookie_headers:
            # Check for cookie prefixes
            if cookie_header.startswith("__Secure-"):
                results["cookie_prefixes"]["secure_prefix"] = True
            
            if cookie_header.startswith("__Host-"):
                results["cookie_prefixes"]["host_prefix"] = True
            
            # Check cookie lifetime
            if "max-age=" not in cookie_header.lower() and "expires=" not in cookie_header.lower():
                results["cookie_lifetime"]["session_cookies"] += 1
            else:
                # Check for long-lived cookies
                max_age_match = re.search(r"[Mm]ax-[Aa]ge=(\d+)", cookie_header)
                expires_match = re.search(r"[Ee]xpires=([^;]+)", cookie_header)
                
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age > 31536000:  # More than 1 year
                        results["cookie_lifetime"]["long_lived_cookies"].append({
                            "header": cookie_header[:50] + "..." if len(cookie_header) > 50 else cookie_header,
                            "max_age": max_age
                        })
                    results["cookie_lifetime"]["persistent_cookies"] += 1
                elif expires_match:
                    results["cookie_lifetime"]["persistent_cookies"] += 1
            
            # Check domain attributes
            if "domain=" in cookie_header.lower():
                domain_match = re.search(r"[Dd]omain=([^;]+)", cookie_header)
                if domain_match:
                    domain_value = domain_match.group(1).strip()
                    if domain_value.startswith("."):
                        results["domain_attributes"]["domain_wildcard"].append(domain_value)
                    else:
                        results["domain_attributes"]["domain_specific"].append(domain_value)
            else:
                results["domain_attributes"]["domain_missing"].append(cookie_header[:30] + "..." if len(cookie_header) > 30 else cookie_header)
        
        print("  [+] Advanced cookie security features check completed")
        
    except Exception as e:
        logger.error(f"Error checking advanced cookie security features for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def comprehensive_cookie_analysis(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive cookie security analysis.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing comprehensive cookie analysis results
    """
    print("[*] Performing comprehensive cookie analysis...")
    
    results = {
        "url": base_url,
        "cookie_analysis": analyze_cookies(base_url),
        "advanced_features": check_cookie_security_features(base_url)
    }
    
    # Add security recommendations
    results["security_recommendations"] = [
        "Set Secure attribute for all cookies, especially sensitive ones",
        "Set HttpOnly attribute for cookies that don't need to be accessed by JavaScript",
        "Set SameSite attribute to Lax or Strict to prevent CSRF attacks",
        "Use __Secure- prefix for cookies that require Secure attribute",
        "Use __Host- prefix for cookies that should only be sent to the host that set them",
        "Avoid long-lived cookies for sensitive information",
        "Set domain attribute explicitly to prevent cookies from being sent to subdomains unnecessarily",
        "Use short expiration times for sensitive cookies"
    ]
    
    print("  [+] Comprehensive cookie analysis completed")
    
    return results