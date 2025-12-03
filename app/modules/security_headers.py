"""
Security Headers Analysis Module for Modular ReconX
Analyzes HTTP security headers for proper configuration
"""

import logging
from typing import Dict, Any, List
from .http_client import get_http_client

logger = logging.getLogger(__name__)

# Security headers that should be present
RECOMMENDED_HEADERS = {
    "strict-transport-security": {
        "description": "HSTS header to enforce HTTPS",
        "recommendation": "max-age=31536000; includeSubDomains"
    },
    "content-security-policy": {
        "description": "CSP header to prevent XSS",
        "recommendation": "default-src 'self'; script-src 'self' 'unsafe-inline'"
    },
    "x-content-type-options": {
        "description": "Prevents MIME type sniffing",
        "recommendation": "nosniff"
    },
    "x-frame-options": {
        "description": "Prevents clickjacking",
        "recommendation": "DENY or SAMEORIGIN"
    },
    "x-xss-protection": {
        "description": "Basic XSS protection",
        "recommendation": "1; mode=block"
    },
    "referrer-policy": {
        "description": "Controls referrer information",
        "recommendation": "no-referrer-when-downgrade"
    },
    "permissions-policy": {
        "description": "Controls browser features",
        "recommendation": "geolocation=(), microphone=(), camera=()"
    }
}

# Security headers that should NOT be present
DEPRECATED_HEADERS = {
    "x-powered-by": "Can reveal server technology",
    "server": "Can reveal server information",
    "x-aspnet-version": "Can reveal framework version",
    "x-aspnetmvc-version": "Can reveal framework version"
}

def analyze_security_headers(base_url: str) -> Dict[str, Any]:
    """
    Analyze HTTP security headers for proper configuration.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing security header analysis results
    """
    print("[*] Analyzing HTTP security headers...")
    
    results = {
        "url": base_url,
        "headers": {},
        "security_analysis": {
            "present_headers": {},
            "missing_headers": {},
            "deprecated_headers": {},
            "misconfigured_headers": {},
            "security_score": 0
        }
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Make request to get headers
        response = http_client.get(base_url)
        headers = {k.lower(): v for k, v in response.headers.items()}
        results["headers"] = dict(response.headers)
        
        # Check for recommended headers
        for header, info in RECOMMENDED_HEADERS.items():
            if header in headers:
                results["security_analysis"]["present_headers"][header] = {
                    "value": headers[header],
                    "description": info["description"]
                }
            else:
                results["security_analysis"]["missing_headers"][header] = {
                    "description": info["description"],
                    "recommendation": info["recommendation"]
                }
        
        # Check for deprecated headers
        for header, reason in DEPRECATED_HEADERS.items():
            if header in headers:
                results["security_analysis"]["deprecated_headers"][header] = {
                    "value": headers[header],
                    "reason": reason
                }
        
        # Check specific header configurations
        # HSTS check
        if "strict-transport-security" in headers:
            hsts_value = headers["strict-transport-security"]
            if "max-age" not in hsts_value:
                results["security_analysis"]["misconfigured_headers"]["strict-transport-security"] = {
                    "value": hsts_value,
                    "issue": "Missing max-age directive"
                }
        
        # X-Content-Type-Options check
        if "x-content-type-options" in headers:
            xcto_value = headers["x-content-type-options"].lower()
            if xcto_value != "nosniff":
                results["security_analysis"]["misconfigured_headers"]["x-content-type-options"] = {
                    "value": headers["x-content-type-options"],
                    "issue": "Should be set to 'nosniff'"
                }
        
        # X-Frame-Options check
        if "x-frame-options" in headers:
            xfo_value = headers["x-frame-options"].upper()
            if xfo_value not in ["DENY", "SAMEORIGIN"]:
                results["security_analysis"]["misconfigured_headers"]["x-frame-options"] = {
                    "value": headers["x-frame-options"],
                    "issue": "Should be set to 'DENY' or 'SAMEORIGIN'"
                }
        
        # Calculate security score
        total_recommended = len(RECOMMENDED_HEADERS)
        present_headers = len(results["security_analysis"]["present_headers"])
        missing_headers = len(results["security_analysis"]["missing_headers"])
        deprecated_headers = len(results["security_analysis"]["deprecated_headers"])
        misconfigured_headers = len(results["security_analysis"]["misconfigured_headers"])
        
        # Score calculation (out of 100)
        results["security_analysis"]["security_score"] = max(0, 
            int((present_headers / total_recommended) * 100) - 
            (missing_headers * 5) - 
            (deprecated_headers * 10) - 
            (misconfigured_headers * 10)
        )
        
        print(f"  [+] Security header analysis completed (Score: {results['security_analysis']['security_score']}/100)")
        
    except Exception as e:
        logger.error(f"Error analyzing security headers for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def check_cors_configuration(base_url: str) -> Dict[str, Any]:
    """
    Check CORS configuration for potential misconfigurations.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing CORS analysis results
    """
    print("[*] Checking CORS configuration...")
    
    results = {
        "url": base_url,
        "cors_headers": {},
        "misconfigurations": [],
        "risk_level": "low"
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Make request with Origin header to test CORS
        headers = {"Origin": "https://malicious-site.com"}
        response = http_client.get(base_url, headers=headers)
        
        # Check for CORS headers
        cors_headers = {}
        for header, value in response.headers.items():
            if "access-control" in header.lower():
                cors_headers[header] = value
                results["cors_headers"][header] = value
        
        # Check for dangerous configurations
        if "access-control-allow-origin" in cors_headers:
            acao_value = cors_headers["access-control-allow-origin"]
            if acao_value == "*" or acao_value == "https://malicious-site.com":
                results["misconfigurations"].append({
                    "header": "access-control-allow-origin",
                    "value": acao_value,
                    "issue": "Overly permissive CORS policy"
                })
                results["risk_level"] = "high"
        
        if "access-control-allow-credentials" in cors_headers:
            acac_value = cors_headers["access-control-allow-credentials"]
            if acac_value.lower() == "true":
                if results["risk_level"] != "high":
                    results["risk_level"] = "medium"
                results["misconfigurations"].append({
                    "header": "access-control-allow-credentials",
                    "value": acac_value,
                    "issue": "Credentials allowed with CORS"
                })
        
        print(f"  [+] CORS configuration check completed (Risk: {results['risk_level']})")
        
    except Exception as e:
        logger.error(f"Error checking CORS configuration for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def comprehensive_security_analysis(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive security header analysis.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing comprehensive security analysis results
    """
    print("[*] Performing comprehensive security analysis...")
    
    results = {
        "url": base_url,
        "security_headers": analyze_security_headers(base_url),
        "cors_analysis": check_cors_configuration(base_url)
    }
    
    # Add overall security recommendations
    results["security_recommendations"] = [
        "Implement missing security headers",
        "Remove or obfuscate server information headers",
        "Review and tighten CORS policy",
        "Implement proper Content Security Policy",
        "Configure HSTS for all subdomains"
    ]
    
    print("  [+] Comprehensive security analysis completed")
    
    return results