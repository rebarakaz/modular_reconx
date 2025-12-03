"""
CORS Misconfiguration Checker for Modular ReconX
Checks for Cross-Origin Resource Sharing misconfigurations
"""

import logging
from typing import Dict, Any, List
from .http_client import get_http_client

logger = logging.getLogger(__name__)

def check_cors_misconfigurations(base_url: str) -> Dict[str, Any]:
    """
    Check for CORS misconfigurations that could lead to security issues.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing CORS misconfiguration analysis results
    """
    print("[*] Checking for CORS misconfigurations...")
    
    results = {
        "url": base_url,
        "cors_headers": {},
        "misconfigurations": [],
        "risk_level": "low",
        "findings": []
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Test various origins to check for permissive CORS policies
        test_origins = [
            "https://malicious-site.com",
            "http://localhost:3000",
            "https://subdomain.example.com",
            "null",
            "https://attacker.example.com"
        ]
        
        for origin in test_origins:
            try:
                # Make request with Origin header
                headers = {"Origin": origin}
                response = http_client.get(base_url, headers=headers)
                
                # Check for CORS headers in response
                cors_headers = {}
                for header, value in response.headers.items():
                    if "access-control" in header.lower():
                        cors_headers[header] = value
                        results["cors_headers"][header] = value
                
                # Analyze CORS headers for misconfigurations
                if "access-control-allow-origin" in cors_headers:
                    acao_value = cors_headers["access-control-allow-origin"]
                    
                    # Check for wildcard origin
                    if acao_value == "*":
                        misconfig = {
                            "type": "wildcard_origin",
                            "origin_tested": origin,
                            "acao_value": acao_value,
                            "risk": "high",
                            "description": "Access-Control-Allow-Origin set to wildcard (*)"
                        }
                        results["misconfigurations"].append(misconfig)
                        if results["risk_level"] != "high":
                            results["risk_level"] = "high"
                        results["findings"].append("CORS policy allows any origin")
                    
                    # Check for reflected origin
                    elif acao_value == origin:
                        misconfig = {
                            "type": "reflected_origin",
                            "origin_tested": origin,
                            "acao_value": acao_value,
                            "risk": "high",
                            "description": "Access-Control-Allow-Origin reflects the Origin header"
                        }
                        results["misconfigurations"].append(misconfig)
                        if results["risk_level"] != "high":
                            results["risk_level"] = "high"
                        results["findings"].append("CORS policy reflects any origin")
                
                # Check for credentials with permissive CORS
                if "access-control-allow-credentials" in cors_headers:
                    acac_value = cors_headers["access-control-allow-credentials"].lower()
                    if acac_value == "true":
                        # Check if this is combined with permissive origin
                        if "access-control-allow-origin" in cors_headers:
                            acao_value = cors_headers["access-control-allow-origin"]
                            if acao_value == "*" or acao_value == origin:
                                misconfig = {
                                    "type": "credentials_with_permissive_origin",
                                    "origin_tested": origin,
                                    "acac_value": acac_value,
                                    "acao_value": acao_value,
                                    "risk": "critical",
                                    "description": "Access-Control-Allow-Credentials set to true with permissive origin"
                                }
                                results["misconfigurations"].append(misconfig)
                                results["risk_level"] = "critical"
                                results["findings"].append("CORS credentials allowed with permissive origin")
                
                # Check for dangerous exposed headers
                if "access-control-expose-headers" in cors_headers:
                    exposed_headers = cors_headers["access-control-expose-headers"].lower()
                    dangerous_headers = ["authorization", "x-api-key", "x-auth-token"]
                    for dangerous in dangerous_headers:
                        if dangerous in exposed_headers:
                            misconfig = {
                                "type": "dangerous_exposed_headers",
                                "header": dangerous,
                                "exposed_headers": exposed_headers,
                                "risk": "medium",
                                "description": f"Dangerous header '{dangerous}' exposed via CORS"
                            }
                            results["misconfigurations"].append(misconfig)
                            if results["risk_level"] not in ["high", "critical"]:
                                results["risk_level"] = "medium"
                            results["findings"].append(f"Dangerous header '{dangerous}' exposed via CORS")
                
            except Exception as e:
                logger.error(f"Error testing CORS with origin {origin}: {e}")
                continue
        
        # Test preflight requests (OPTIONS)
        try:
            options_response = http_client.session.options(base_url, headers={"Origin": "https://malicious-site.com"})
            if options_response.status_code == 200 or options_response.status_code == 204:
                results["findings"].append("CORS preflight requests are accepted")
                
                # Check for preflight-specific headers
                for header, value in options_response.headers.items():
                    if "access-control" in header.lower():
                        results["cors_headers"][f"preflight_{header}"] = value
                        
        except Exception as e:
            logger.error(f"Error testing CORS preflight: {e}")
        
        print(f"  [+] CORS misconfiguration check completed (Risk Level: {results['risk_level']})")
        
    except Exception as e:
        logger.error(f"Error checking CORS misconfigurations for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def comprehensive_cors_analysis(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive CORS analysis.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing comprehensive CORS analysis results
    """
    print("[*] Performing comprehensive CORS analysis...")
    
    results = {
        "url": base_url,
        "cors_analysis": check_cors_misconfigurations(base_url)
    }
    
    # Add security recommendations
    results["security_recommendations"] = [
        "Set Access-Control-Allow-Origin to specific trusted domains only",
        "Do not reflect the Origin header value in Access-Control-Allow-Origin",
        "Avoid using wildcard (*) for Access-Control-Allow-Origin when credentials are allowed",
        "Limit exposed headers to only those that are necessary",
        "Implement proper validation of preflight requests",
        "Consider implementing CORS only for specific endpoints that require it"
    ]
    
    print("  [+] Comprehensive CORS analysis completed")
    
    return results