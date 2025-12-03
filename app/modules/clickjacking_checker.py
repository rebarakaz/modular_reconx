"""
Clickjacking Protection Checker for Modular ReconX
Checks for proper clickjacking protection mechanisms
"""

import logging
from typing import Dict, Any, List
from .http_client import get_http_client

logger = logging.getLogger(__name__)

def check_clickjacking_protection(base_url: str) -> Dict[str, Any]:
    """
    Check for clickjacking protection mechanisms.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing clickjacking protection analysis results
    """
    print("[*] Checking for clickjacking protection...")
    
    results = {
        "url": base_url,
        "headers": {},
        "protection_mechanisms": {
            "x_frame_options": {
                "present": False,
                "value": "",
                "valid": False,
                "description": "X-Frame-Options header prevents clickjacking"
            },
            "content_security_policy": {
                "present": False,
                "value": "",
                "frame_ancestors": "",
                "valid": False,
                "description": "Content-Security-Policy frame-ancestors directive"
            }
        },
        "vulnerability_assessment": {
            "vulnerable": False,
            "risk_level": "low",
            "issues": []
        },
        "test_results": []
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Make request to get headers
        response = http_client.get(base_url)
        headers = {k.lower(): v for k, v in response.headers.items()}
        results["headers"] = dict(response.headers)
        
        # Check X-Frame-Options header
        if "x-frame-options" in headers:
            xfo_value = headers["x-frame-options"]
            results["protection_mechanisms"]["x_frame_options"]["present"] = True
            results["protection_mechanisms"]["x_frame_options"]["value"] = xfo_value
            
            # Validate X-Frame-Options value
            valid_values = ["DENY", "SAMEORIGIN"]
            if xfo_value.upper() in valid_values:
                results["protection_mechanisms"]["x_frame_options"]["valid"] = True
            elif xfo_value.upper().startswith("ALLOW-FROM "):
                # ALLOW-FROM is deprecated but still valid
                results["protection_mechanisms"]["x_frame_options"]["valid"] = True
                results["test_results"].append("X-Frame-Options uses deprecated ALLOW-FROM directive")
            else:
                results["vulnerability_assessment"]["issues"].append(f"Invalid X-Frame-Options value: {xfo_value}")
        
        # Check Content-Security-Policy header for frame-ancestors
        csp_headers = []
        if "content-security-policy" in headers:
            csp_headers.append(("content-security-policy", headers["content-security-policy"]))
        if "content-security-policy-report-only" in headers:
            csp_headers.append(("content-security-policy-report-only", headers["content-security-policy-report-only"]))
        
        for header_name, header_value in csp_headers:
            results["protection_mechanisms"]["content_security_policy"]["present"] = True
            results["protection_mechanisms"]["content_security_policy"]["value"] = header_value
            
            # Check for frame-ancestors directive
            if "frame-ancestors" in header_value:
                results["protection_mechanisms"]["content_security_policy"]["frame_ancestors"] = header_value
                # Extract frame-ancestors value
                import re
                frame_ancestors_match = re.search(r"frame-ancestors\s+([^;]+)", header_value)
                if frame_ancestors_match:
                    frame_ancestors_value = frame_ancestors_match.group(1).strip()
                    results["protection_mechanisms"]["content_security_policy"]["frame_ancestors"] = frame_ancestors_value
                    
                    # Validate frame-ancestors value
                    if frame_ancestors_value in ["'none'", "'self'"] or frame_ancestors_value.startswith("'self' "):
                        results["protection_mechanisms"]["content_security_policy"]["valid"] = True
                    elif frame_ancestors_value == "*":
                        results["vulnerability_assessment"]["issues"].append("CSP frame-ancestors set to '*' (allows framing from any origin)")
                    else:
                        # Assume custom origins are valid if properly formatted
                        results["protection_mechanisms"]["content_security_policy"]["valid"] = True
        
        # Assess vulnerability
        xfo_valid = results["protection_mechanisms"]["x_frame_options"]["valid"]
        csp_valid = results["protection_mechanisms"]["content_security_policy"]["valid"]
        
        if not xfo_valid and not csp_valid:
            results["vulnerability_assessment"]["vulnerable"] = True
            results["vulnerability_assessment"]["risk_level"] = "high"
            results["vulnerability_assessment"]["issues"].append("No valid clickjacking protection mechanisms found")
        elif not xfo_valid and csp_valid:
            results["vulnerability_assessment"]["risk_level"] = "low"
            results["vulnerability_assessment"]["issues"].append("Only CSP protection present (X-Frame-Options missing)")
        elif xfo_valid and not csp_valid:
            results["vulnerability_assessment"]["risk_level"] = "low"
            results["vulnerability_assessment"]["issues"].append("Only X-Frame-Options protection present (CSP missing)")
        
        print(f"  [+] Clickjacking protection check completed (Risk Level: {results['vulnerability_assessment']['risk_level']})")
        
    except Exception as e:
        logger.error(f"Error checking clickjacking protection for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def test_frameability(base_url: str) -> Dict[str, Any]:
    """
    Test if the page can be framed by attempting to load it in an iframe context.
    
    Args:
        base_url: The base URL to test
        
    Returns:
        Dictionary containing frameability test results
    """
    print("[*] Testing page frameability...")
    
    results = {
        "url": base_url,
        "frame_test": {
            "can_be_framed": False,
            "test_method": "header_analysis",
            "simulated_frame": ""
        }
    }
    
    try:
        # For now, we'll simulate this test by analyzing headers
        # In a real implementation, this would involve actually trying to frame the page
        protection_results = check_clickjacking_protection(base_url)
        
        # If either protection mechanism is valid, the page likely can't be framed
        xfo_valid = protection_results["protection_mechanisms"]["x_frame_options"]["valid"]
        csp_valid = protection_results["protection_mechanisms"]["content_security_policy"]["valid"]
        
        if xfo_valid or csp_valid:
            results["frame_test"]["can_be_framed"] = False
            results["frame_test"]["test_method"] = "protected_by_headers"
        else:
            results["frame_test"]["can_be_framed"] = True
            results["frame_test"]["test_method"] = "no_protection_detected"
            
            # Create a simulated frame test
            results["frame_test"]["simulated_frame"] = f"""
<!DOCTYPE html>
<html>
<head><title>Clickjacking Test</title></head>
<body>
    <h1>Clickjacking Test Page</h1>
    <iframe src="{base_url}" width="800" height="600"></iframe>
    <p>If you can see the target page above, it may be vulnerable to clickjacking.</p>
</body>
</html>
            """.strip()
        
        print("  [+] Frameability test completed")
        
    except Exception as e:
        logger.error(f"Error testing frameability for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def comprehensive_clickjacking_analysis(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive clickjacking protection analysis.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing comprehensive clickjacking analysis results
    """
    print("[*] Performing comprehensive clickjacking analysis...")
    
    results = {
        "url": base_url,
        "protection_analysis": check_clickjacking_protection(base_url),
        "frameability_test": test_frameability(base_url)
    }
    
    # Add security recommendations
    results["security_recommendations"] = [
        "Implement X-Frame-Options header with DENY or SAMEORIGIN value",
        "Implement Content-Security-Policy with frame-ancestors directive",
        "Use both X-Frame-Options and CSP for maximum compatibility",
        "Set frame-ancestors to 'none' for pages that should never be framed",
        "Set frame-ancestors to 'self' for pages that should only be framed by the same origin",
        "Regularly test clickjacking protection mechanisms"
    ]
    
    print("  [+] Comprehensive clickjacking analysis completed")
    
    return results