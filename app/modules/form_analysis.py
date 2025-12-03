"""
Form Analysis Module for Modular ReconX
Analyzes HTML forms for security issues and potential vulnerabilities
"""

import re
import logging
from typing import Dict, Any, List
from urllib.parse import urljoin
from .http_client import get_http_client

logger = logging.getLogger(__name__)

# Common form action patterns that might indicate vulnerabilities
VULNERABLE_ACTION_PATTERNS = [
    r"(?i)(login|signin|auth)",
    r"(?i)(register|signup|create)",
    r"(?i)(password|reset|recover)",
    r"(?i)(upload|file|image)",
    r"(?i)(admin|manage|control)"
]

# Input field types that are often associated with vulnerabilities
VULNERABLE_INPUT_TYPES = [
    "password", "hidden", "file", "email", "url", "search"
]

# Attributes that should be present for security
REQUIRED_SECURITY_ATTRIBUTES = [
    "autocomplete", "required", "pattern"
]

def analyze_html_forms(base_url: str) -> Dict[str, Any]:
    """
    Analyze HTML forms for security issues and potential vulnerabilities.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing form analysis results
    """
    print("[*] Analyzing HTML forms for security issues...")
    
    results = {
        "url": base_url,
        "forms": [],
        "total_forms": 0,
        "vulnerable_forms": 0,
        "security_issues": []
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Fetch the page
        response = http_client.get(base_url)
        content = response.text
        
        # Extract forms using regex
        form_pattern = r"<form[^>]*>(.*?)</form>"
        forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        results["total_forms"] = len(forms)
        
        for i, form_content in enumerate(forms):
            form_info = {
                "id": i,
                "attributes": {},
                "inputs": [],
                "security_analysis": {
                    "vulnerability_indicators": [],
                    "missing_security_features": [],
                    "risk_score": 0
                }
            }
            
            # Extract form attributes
            attr_pattern = r'([a-zA-Z\-]+)=["\']([^"\']*)["\']'
            attributes = re.findall(attr_pattern, form_content)
            
            for attr_name, attr_value in attributes:
                form_info["attributes"][attr_name.lower()] = attr_value
            
            # Analyze action attribute
            action = form_info["attributes"].get("action", "")
            if action:
                form_info["attributes"]["full_action"] = urljoin(base_url, action)
                
                # Check for vulnerable action patterns
                for pattern in VULNERABLE_ACTION_PATTERNS:
                    if re.search(pattern, action):
                        form_info["security_analysis"]["vulnerability_indicators"].append({
                            "type": "vulnerable_action",
                            "pattern": pattern,
                            "action": action
                        })
            
            # Analyze method attribute
            method = form_info["attributes"].get("method", "GET").upper()
            form_info["attributes"]["method"] = method
            
            if method == "GET" and any(indicator["type"] == "vulnerable_action" 
                                      for indicator in form_info["security_analysis"]["vulnerability_indicators"]):
                form_info["security_analysis"]["vulnerability_indicators"].append({
                    "type": "insecure_method",
                    "issue": "GET method used for potentially sensitive action"
                })
            
            # Extract input fields
            input_pattern = r"<input[^>]*>"
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_tag in inputs:
                input_info = {"attributes": {}}
                
                # Extract all attributes
                input_attributes = re.findall(attr_pattern, input_tag)
                for attr_name, attr_value in input_attributes:
                    input_info["attributes"][attr_name.lower()] = attr_value
                
                # Check for vulnerable input types
                input_type = input_info["attributes"].get("type", "text").lower()
                if input_type in VULNERABLE_INPUT_TYPES:
                    input_info["vulnerability_indicator"] = True
                    form_info["security_analysis"]["vulnerability_indicators"].append({
                        "type": "vulnerable_input_type",
                        "input_type": input_type
                    })
                
                # Check for missing security attributes
                missing_attrs = []
                for attr in REQUIRED_SECURITY_ATTRIBUTES:
                    if attr not in input_info["attributes"]:
                        missing_attrs.append(attr)
                
                if missing_attrs:
                    input_info["missing_security_attributes"] = missing_attrs
                    form_info["security_analysis"]["missing_security_features"].extend(missing_attrs)
                
                # Check for password fields without autocomplete=off
                if input_type == "password" and input_info["attributes"].get("autocomplete", "") != "off":
                    form_info["security_analysis"]["vulnerability_indicators"].append({
                        "type": "password_autocomplete",
                        "issue": "Password field without autocomplete=off"
                    })
                
                form_info["inputs"].append(input_info)
            
            # Calculate risk score
            vulnerability_count = len(form_info["security_analysis"]["vulnerability_indicators"])
            missing_features_count = len(set(form_info["security_analysis"]["missing_security_features"]))
            form_info["security_analysis"]["risk_score"] = vulnerability_count * 2 + missing_features_count
            
            # Increment vulnerable forms counter
            if form_info["security_analysis"]["risk_score"] > 0:
                results["vulnerable_forms"] += 1
            
            results["forms"].append(form_info)
        
        # Add overall security issues
        if results["vulnerable_forms"] > 0:
            results["security_issues"].append({
                "type": "vulnerable_forms",
                "count": results["vulnerable_forms"],
                "description": f"Found {results['vulnerable_forms']} forms with potential security issues"
            })
        
        print(f"  [+] Form analysis completed ({results['vulnerable_forms']}/{results['total_forms']} forms with issues)")
        
    except Exception as e:
        logger.error(f"Error analyzing HTML forms for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def check_form_security_features(base_url: str) -> Dict[str, Any]:
    """
    Check for specific form security features like CSRF protection.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing form security feature analysis
    """
    print("[*] Checking form security features...")
    
    results = {
        "url": base_url,
        "csrf_protection": {
            "found": False,
            "tokens": [],
            "issues": []
        },
        "form_validation": {
            "client_side": False,
            "server_side_indicators": []
        }
    }
    
    try:
        # Get HTTP client
        http_client = get_http_client()
        
        # Fetch the page
        response = http_client.get(base_url)
        content = response.text
        
        # Check for CSRF tokens
        csrf_patterns = [
            r"<input[^>]*name=[\"']csrf[_\-]token[\"'][^>]*value=[\"']([^\"']+)[\"'][^>]*>",
            r"<input[^>]*name=[\"']_token[\"'][^>]*value=[\"']([^\"']+)[\"'][^>]*>",
            r"<meta[^>]*name=[\"']csrf[_\-]token[\"'][^>]*content=[\"']([^\"']+)[\"'][^>]*>"
        ]
        
        for pattern in csrf_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                results["csrf_protection"]["found"] = True
                results["csrf_protection"]["tokens"].extend(matches)
        
        if not results["csrf_protection"]["found"]:
            results["csrf_protection"]["issues"].append("No CSRF protection tokens found")
        
        # Check for client-side validation
        validation_patterns = [
            r"required\s*[=\"]",
            r"pattern\s*=",
            r"onsubmit\s*=",
            r"onchange\s*=",
            r"oninput\s*="
        ]
        
        for pattern in validation_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                results["form_validation"]["client_side"] = True
                break
        
        print(f"  [+] Form security feature check completed (CSRF Protection: {'Found' if results['csrf_protection']['found'] else 'Not Found'})")
        
    except Exception as e:
        logger.error(f"Error checking form security features for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def comprehensive_form_analysis(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive form analysis for security issues.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing comprehensive form analysis results
    """
    print("[*] Performing comprehensive form analysis...")
    
    results = {
        "url": base_url,
        "form_analysis": analyze_html_forms(base_url),
        "security_features": check_form_security_features(base_url)
    }
    
    # Add security recommendations
    results["security_recommendations"] = [
        "Implement CSRF protection tokens in all forms",
        "Use POST method for sensitive actions",
        "Add autocomplete=off to password fields",
        "Implement proper input validation both client-side and server-side",
        "Use HTTPS for all forms handling sensitive data",
        "Add proper error handling without revealing system information"
    ]
    
    print("  [+] Comprehensive form analysis completed")
    
    return results