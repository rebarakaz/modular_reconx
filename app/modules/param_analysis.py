"""
Parameter Analysis Module for Modular ReconX
Identifies potential injection points and vulnerable parameters in web applications
"""

import re
import logging
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from .http_client import get_http_client

logger = logging.getLogger(__name__)

# Common parameter names that are often vulnerable to injection attacks
INJECTION_PRONE_PARAMS = {
    "id", "user", "user_id", "uid", "account", "account_id", "product", "product_id",
    "category", "cat", "search", "query", "q", "page", "redirect", "redirect_to",
    "url", "uri", "path", "file", "filename", "dir", "directory", "cmd", "exec",
    "command", "execute", "ping", "ip", "host", "domain", "email", "mail", "to",
    "from", "subject", "message", "msg", "content", "comment", "desc", "description",
    "title", "name", "username", "password", "pass", "pwd", "token", "key", "api_key",
    "apikey", "secret", "signature", "sig", "callback", "next", "return", "rurl",
    "destination", "dest", "continue", "view", "template", "layout", "style", "theme",
    "lang", "language", "locale", "debug", "test", "config", "cfg", "setting", "option",
    "sort", "order", "by", "limit", "offset", "size", "count", "num", "number", "index",
    "ref", "reference", "source", "src", "target", "action", "do", "func", "function",
    "method", "op", "operation", "type", "mode", "format", "ext", "extension"
}

# Common patterns in URLs that might indicate dynamic content
DYNAMIC_URL_PATTERNS = [
    r"[?&][^=]+=[^&]*",  # Query parameters
    r"/\d+/",             # Numeric IDs in paths
    r"/[^/]*\.[^/]*$",    # File extensions
]

def analyze_url_parameters(url: str) -> Dict[str, Any]:
    """
    Analyze URL parameters for potential injection points.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary containing analysis results
    """
    results = {
        "url": url,
        "parameters": [],
        "injection_prone_params": [],
        "dynamic_indicators": [],
        "risk_score": 0
    }
    
    try:
        # Parse URL and extract query parameters
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Analyze each parameter
        for param_name, param_values in query_params.items():
            param_info = {
                "name": param_name,
                "values": param_values,
                "injection_risk": param_name.lower() in INJECTION_PRONE_PARAMS,
                "length": len(param_values[0]) if param_values else 0
            }
            
            results["parameters"].append(param_info)
            
            # Check if parameter is prone to injection
            if param_info["injection_risk"]:
                results["injection_prone_params"].append(param_name)
        
        # Check for dynamic URL patterns
        for pattern in DYNAMIC_URL_PATTERNS:
            if re.search(pattern, url):
                results["dynamic_indicators"].append(pattern)
        
        # Calculate risk score
        results["risk_score"] = len(results["injection_prone_params"]) * 2 + len(results["dynamic_indicators"])
        
    except Exception as e:
        logger.error(f"Error analyzing URL parameters for {url}: {e}")
        results["error"] = str(e)
    
    return results

def analyze_form_parameters(base_url: str) -> Dict[str, Any]:
    """
    Analyze HTML forms for potential injection points.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing form analysis results
    """
    results = {
        "url": base_url,
        "forms": [],
        "input_fields": [],
        "injection_prone_inputs": [],
        "risk_score": 0
    }
    
    try:
        # Get HTTP client with appropriate settings
        http_client = get_http_client()
        
        # Fetch the page
        response = http_client.get(base_url)
        content = response.text
        
        # Extract forms using regex (simplified approach)
        form_pattern = r"<form[^>]*>(.*?)</form>"
        forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
        
        for i, form_content in enumerate(forms):
            form_info = {
                "id": i,
                "inputs": [],
                "action": "",
                "method": "GET"
            }
            
            # Extract action attribute
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            if action_match:
                form_info["action"] = action_match.group(1)
            
            # Extract method attribute
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            if method_match:
                form_info["method"] = method_match.group(1).upper()
            
            # Extract input fields
            input_pattern = r"<input[^>]*>"
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_tag in inputs:
                input_info = {}
                
                # Extract name attribute
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                if name_match:
                    input_info["name"] = name_match.group(1)
                    
                    # Check if input name is prone to injection
                    if input_info["name"].lower() in INJECTION_PRONE_PARAMS:
                        results["injection_prone_inputs"].append(input_info["name"])
                        input_info["injection_risk"] = True
                    else:
                        input_info["injection_risk"] = False
                
                # Extract type attribute
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                if type_match:
                    input_info["type"] = type_match.group(1).lower()
                else:
                    input_info["type"] = "text"  # Default type
                
                # Extract other attributes
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                if value_match:
                    input_info["value"] = value_match.group(1)
                
                form_info["inputs"].append(input_info)
                results["input_fields"].append(input_info)
            
            results["forms"].append(form_info)
        
        # Calculate risk score
        results["risk_score"] = len(results["injection_prone_inputs"])
        
    except Exception as e:
        logger.error(f"Error analyzing form parameters for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def comprehensive_param_analysis(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive parameter analysis including URL and form analysis.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing comprehensive parameter analysis results
    """
    print("[*] Performing comprehensive parameter analysis...")
    
    results = {
        "url_analysis": analyze_url_parameters(base_url),
        "form_analysis": analyze_form_parameters(base_url)
    }
    
    # Calculate overall risk score
    url_risk = results["url_analysis"].get("risk_score", 0)
    form_risk = results["form_analysis"].get("risk_score", 0)
    results["overall_risk_score"] = url_risk + form_risk
    
    print(f"  [+] Parameter analysis completed (Risk Score: {results['overall_risk_score']})")
    
    return results