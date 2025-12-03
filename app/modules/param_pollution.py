"""
HTTP Parameter Pollution Detector for Modular ReconX
Detects potential HTTP Parameter Pollution vulnerabilities
"""

import logging
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .http_client import get_http_client

logger = logging.getLogger(__name__)

def detect_parameter_pollution(base_url: str) -> Dict[str, Any]:
    """
    Detect potential HTTP Parameter Pollution vulnerabilities.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing parameter pollution analysis results
    """
    print("[*] Detecting HTTP Parameter Pollution vulnerabilities...")
    
    results = {
        "url": base_url,
        "original_params": {},
        "pollution_tests": [],
        "vulnerability_assessment": {
            "vulnerable": False,
            "risk_level": "low",
            "issues": []
        }
    }
    
    try:
        # Parse the URL to extract parameters
        parsed_url = urlparse(base_url)
        original_params = parse_qs(parsed_url.query)
        results["original_params"] = original_params
        
        # If no parameters, no need to test
        if not original_params:
            results["vulnerability_assessment"]["issues"].append("No query parameters found to test")
            print("  [+] No parameters to test for pollution")
            return results
        
        # Get HTTP client
        http_client = get_http_client()
        
        # Test each parameter for duplication
        for param_name, param_values in original_params.items():
            # Create a test URL with duplicated parameter
            test_params = original_params.copy()
            # Add the same parameter again with a test value
            test_params[param_name] = param_values + ["POLLUTION_TEST"]
            
            # Reconstruct URL with duplicated parameters
            query_string = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                query_string,
                parsed_url.fragment
            ))
            
            # Test the polluted URL
            try:
                response = http_client.get(test_url)
                
                # Store test results
                test_result = {
                    "parameter": param_name,
                    "original_values": param_values,
                    "test_url": test_url,
                    "status_code": response.status_code,
                    "response_length": len(response.content),
                    "indicators": []
                }
                
                # Check for potential pollution indicators
                # Look for the test value in the response
                response_text = response.text.lower()
                test_value_lower = "pollution_test".lower()
                
                if test_value_lower in response_text:
                    test_result["indicators"].append("Test value found in response")
                    results["vulnerability_assessment"]["vulnerable"] = True
                    if results["vulnerability_assessment"]["risk_level"] != "high":
                        results["vulnerability_assessment"]["risk_level"] = "medium"
                
                # Check for duplicated content or unusual responses
                if response.status_code not in [200, 301, 302]:
                    test_result["indicators"].append(f"Unusual status code: {response.status_code}")
                
                results["pollution_tests"].append(test_result)
                
            except Exception as e:
                logger.error(f"Error testing parameter pollution for {param_name}: {e}")
                results["pollution_tests"].append({
                    "parameter": param_name,
                    "error": str(e)
                })
        
        # Assess overall vulnerability
        vulnerable_tests = [test for test in results["pollution_tests"] if test.get("indicators")]
        if vulnerable_tests:
            results["vulnerability_assessment"]["vulnerable"] = True
            results["vulnerability_assessment"]["risk_level"] = "high"
            results["vulnerability_assessment"]["issues"].append(
                f"Found {len(vulnerable_tests)} parameters that may be vulnerable to HTTP Parameter Pollution"
            )
        
        print(f"  [+] Parameter pollution detection completed ({len(results['pollution_tests'])} parameters tested)")
        
    except Exception as e:
        logger.error(f"Error detecting parameter pollution for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def analyze_parameter_handling(base_url: str) -> Dict[str, Any]:
    """
    Analyze how the application handles multiple parameters with the same name.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing parameter handling analysis results
    """
    print("[*] Analyzing parameter handling behavior...")
    
    results = {
        "url": base_url,
        "parameter_behavior": {},
        "backend_analysis": {
            "likely_technologies": [],
            "behavior_patterns": []
        }
    }
    
    try:
        # Parse the URL to extract parameters
        parsed_url = urlparse(base_url)
        original_params = parse_qs(parsed_url.query)
        
        # If no parameters, no need to test
        if not original_params:
            results["note"] = "No query parameters found to analyze"
            print("  [+] No parameters to analyze for handling behavior")
            return results
        
        # Get HTTP client
        http_client = get_http_client()
        
        # Test parameter handling for common backend technologies
        backend_indicators = {
            "PHP": {
                "pattern": "array(",
                "description": "PHP uses the last parameter value or creates arrays"
            },
            "ASP.NET": {
                "pattern": "System.String[]",
                "description": "ASP.NET creates string arrays for duplicate parameters"
            },
            "Java/Spring": {
                "pattern": "[",
                "description": "Java frameworks typically use the first parameter value"
            }
        }
        
        # Test with multiple values for the first parameter
        first_param = list(original_params.keys())[0]
        first_param_values = original_params[first_param]
        
        # Create test with multiple values
        test_params = original_params.copy()
        test_params[first_param] = first_param_values + ["TEST_VALUE_1", "TEST_VALUE_2"]
        
        # Reconstruct URL
        query_string = urlencode(test_params, doseq=True)
        test_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            query_string,
            parsed_url.fragment
        ))
        
        # Make request
        response = http_client.get(test_url)
        response_text = response.text
        
        # Analyze response for backend indicators
        for tech, info in backend_indicators.items():
            if info["pattern"] in response_text:
                results["backend_analysis"]["likely_technologies"].append({
                    "technology": tech,
                    "indicator": info["pattern"],
                    "confidence": "high"
                })
        
        # Analyze general behavior
        if "TEST_VALUE_1" in response_text and "TEST_VALUE_2" in response_text:
            results["backend_analysis"]["behavior_patterns"].append("All parameter values are processed")
        elif "TEST_VALUE_2" in response_text:
            results["backend_analysis"]["behavior_patterns"].append("Last parameter value is used")
        elif "TEST_VALUE_1" in response_text:
            results["backend_analysis"]["behavior_patterns"].append("First parameter value is used")
        else:
            results["backend_analysis"]["behavior_patterns"].append("Parameter values are filtered or escaped")
        
        print("  [+] Parameter handling analysis completed")
        
    except Exception as e:
        logger.error(f"Error analyzing parameter handling for {base_url}: {e}")
        results["error"] = str(e)
    
    return results

def comprehensive_parameter_pollution_analysis(base_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive HTTP Parameter Pollution analysis.
    
    Args:
        base_url: The base URL to analyze
        
    Returns:
        Dictionary containing comprehensive parameter pollution analysis results
    """
    print("[*] Performing comprehensive HTTP Parameter Pollution analysis...")
    
    results = {
        "url": base_url,
        "pollution_detection": detect_parameter_pollution(base_url),
        "parameter_handling": analyze_parameter_handling(base_url)
    }
    
    # Add security recommendations
    results["security_recommendations"] = [
        "Validate and sanitize all input parameters",
        "Implement proper parameter parsing that handles duplicates safely",
        "Use allowlists for expected parameters and values",
        "Implement consistent parameter handling across all application layers",
        "Log and monitor for unusual parameter patterns",
        "Use web application firewalls to detect parameter pollution attempts",
        "Test applications with multiple parameters of the same name",
        "Implement proper input validation for all parameter values"
    ]
    
    print("  [+] Comprehensive HTTP Parameter Pollution analysis completed")
    
    return results