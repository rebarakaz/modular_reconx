"""
Comprehensive Technology Detection Module for Modular ReconX
Combines multiple detection methods for more accurate technology identification
"""

import logging
from typing import Dict, Any, List
from .tech_stack import get_tech_stack
from .builtwith_scan import detect_builtwith

logger = logging.getLogger(__name__)

def comprehensive_tech_detection(url: str, domain: str = None) -> Dict[str, Any]:
    """
    Perform comprehensive technology detection using multiple methods.
    
    Args:
        url: The URL to scan (e.g., 'http://example.com')
        domain: Optional domain name for BuiltWith scan
        
    Returns:
        Dictionary containing comprehensive technology detection results
    """
    if domain is None:
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
    
    results = {
        "url": url,
        "domain": domain,
        "methods": {}
    }
    
    # Method 1: HTTP header and HTML analysis
    print("[*] Performing HTTP header and HTML analysis...")
    try:
        tech_stack_results = get_tech_stack(url)
        results["methods"]["http_analysis"] = tech_stack_results
        print("  [+] HTTP header and HTML analysis completed")
    except Exception as e:
        logger.error(f"HTTP analysis failed: {e}")
        results["methods"]["http_analysis"] = {"error": str(e)}
    
    # Method 2: BuiltWith API scan
    print("[*] Performing BuiltWith API scan...")
    try:
        builtwith_results = detect_builtwith(domain)
        results["methods"]["builtwith"] = builtwith_results
        print("  [+] BuiltWith API scan completed")
    except Exception as e:
        logger.error(f"BuiltWith scan failed: {e}")
        results["methods"]["builtwith"] = {"error": str(e)}
    
    # Method 3: Additional passive detection methods
    print("[*] Performing passive technology detection...")
    try:
        passive_results = _passive_detection(url)
        results["methods"]["passive_detection"] = passive_results
        print("  [+] Passive technology detection completed")
    except Exception as e:
        logger.error(f"Passive detection failed: {e}")
        results["methods"]["passive_detection"] = {"error": str(e)}
    
    # Consolidate results
    results["consolidated"] = _consolidate_results(results["methods"])
    
    return results

def _passive_detection(url: str) -> Dict[str, Any]:
    """
    Perform passive technology detection using publicly available information.
    
    Args:
        url: The URL to scan
        
    Returns:
        Dictionary containing passive detection results
    """
    # This would include methods like:
    # - DNS TXT record analysis
    # - DNS subdomain enumeration for known services
    # - Certificate transparency log analysis
    # - WHOIS data analysis
    # - Social media footprint analysis
    
    results = {
        "dns_analysis": _analyze_dns_records(url),
        "certificate_info": _analyze_certificate_info(url),
        "social_footprint": _analyze_social_footprint(url)
    }
    
    return results

def _analyze_dns_records(url: str) -> Dict[str, Any]:
    """
    Analyze DNS records for technology indicators.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary containing DNS analysis results
    """
    # This would analyze DNS records for:
    # - MX records (email services)
    # - TXT records (SPF, DKIM, etc.)
    # - CNAME records (CDN, cloud services)
    # - NS records (DNS providers)
    
    return {
        "note": "DNS analysis would be implemented here",
        "potential_indicators": [
            "MX records can indicate email service providers",
            "CNAME records can reveal CDN or cloud service usage",
            "TXT records can show security configurations"
        ]
    }

def _analyze_certificate_info(url: str) -> Dict[str, Any]:
    """
    Analyze SSL/TLS certificate information.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary containing certificate analysis results
    """
    # This would analyze:
    # - Certificate issuer (Let's Encrypt, DigiCert, etc.)
    # - Certificate transparency logs
    # - Certificate extensions
    # - SAN (Subject Alternative Names)
    
    return {
        "note": "Certificate analysis would be implemented here",
        "potential_indicators": [
            "Certificate issuer can indicate hosting providers",
            "SAN entries can reveal related domains/subdomains",
            "Certificate transparency logs can show infrastructure details"
        ]
    }

def _analyze_social_footprint(url: str) -> Dict[str, Any]:
    """
    Analyze social media footprint for technology indicators.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary containing social footprint analysis results
    """
    # This would analyze:
    # - Social media accounts linked to the domain
    # - Developer profiles mentioning the technology stack
    # - Job postings that reveal technology choices
    # - GitHub/GitLab repositories
    
    return {
        "note": "Social footprint analysis would be implemented here",
        "potential_indicators": [
            "Social media accounts can reveal company technology choices",
            "Job postings often mention required technical skills",
            "Developer profiles may show preferred technologies"
        ]
    }

def _consolidate_results(method_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Consolidate results from multiple detection methods.
    
    Args:
        method_results: Dictionary containing results from all methods
        
    Returns:
        Dictionary containing consolidated results
    """
    consolidated = {
        "technologies": [],
        "cms": [],
        "frameworks": [],
        "languages": [],
        "servers": [],
        "hosting": [],
        "security": [],
        "confidence_scores": {}
    }
    
    # Extract information from HTTP analysis
    http_results = method_results.get("http_analysis", {})
    if isinstance(http_results, dict) and "error" not in http_results:
        # Extract technologies
        techs = http_results.get("detected_technologies", [])
        consolidated["technologies"].extend(techs)
        
        # Extract CMS
        cms_indicators = ["WordPress", "Joomla", "Drupal", "Magento", "Shopify"]
        for tech in techs:
            if tech in cms_indicators:
                consolidated["cms"].append(tech)
        
        # Extract frameworks and languages
        framework_indicators = ["React", "Vue.js", "Angular", "Next.js", "Nuxt.js", "Django", "Flask", "Express"]
        language_indicators = ["PHP", "Python", "Node.js", "Ruby", "Java", "ASP.NET", "Go"]
        for tech in techs:
            if tech in framework_indicators:
                consolidated["frameworks"].append(tech)
            elif tech in language_indicators:
                consolidated["languages"].append(tech)
        
        # Extract servers
        server = http_results.get("server", "")
        if server and server != "Not specified":
            consolidated["servers"].append(server)
        
        # Extract security information
        wafs = http_results.get("detected_wafs", [])
        consolidated["security"].extend(wafs)
        
        cloud_services = http_results.get("detected_cloud_services", [])
        consolidated["hosting"].extend(cloud_services)
    
    # Extract information from BuiltWith results
    bw_results = method_results.get("builtwith", {})
    if isinstance(bw_results, dict) and "error" not in bw_results:
        # BuiltWith returns categorized technology data
        for category, tech_list in bw_results.items():
            if isinstance(tech_list, list):
                for tech_info in tech_list:
                    if isinstance(tech_info, str) and "/" in tech_info:
                        # Format: "Technology/Version"
                        tech_name = tech_info.split("/")[0]
                        consolidated["technologies"].append(tech_name)
    
    # Remove duplicates and sort
    for key in consolidated:
        if isinstance(consolidated[key], list):
            consolidated[key] = sorted(list(set(consolidated[key])))
    
    return consolidated