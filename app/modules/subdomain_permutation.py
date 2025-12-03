"""
Subdomain Permutation Module for Modular ReconX
Enhances subdomain discovery through permutation-based techniques
"""

import itertools
import logging
from typing import List, Set, Dict, Any
from .subdomain_enum import _resolve_subdomain
from .utils import get_resource_path

logger = logging.getLogger(__name__)

# Common prefixes and suffixes for permutation
COMMON_PREFIXES = [
    "www", "mail", "ftp", "dev", "test", "api", "blog", "shop", "store", "vpn",
    "m", "remote", "portal", "staging", "admin", "login", "dashboard", "secure",
    "beta", "cdn", "static", "assets", "img", "images", "js", "css", "files",
    "docs", "support", "help", "status", "stats", "monitor", "console", "manage",
    "manager", "control", "cp", "cpanel", "webmail", "autodiscover", "autoconfig",
    "sip", "smtp", "pop", "pop3", "imap", "cloud", "apps", "app", "mobile", "mobi"
]

COMMON_SUFFIXES = [
    "api", "dev", "test", "staging", "prod", "admin", "login", "portal", "secure",
    "beta", "cdn", "static", "assets", "img", "images", "js", "css", "files",
    "docs", "support", "help", "status", "stats", "monitor", "console", "manage"
]

def _generate_permutations(domain: str, wordlist: List[str]) -> Set[str]:
    """
    Generate permutations of subdomains using common prefixes and suffixes.
    
    Args:
        domain: The target domain (e.g., 'example.com')
        wordlist: List of words to use for permutation
        
    Returns:
        Set of generated subdomain permutations
    """
    permutations = set()
    
    # Add basic words from wordlist
    for word in wordlist:
        if word:
            permutations.add(f"{word}.{domain}")
    
    # Add prefix permutations
    for prefix in COMMON_PREFIXES:
        for word in wordlist:
            if word:
                permutations.add(f"{prefix}-{word}.{domain}")
                permutations.add(f"{prefix}.{word}.{domain}")
    
    # Add suffix permutations
    for suffix in COMMON_SUFFIXES:
        for word in wordlist:
            if word:
                permutations.add(f"{word}-{suffix}.{domain}")
                permutations.add(f"{word}.{suffix}.{domain}")
    
    # Add double permutations (prefix + word + suffix)
    for prefix in COMMON_PREFIXES[:10]:  # Limit to avoid explosion
        for suffix in COMMON_SUFFIXES[:10]:  # Limit to avoid explosion
            for word in wordlist:
                if word:
                    permutations.add(f"{prefix}-{word}-{suffix}.{domain}")
                    permutations.add(f"{prefix}.{word}.{suffix}.{domain}")
    
    return permutations

def _generate_number_permutations(domain: str, wordlist: List[str]) -> Set[str]:
    """
    Generate permutations with numbers (common pattern: www1, www2, etc.)
    
    Args:
        domain: The target domain (e.g., 'example.com')
        wordlist: List of words to use for permutation
        
    Returns:
        Set of generated subdomain permutations with numbers
    """
    permutations = set()
    numbers = ["1", "2", "3", "4", "5", "01", "02", "03", "04", "05"]
    
    for word in wordlist:
        if word:
            # Add number suffixes
            for num in numbers:
                permutations.add(f"{word}{num}.{domain}")
                permutations.add(f"{word}-{num}.{domain}")
            
            # Add number prefixes for common words
            if word in ["www", "mail", "ftp", "dev"]:
                for num in numbers:
                    permutations.add(f"{num}{word}.{domain}")
                    permutations.add(f"{num}-{word}.{domain}")
    
    return permutations

def discover_permutation_subdomains(
    domain: str,
    wordlist_path: str = get_resource_path("data/subdomains.txt"),
    workers: int = 20,  # Lower workers for permutation scanning
    record_types: List[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Discover subdomains through permutation-based techniques.
    
    Args:
        domain: The target domain (e.g., 'example.com')
        wordlist_path: Path to the wordlist file
        workers: Number of concurrent threads to use for DNS resolution
        record_types: List of DNS record types to query
        
    Returns:
        A dictionary containing a list of found subdomains with their records
    """
    if record_types is None:
        record_types = ["A", "AAAA", "CNAME"]
    
    found_subdomains: List[Dict[str, Any]] = []
    
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"Wordlist not found at: {wordlist_path}")
        return {"error": f"Wordlist not found at {wordlist_path}"}
    except Exception as e:
        logger.error(f"Error reading wordlist {wordlist_path}: {e}")
        return {"error": f"Error reading wordlist: {e}"}
    
    # Generate permutations
    logger.info(f"Generating subdomain permutations for {domain}")
    permutations = _generate_permutations(domain, wordlist)
    number_permutations = _generate_number_permutations(domain, wordlist)
    
    # Combine all permutations
    all_permutations = permutations.union(number_permutations)
    logger.info(f"Generated {len(all_permutations)} permutations to check")
    
    # Resolve permutations
    import concurrent.futures
    from tqdm import tqdm
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        # Submit tasks with record_types parameter
        future_to_subdomain = {
            executor.submit(_resolve_subdomain, sub, record_types): sub for sub in all_permutations
        }

        progress = tqdm(
            concurrent.futures.as_completed(future_to_subdomain),
            total=len(all_permutations),
            desc="Permutation Scan",
            unit="doms",
            leave=False,
        )

        for future in progress:
            result = future.result()
            if result:
                found_subdomains.append(result)
                logger.debug(
                    f"Found permutation subdomain: {result['subdomain']} -> IPs: {result.get('ips', [])}"
                )

    # Sort found subdomains alphabetically for consistent output
    found_subdomains.sort(key=lambda x: x["subdomain"])

    logger.info(
        f"Permutation subdomain discovery completed for {domain}. Found {len(found_subdomains)} unique subdomains."
    )
    return {"found": found_subdomains}