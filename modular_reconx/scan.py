import argparse
import concurrent.futures
import logging
import re
import sys
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from pyfiglet import figlet_format
from termcolor import colored

# Local application imports
from modules.breach_check import check_email_breach
from modules.builtwith_scan import detect_builtwith
from modules.dns_lookup import get_dns
from modules.geoip_lookup import geoip_lookup
from modules.ip_lookup import get_ip
from modules.path_bruteforce import bruteforce_paths
from modules.port_scanner import scan_ports
from modules.reverse_ip import reverse_ip_lookup
from modules.social_finder import find_social_links
from modules.ssl_cert_info import get_ssl_info
from modules.subdomain_enum import enumerate_subdomains
from modules.tech_stack import get_tech_stack
from modules.utils import save_report
from modules.vuln_scanner import (
    check_versioned_vulnerabilities,
    search_general_vulnerabilities,
)
from modules.wayback_machine import get_wayback_urls
from modules.whois_lookup import get_whois
from modules.wp_scanner import scan_wordpress_site
from modules.ct_log_monitor import monitor_certificate_transparency

# Load environment variables
load_dotenv()

# Version information
VERSION = "1.1"


def setup_logging() -> None:
    """
    Configures a file logger to record errors and important events.
    The log file is overwritten on each run.
    """
    # We configure the root logger to catch logs from all modules.
    # Using 'w' to overwrite the log file for each new scan session.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        filename="osint_tool.log",
        filemode="w",
    )


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format.

    Args:
        domain: The domain name to validate

    Returns:
        True if valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False

    # Remove whitespace
    domain = domain.strip()

    # Basic length check
    if len(domain) > 253:
        return False

    # Regex pattern for domain validation
    pattern = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    return bool(pattern.match(domain))


def filter_related_domains(
    target_whois: Dict[str, Any], reverse_ip_results: Dict[str, Any]
) -> Dict[str, List[str]]:
    """
    Analyze reverse IP results and filter them based on WHOIS similarity.
    """
    filtered_results = {"likely_related": [], "other_neighbors": []}

    # Get registrar name from the main target domain
    target_registrar = target_whois.get("registrar")
    if not target_registrar or not reverse_ip_results.get("domains"):
        # If not enough data, return the list as is
        filtered_results["other_neighbors"] = reverse_ip_results.get("domains", [])
        return filtered_results

    # Get domain list from reverse IP results
    neighbor_domains = reverse_ip_results.get("domains", [])

    print(
        f"[*] Starting WHOIS correlation for {len(neighbor_domains)} neighboring domains (this may be slow)..."
    )

    for domain in neighbor_domains:
        # Validate domain before processing
        if not validate_domain(domain):
            filtered_results["other_neighbors"].append(domain)
            logging.warning(f"Invalid domain format for neighboring domain {domain}")
            continue

        # Call the whois module for each neighboring domain
        try:
            neighbor_whois = get_whois(domain)  # Calling get_whois function from module
            neighbor_registrar = neighbor_whois.get("registrar")

            # Compare registrars. This is a simple method, can be developed further
            if (
                neighbor_registrar
                and target_registrar.lower() == neighbor_registrar.lower()
            ):
                filtered_results["likely_related"].append(domain)
            else:
                filtered_results["other_neighbors"].append(domain)
        except Exception as e:
            # If WHOIS for neighboring domain fails, consider it unrelated
            filtered_results["other_neighbors"].append(domain)
            logging.warning(
                f"Failed to perform WHOIS lookup for neighboring domain {domain}: {e}"
            )

    return filtered_results


def scan(
    domain: str,
    output_format: str,
    skip_ports: bool = False,
    skip_bruteforce: bool = False,
    correlate_domains: bool = False,
) -> None:
    # Validate input domain
    if not validate_domain(domain):
        print(f"[!] Invalid domain format: {domain}")
        logging.error(f"Invalid domain format: {domain}")
        return

    print(f"\n[🔎] Starting OSINT scan for: {domain}")
    logging.info(f"Starting new OSINT scan for domain: {domain}")
    results: Dict[str, Any] = {"domain": domain}

    # Define scans that only need a domain name (passive)
    scans_to_run = {
        "whois": (get_whois, domain),
        "dns": (get_dns, domain),
        "subdomains": (enumerate_subdomains, domain),
        "social_links": (find_social_links, domain),
        "wayback_urls": (get_wayback_urls, domain),
        "certificate_transparency": (monitor_certificate_transparency, domain),
    }

    # Initial IP lookup is blocking, as many other scans depend on it.
    print("[*] Looking up main IP...")
    ip = get_ip(domain)
    base_url = f"http://{domain}"

    # Determine if active scans that require a live host are possible.
    if not ip:
        print(f"  [!] Failed to get IP for {domain}. Active scans will be skipped.")
        logging.warning(f"Could not resolve IP for {domain}. Skipping active scans.")
        results["error"] = "IP address could not be resolved."
    else:
        results["ip_address"] = ip
        print(f"  [+] Found IP: {ip}")
        # base_url is already defined above

        # Add active scans to the list
        active_scans = {
            "tech_stack": (get_tech_stack, base_url),
            "builtwith": (detect_builtwith, domain),
            "geoip": (geoip_lookup, ip),
            "reverse_ip": (reverse_ip_lookup, ip),
            "ssl_certificate": (get_ssl_info, domain),
        }
        if not skip_ports:
            active_scans["open_ports"] = (scan_ports, ip)
        if not skip_bruteforce:
            active_scans["paths_found"] = (bruteforce_paths, base_url)
        scans_to_run.update(active_scans)

    # Use ThreadPoolExecutor for cleaner and more modern concurrency management.
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(scans_to_run)
    ) as executor:
        future_to_key = {
            executor.submit(func, *args): key
            for key, (func, *args) in scans_to_run.items()
        }

        print("[*] Running concurrent scans...")
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
                print(f"  [+] Completed: {key}")
            except Exception as exc:
                results[key] = {"error": f"Failed to run {key}: {exc}"}
                print(f"  [!] Failed: {key}")
                logging.error(
                    f"Module '{key}' failed for domain '{domain}'", exc_info=True
                )

    # --- IMPORTANT: Extract required results after all concurrent scans are complete ---
    builtwith_results = results.get("builtwith", {})
    tech_stack_results = results.get("tech_stack", {})

    # Get the primary email for breach checking from WHOIS results
    primary_email: Optional[str] = None
    whois_data = results.get("whois", {})
    if isinstance(whois_data, dict):
        whois_emails = whois_data.get("emails")
        if isinstance(whois_emails, list) and whois_emails:
            primary_email = whois_emails[0]
        elif isinstance(whois_emails, str):
            primary_email = whois_emails

    if primary_email:
        print("[*] Checking for data breaches for email...")
        results["breach_check"] = check_email_breach(primary_email)
        print("  [+] Completed: breach_check")
    else:
        results["breach_check"] = {"note": "No email found in WHOIS"}

    # Check for versioned vulnerabilities based on tech stack
    # Ensure builtwith_results is a dict and not an error or empty
    if builtwith_results and not builtwith_results.get("error"):
        print(
            "  [+] Starting: vulnerability check based on technology (Vulners.com)..."
        )
        results["vulnerabilities"] = check_versioned_vulnerabilities(
            builtwith_results, tech_stack_results
        )
        print("  [+] Completed: vulnerability check")
    else:  # This is the branch if builtwith_results is not available or there's an error
        results["vulnerabilities"] = {
            "note": "Version-specific vulnerability check skipped (BuiltWith data not available or error)."
        }

    # Perform general keyword vulnerability search
    print(
        "  [+] Starting: general vulnerability search based on keywords (Vulners.com)..."
    )
    # Use server or x_powered_by from tech_stack, or domain as fallback keyword
    keyword = (
        tech_stack_results.get("server")
        or tech_stack_results.get("x_powered_by")
        or domain
    )
    results["vulnerabilities_by_keyword"] = search_general_vulnerabilities(keyword)
    print("  [+] Completed: vulnerabilities_by_keyword")

    # --- "NOISY NEIGHBORS" CORRELATION FEATURE (FINAL VERSION) ---
    if correlate_domains:
        # This feature only runs if the user requests it with the --correlate flag
        print("\n[*] --correlate option active. Starting domain correlation...")
        if "error" not in results.get("reverse_ip", {}) and "error" not in results.get(
            "whois", {}
        ):
            correlated_domains = filter_related_domains(
                results["whois"], results["reverse_ip"]
            )
            results["correlated_reverse_ip"] = correlated_domains
            print("[+] Domain correlation completed.")
        else:
            results["correlated_reverse_ip"] = {
                "note": "Domain correlation skipped due to incomplete WHOIS or Reverse IP data."
            }
    else:
        # If no flag, don't add this key to the report
        pass

    # --- NEW FEATURE: WordPress Specific Scanner ---
    # Check for WordPress from various sources for better reliability
    is_wordpress = False
    generator_info = results.get("tech_stack", {}).get("generator", "")
    if generator_info and "wordpress" in generator_info.lower():
        is_wordpress = True

    # Fallback to check builtwith results if generator doesn't mention WordPress
    if not is_wordpress:
        builtwith_cms = results.get("builtwith", {}).get("cms", [])
        if any("wordpress" in cms.lower() for cms in builtwith_cms):
            is_wordpress = True

    if is_wordpress:
        print("\n[*] WordPress detected. Starting comprehensive plugin scan with WPScan...")
        
        # Use the enhanced WordPress scanner
        wpscan_results = scan_wordpress_site(base_url)
        
        # Save the results in the main report
        results["wpscan_results"] = wpscan_results
        print("[+] Completed: WPScan comprehensive scan")
        print(f"    - Plugins detected: {wpscan_results.get('scan_summary', {}).get('total_plugins_detected', 0)}")
        print(f"    - Vulnerable plugins: {wpscan_results.get('scan_summary', {}).get('vulnerable_plugins', 0)}")
        print(f"    - Total vulnerabilities: {wpscan_results.get('scan_summary', {}).get('total_vulnerabilities', 0)}")

    filename = save_report(results, output_format)
    print(f"\n✅ Results saved to: {filename}\n")


def main():
    """Main function to run the OSINT tool from the command line."""
    parser = argparse.ArgumentParser(
        description="Modular ReconX - Advanced OSINT reconnaissance tool."
    )
    parser.add_argument("domain", help="The domain to scan (e.g., example.com)")
    parser.add_argument(
        "--output",
        choices=["json", "txt"],
        default="json",
        help="The output format for the report (json or txt).",
    )
    parser.add_argument(
        "--skip-ports", action="store_true", help="Skip the port scanning module."
    )
    parser.add_argument(
        "--skip-bruteforce",
        action="store_true",
        help="Skip the path bruteforcing module.",
    )

    # --- ADD NEW ARGUMENT HERE ---
    parser.add_argument(
        "--correlate",
        action="store_true",
        help="Correlate reverse IP results by checking WHOIS similarity (slow).",
    )
    parser.add_argument(
        "--version", action="version", version=f"Modular ReconX v{VERSION}"
    )
    setup_logging()
    args = parser.parse_args()

    # Validate input domain
    target_domain = args.domain.strip()
    if not validate_domain(target_domain):
        print(f"[!] Invalid domain format: {target_domain}")
        sys.exit(1)

    banner = figlet_format("Modular ReconX", font="slant")
    print(colored(banner, "cyan"))
    print(
        colored(
            f"Advanced OSINT Tool v{VERSION} | Made with 💖 by Chrisnov & Nai Momang 💻🕵️‍\n",
            "magenta",
        )
    )

    scan(
        target_domain,
        output_format=args.output,
        skip_ports=args.skip_ports,
        skip_bruteforce=args.skip_bruteforce,
        correlate_domains=args.correlate,
    )


if __name__ == "__main__":
    main()
