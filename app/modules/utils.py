import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, List, Union

try:
    # Python 3.9+
    from importlib.resources import files
except ImportError:
    # Python 3.8
    from importlib_resources import files  # pyright: ignore[reportMissingImports]


def get_resource_path(relative_path: str) -> str:
    """
    Get the absolute path to a resource, works for development and for PyInstaller.
    When running as a bundle, PyInstaller stores data files in a temporary
    folder and puts the path in `sys._MEIPASS`.
    
    For package data, this function will correctly locate files in the app/data directory.
    """
    try:
        # Use getattr to avoid linter warnings about _MEIPASS
        base_path = getattr(sys, "_MEIPASS", None)
        if base_path:
            # Running as PyInstaller bundle
            return os.path.join(base_path, relative_path)
        
        # Try to locate as package data first
        try:
            # For files in app/data directory
            if relative_path.startswith("data/"):
                data_file = files('app').joinpath(relative_path)
                if data_file.is_file():
                    return str(data_file)
        except Exception:
            pass
            
        # Fallback to current directory for development
        base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    except Exception:
        base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)


def timestamp() -> str:
    """Generate a timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _generate_filename(domain: str, extension: str) -> str:
    """Helper to create a consistent filename."""
    safe_domain = domain.replace(".", "_")
    time_str = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"output/report_{safe_domain}_{time_str}.{extension}"


def save_json_output(data: Dict[str, Any]) -> str:
    """Saves the report data to a JSON file."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "json")

    # Ensure output directory exists
    os.makedirs("output", exist_ok=True)

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        raise IOError(f"Failed to save JSON report to {filename}: {e}")

    return filename


def _format_section_content(
    title: str, value: Union[Dict, List, str, None], report_lines: List[str]
) -> None:
    """Format section content for text report."""
    if not value:
        report_lines.append("No data found or module skipped.")
        return

    if isinstance(value, dict) and "error" in value:
        report_lines.append(f"Error: {value['error']}")
        return
    if isinstance(value, dict) and "note" in value:
        report_lines.append(f"Note: {value['note']}")
        return

    # Custom formatters for specific modules
    if title == "open_ports":
        # Ensure value is a dict before accessing
        if isinstance(value, dict):
            ports_data = value.get("open_ports", {})
            if not ports_data:
                report_lines.append("No open ports found.")
            for port, banner in sorted(ports_data.items()):
                report_lines.append(f"  - Port {port:<5} | {banner or 'N/A'}")
        else:
            report_lines.append("Invalid data format for open ports.")
    elif title == "tech_stack":
        # Ensure value is a dict before accessing
        if isinstance(value, dict):
            # Handle the main tech_stack fields
            for k, v in value.items():
                if k != "security_headers":
                    report_lines.append(f"  - {k.replace('_', ' ').title()}: {v}")

            # Handle the security_headers sub-dictionary
            sec_headers = value.get("security_headers", {})
            if sec_headers:
                report_lines.append("  - Security Headers:")
                if "note" in sec_headers:
                    report_lines.append(f"    - {sec_headers['note']}")
                else:
                    for k, v in sorted(sec_headers.items()):
                        report_lines.append(f"    - {k}: {v}")
        else:
            report_lines.append("Invalid data format for tech stack.")
    elif title in ["subdomains", "paths_found"]:
        # Ensure value is a dict before accessing
        if isinstance(value, dict):
            found_items = value.get("found", [])
            if not found_items:
                report_lines.append("None found.")
            for item in found_items:
                if isinstance(item, dict) and "subdomain" in item:
                    # Fix for subdomain formatting:
                    ips_str = ", ".join(item.get("ips", ["N/A"]))
                    report_lines.append(f"  - {item['subdomain']:<40} | IPs: {ips_str}")
                elif isinstance(item, dict) and "path" in item:
                    report_lines.append(
                        f"  - {item['path']:<30} | Status: {item.get('status_code', 'N/A')} | Type: {item.get('content_type', 'N/A')}"
                    )
        else:
            report_lines.append("Invalid data format for subdomains/paths.")
    elif title == "social_links":
        if not value:
            report_lines.append("No social links found.")
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    report_lines.append(
                        f"  - {item.get('platform', 'Unknown'):<15} | {item.get('url', 'N/A')}"
                    )
                else:
                    report_lines.append(f"  - {item}")
        else:
            report_lines.append("Invalid data format for social links.")
    elif title == "vulnerabilities":
        # Ensure value is a dict before accessing
        if isinstance(value, dict):
            if not value:
                report_lines.append("No vulnerabilities found.")
            for tech, vulns in sorted(value.items()):
                report_lines.append(f"  - {tech}:")
                if isinstance(vulns, list):
                    for vuln in vulns:
                        if isinstance(vuln, dict):
                            source = vuln.get("source", "N/A")
                            report_lines.append(
                                f"    - [{vuln.get('id')}] {vuln.get('title')} (CVSS: {vuln.get('cvss_score', 'N/A')}) [Source: {source}]"
                            )
                        else:
                            report_lines.append(f"    - {vuln}")
                elif isinstance(vulns, dict) and "error" in vulns:
                    report_lines.append(f"    - Error: {vulns['error']}")
        else:
            report_lines.append("Invalid data format for vulnerabilities.")
    elif isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, list):
                report_lines.append(f"  - {k.replace('_', ' ').title()}:")
                for i in v:
                    report_lines.append(f"    - {i}")
            else:
                report_lines.append(f"  - {k.replace('_', ' ').title()}: {v}")
    elif isinstance(value, list):
        for item in value:
            report_lines.append(f"  - {item}")
    else:
        report_lines.append(str(value))


def save_text_report(data: Dict[str, Any]) -> str:
    """Saves the report data to a human-readable TXT file."""
    domain = data.get("domain", "unknown")
    filename = _generate_filename(domain, "txt")

    report_lines: List[str] = []

    # --- Build the report ---
    report_lines.append(f"OSINT Report for: {data.get('domain')}")
    report_lines.append(f"Generated on: {timestamp()}")

    # Add basic info first
    basic_info = {"Domain": data.get("domain"), "IP Address": data.get("ip_address")}
    report_lines.append(f"\n{'=' * 10} BASIC INFO {'=' * 10}\n")
    for key, value in basic_info.items():
        report_lines.append(f"  - {key}: {value}")

    # Order of sections
    section_order = [
        "whois",
        "dns",
        "geoip",
        "ssl_certificate",
        "tech_stack",
        "builtwith",
        "open_ports",
        "subdomains",
        "paths_found",
        "wayback_urls",
        "social_links",
        "reverse_ip",
        "breach_check",
        "vulnerabilities",
    ]

    for key in section_order:
        if key in data:
            report_lines.append(
                f"\n{'=' * 10} {key.replace('_', ' ').upper()} {'=' * 10}\n"
            )
            _format_section_content(key, data[key], report_lines)

    # Ensure output directory exists
    os.makedirs("output", exist_ok=True)

    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))
    except Exception as e:
        raise IOError(f"Failed to save text report to {filename}: {e}")

    return filename


def save_report(data: Dict[str, Any], output_format: str = "json") -> str:
    """
    Dispatches to the correct save function based on the desired format.

    Args:
        data: The report data to save
        output_format: The output format ("json" or "txt")

    Returns:
        The path to the saved file

    Raises:
        ValueError: If an unsupported output format is specified
        IOError: If there's an error saving the file
    """
    if output_format == "txt":
        return save_text_report(data)
    elif output_format == "json":
        return save_json_output(data)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")
