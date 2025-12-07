# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Project Overview

Modular ReconX is a modular OSINT (Open Source Intelligence) tool written in Python for performing comprehensive analysis of domains or websites using open-source intelligence techniques. The tool provides security professionals, penetration testers, and researchers with a powerful suite of modules for gathering intelligence.

## High-Level Architecture

The project follows a modular architecture where each OSINT capability is implemented as a separate module in the `app/modules/` directory. The main execution flow is controlled by `app/scan.py`, which orchestrates the concurrent execution of these modules.

### Core Components

1. **Main Entry Point**: `app/scan.py` - Handles command-line argument parsing, module orchestration, and concurrent execution
2. **Module System**: `app/modules/` - Contains individual OSINT modules (WHOIS lookup, DNS scanning, port scanning, etc.)
3. **HTTP Client**: `app/modules/http_client.py` - Enhanced HTTP client with proxy support, user-agent rotation, and rate limiting
4. **Data Files**: `app/data/` - Contains wordlists, GeoIP database, and vulnerability database
5. **NVD Data**: `nvd_data/` - Contains raw NVD JSON feeds for offline vulnerability checking
6. **Output**: `output/` - Stores scan results in JSON or text format
7. **Cache**: `cache/` - Temporary storage for DNS and WHOIS lookup caching

### Key Modules

- `whois_lookup.py` - Domain registration information
- `dns_lookup.py` - DNS record enumeration (A, MX, NS, TXT)
- `subdomain_enum.py` - Wordlist-based subdomain discovery
- `ct_log_monitor.py` - Certificate Transparency log monitoring
- `port_scanner.py` - Port scanning (21-8080)
- `path_bruteforce.py` - Directory/path discovery
- `wp_scanner.py` - WordPress plugin and vulnerability detection
- `vuln_scanner.py` - Technology vulnerability checking
- `reverse_ip.py` - Reverse IP lookups
- `geoip_lookup.py` - Geographic IP location
- `social_finder.py` - Social media account discovery
- `param_analysis.py` - Parameter vulnerability analysis
- `js_analysis.py` - JavaScript security analysis
- `api_discovery.py` - API endpoint discovery
- `security_headers.py` - HTTP security headers analysis
- `form_analysis.py` - HTML form security analysis
- `cors_checker.py` - CORS misconfiguration detection
- `cookie_analysis.py` - HTTP cookie security analysis
- `clickjacking_checker.py` - Clickjacking protection verification
- `param_pollution.py` - HTTP Parameter Pollution detection
- `cloud_enum.py` - Cloud storage enumeration
- `metadata_analysis.py` - Document metadata analysis
- `image_forensics.py` - Image EXIF analysis
- `social_eng.py` - Social engineering reconnaissance
- `reverse_image.py` - Reverse image search link generation
- `ai_analysis.py` - AI-powered report analysis (Gemini)
- `github_scanner.py` - GitHub secret and dork scanning
- `waf_detector.py` - Web Application Firewall detection
- `breach_check.py` - Email breach verification
- `subdomain_permutation.py` - Subdomain permutation generation

## Common Development Commands

### Installation

```bash
pip install -e .
```

### Running the Tool

```bash
# Basic scan
reconx example.com

# Scan with all features enabled
reconx example.com --correlate

# Fast scan (skip slow modules)
reconx example.com --skip-ports --skip-bruteforce

# Privacy-focused scan (passive techniques only)
reconx example.com --passive-only

# Scan with proxy support
reconx example.com --proxy http://127.0.0.1:8080

# Scan with rate limiting
reconx example.com --rate-limit 1.0

# Enable comprehensive bug hunting mode
reconx example.com --bug-hunt

# Enable AI analysis (requires GEMINI_API_KEY)
reconx example.com --ai

# Scan GitHub for secrets
reconx example.com --github

# Detect Web Application Firewall
reconx example.com --waf

# Use enhanced subdomain wordlist
reconx example.com --enhanced-subdomains
```

### Data Management

```bash
# Download required data files (GeoIP database, NVD feeds)
python download_data.py

# Update local vulnerability database
python update_db.py
```

### Testing

```bash
# Run specific module tests
python test_ct_monitor.py
python test_wp_scanner.py

# Run comprehensive tests
python comprehensive_ct_test.py
python comprehensive_wp_test.py
```

### Development Utilities

```bash
# View NVD database structure
python peek_nvd.py
```

## Code Structure Guidelines

1. **Module Design**: Each module should be self-contained with a clear interface
2. **Error Handling**: Modules should handle exceptions gracefully and return consistent error structures
3. **Caching**: Use the caching mechanism in `app/modules/cache.py` for expensive operations
4. **Resource Access**: Use `get_resource_path()` from `app/modules/utils.py` for accessing data files
5. **Output Formatting**: Use the existing report formatting functions in `app/modules/utils.py`
6. **HTTP Requests**: Use the enhanced HTTP client in `app/modules/http_client.py` for all external requests to benefit from proxy support, user-agent rotation, and rate limiting

## Package Management

The project uses setuptools for package management with entry points defined for `reconx` and `modular-reconx` commands. Dependencies are managed through `requirements.txt`.
