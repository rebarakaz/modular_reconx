# 🕵️ Modular ReconX v1.1

**Modular ReconX** is a modular OSINT tool based on Python for performing a complete analysis of a domain or website using open-source intelligence techniques.

## ✨ Features

- ✅ WHOIS Lookup (with fallback)
- ✅ DNS Record Scan (A, MX, NS, TXT)
- ✅ BuiltWith-like Detection (tech stack & CMS)
- ✅ GeoIP Lookup (server location)
- ✅ Port Scanner (21-8080)
- ✅ Subdomain Enumerator (wordlist-based)
- ✅ Certificate Transparency Log Monitoring (enhanced subdomain discovery)
- ✅ Reverse IP Lookup (HackerTarget & ViewDNS fallback)
- ✅ Directory/Path Bruteforce (/admin, /login, dll)
- ✅ SSL Certificate Info (common name & issuer)
- ✅ Social Media Finder (Facebook, IG, Twitter, LinkedIn, TikTok, Threads, YouTube, Telegram)
- ✅ Breach Email Check (optional WHOIS email scan with HIBP and Mozilla Monitor fallback)
- ✅ Vulnerability Check (via Vulners API for detected tech with offline NVD database support)
- ✅ Wayback Machine URL History
- ✅ Enhanced WordPress Plugin Vulnerability Scanner (automatic plugin detection via multiple methods and vulnerability assessment)
- ✅ Domain Correlation (filter reverse IP results by WHOIS similarity)
- ✅ Caching Mechanism (1-hour cache for DNS and WHOIS lookups)
- ✅ Input Validation (domain format validation)
- ✅ Improved Error Handling

## ⚙️ Setup

### 1. Prerequisites
- Python 3.8+

### 2. Installation Options

#### Option A: Install as a Package (Recommended)
```bash
# Clone the repository
git clone https://github.com/rebarakaz/modular_reconx.git
cd ModularReconX

# Install as a package
pip install -e .
```

This installation method allows you to run the tool from anywhere using:
```bash
reconx example.com
# or
modular-reconx example.com
```

#### Option B: Traditional Installation
```bash
# Clone the repository
git clone https://github.com/rebarakaz/modular_reconx.git
cd ModularReconX

# Create and activate a virtual environment
python -m venv venv
# On Windows: venv\Scripts\activate
# On macOS/Linux: source venv/bin/activate

# Install the required packages
pip install -r requirements.txt
```

### 3. Configuration (API Keys)

Some modules in Modular ReconX require API keys to function. The tool uses a `.env` file to store these keys securely.

1.  Copy the `.env.example` file to a new file named `.env`. You can use this command in your terminal:
    ```bash
    cp .env.example .env
    ```

2.  Open the newly created `.env` file with a text editor.

3.  Fill in the API keys you have. If you don't have any of the keys, just leave them empty, and the corresponding modules will be automatically skipped.
    ```env
    SHODAN_API_KEY="YourShodanAPIKeyHere"
    HIBP_API_KEY="YourHaveIBeenPwnedAPIKeyHere"
    VULNERS_API_KEY="YourVulnersAPIKeyHere"
    ZOOMEYE_API_KEY="YourZoomEyeAPIKeyHere"
    WPSCAN_API_KEY="YourWPScanAPIKeyHere"
    ```
    * **VULNERS_API_KEY**: Required for vulnerability scanning. A free key can be obtained from Vulners.com.
    * **WPSCAN_API_KEY**: Required for WordPress-specific scanning. A free key (25 requests/day) can be obtained from WPScan.com.

### 4. Download Data Dependencies

Some modules require local databases to function. A script is provided to download and set up these dependencies automatically.

1.  **GeoLite2 Database (for GeoIP lookups):**
    *   Sign up for a free [MaxMind account](https://www.maxmind.com/en/geolite2/signup) to get a license key.
    *   Add your key to the `.env` file:
        ```env
        MAXMIND_LICENSE_KEY="YourMaxMindLicenseKeyHere"
        ```

2.  **Run the Download Script:**
    ```bash
    python download_data.py
    ```
    This command will download the GeoLite2 database and the latest NVD vulnerability feeds. You can also run `python download_data.py --nvd` or `python download_data.py --geoip` to download them separately.

3.  **Update the NVD Database:**
    After downloading the NVD JSON feeds, it's recommended to process them into the local database for the tool to use.
    ```bash
    python update_db.py
    ```


## 🚀 How to Run

### If installed as a package (Option A):
```bash
reconx example.com
# or
modular-reconx example.com
```

### If using traditional installation (Option B):
Run a full scan and save the report as a JSON file (default):
```bash
python scan.py example.com
```

To speed up the scan, you can skip the slower modules like port scanning and path bruteforcing:
```bash
python scan.py example.com --skip-ports --skip-bruteforce
```

To enable domain correlation (compare WHOIS data of reverse IP results):
```bash
python scan.py example.com --correlate
```

Results are saved as a JSON file in the `output/` directory.

## 🆕 What's New in v1.1

### Performance Improvements
- Added caching mechanism for DNS and WHOIS lookups (1-hour cache)
- Improved concurrent execution of modules
- Added offline NVD vulnerability database support

### Security Enhancements
- Added domain format validation
- Improved error handling and logging
- Added Mozilla Monitor as a free alternative for breach checking

### New Features
- Domain correlation: Filter reverse IP results by WHOIS similarity
- Enhanced WordPress plugin vulnerability scanning with multiple detection methods:
  - CSS/JS file detection in wp-content/plugins/
  - readme.txt file analysis
  - HTML source code signature scanning
  - WordPress REST API integration (when available)
  - Meta tag and comment analysis
- Certificate Transparency Log Monitoring for enhanced subdomain discovery:
  - Multi-source CT log querying (crt.sh, CertSpotter, BufferOver)
  - Passive reconnaissance capabilities
  - Recently issued certificate discovery
  - Comprehensive subdomain coverage beyond wordlists
- Offline NVD database support for vulnerability checks
- Enhanced technology detection from HTTP headers

### Code Modernization
- Updated dependencies to latest versions
- Improved type hints and code documentation
- Better code organization and structure

## 📁 Directory Structure

- `data/`: Contains wordlists, GeoIP database, and NVD vulnerability database
- `modules/`: Individual OSINT modules
- `nvd_data/`: NVD JSON data files for offline vulnerability checking
- `output/`: JSON scan reports
- `scan.py`: Main execution script
- `setup.py`: Package installation script
- `requirements.txt`: Python dependencies
- `.env`: Configuration file for API keys
- `cache/`: Cache directory for DNS and WHOIS lookups (created automatically)

## 🛡️ Usage Guidelines

- This tool is intended for ethical use only
- Only scan domains you own or have explicit permission to scan
- Be respectful of rate limits for external APIs
- The caching mechanism helps reduce redundant requests to external services
- For offline vulnerability checking, regularly update the NVD data files and run `update_db.py`

## 🤝 Contributing

Feel free to fork the repository and submit pull requests. For major changes, please open an issue first to discuss what you would like to change.

## 👤 Author

**Reynov Christian aka BabyDev**
- Business: Chrisnov IT Solutions
- Website: https://chrisnov.com