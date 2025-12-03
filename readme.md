# 🕵️ Modular ReconX v1.2.0

<p align="center">
  <img src="splash.png" alt="Modular ReconX Splash Screen" width="600">
</p>

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
- ✅ Enhanced Privacy Mode (passive-only scanning to avoid detection)
- ✅ Proxy Support (SOCKS/HTTP proxy for anonymizing requests)
- ✅ User-Agent Rotation (automatic rotation to avoid detection)
- ✅ Rate Limiting Controls (configurable delays between requests)
- ✅ Enhanced Vulnerability Scanning (local exploit database with offline searchsploit-like functionality)
- ✅ Subdomain Enumeration Enhancements (permutation-based discovery and enhanced wordlists)
- ✅ Parameter Analysis (identifies potential injection points)
- ✅ JavaScript Analysis (finds sensitive data and security issues in JS files)
- ✅ API Endpoint Discovery (uncovers hidden API endpoints)
- ✅ Security Headers Analysis (checks for proper HTTP security headers)
- ✅ Form Analysis (identifies security issues in HTML forms)
- ✅ CORS Misconfiguration Checker (detects dangerous CORS policies)
- ✅ Cookie Security Analysis (analyzes cookie security attributes)
- ✅ Clickjacking Protection Checker (verifies anti-clickjacking measures)
- ✅ HTTP Parameter Pollution Detector (identifies parameter duplication vulnerabilities)
- ✅ **Cloud Enumeration** (AWS S3, Azure Blob, GCP Bucket)
- ✅ **Metadata Analysis** (PDF/DOCX metadata extraction)
- ✅ **Image Forensics** (EXIF data extraction)
- ✅ **Social Engineering Recon** (Dorks & Email Pattern Analysis)
- ✅ **Reverse Image Search** (Google Lens, Bing, Yandex, TinEye links)
- ✅ **Docker Support** (Containerized deployment)
- ✅ **Local File Analysis** (Analyze local images and documents)

## ⚙️ Setup

### 1. Prerequisites

- Python 3.8+

### 2. Installation

#### Option A: Standard Installation

```bash
# Clone the repository
git clone https://github.com/rebarakaz/modular_reconx.git
cd modular_reconx

# Install dependencies
pip install -r requirements.txt

# Install as a package
pip install -e .
```

This installation method allows you to run the tool from anywhere using:

```bash
reconx example.com
# or
modular-reconx example.com
```

#### Option B: Docker Installation (Recommended)

Docker provides an isolated environment with all dependencies pre-configured.

```bash
# Clone the repository
git clone https://github.com/rebarakaz/modular_reconx.git
cd modular_reconx

# Build the Docker image
docker build -t modular-reconx .

# Run a scan
docker run --rm modular-reconx example.com

# Or use Docker Compose
docker-compose run --rm reconx example.com
```

**Docker Benefits:**

- No dependency conflicts
- Consistent environment across platforms
- Easy deployment and scaling
- Isolated from host system

### 3. Configuration (API Keys)

Some modules in Modular ReconX require API keys to function. The tool uses a `.env` file to store these keys securely.

1. Copy the `.env.example` file to a new file named `.env`. You can use this command in your terminal:

    ```bash
    cp .env.example .env
    ```

2. Open the newly created `.env` file with a text editor.

3. Fill in the API keys you have. If you don't have any of the keys, just leave them empty, and the corresponding modules will be automatically skipped.

    ```env
    SHODAN_API_KEY="YourShodanAPIKeyHere"
    HIBP_API_KEY="YourHaveIBeenPwnedAPIKeyHere"
    VULNERS_API_KEY="YourVulnersAPIKeyHere"
    ZOOMEYE_API_KEY="YourZoomEyeAPIKeyHere"
    WPSCAN_API_KEY="YourWPScanAPIKeyHere"
    ```

    - **VULNERS_API_KEY**: Required for vulnerability scanning. A free key can be obtained from Vulners.com.
    - **WPSCAN_API_KEY**: Required for WordPress-specific scanning. A free key (25 requests/day) can be obtained from WPScan.com.

### 4. Download Data Dependencies

Some modules require local databases to function. A script is provided to download and set up these dependencies automatically.

1. **GeoLite2 Database (for GeoIP lookups):**
    - Sign up for a free [MaxMind account](https://www.maxmind.com/en/geolite2/signup) to get a license key.
    - Add your key to the `.env` file:

        ```env
        MAXMIND_LICENSE_KEY="YourMaxMindLicenseKeyHere"
        ```

2. **Run the Download Script:**

    ```bash
    python download_data.py
    ```

    This command will download the GeoLite2 database and the latest NVD vulnerability feeds. You can also run `python download_data.py --nvd` or `python download_data.py --geoip` to download them separately.

3. **Update the NVD Database:**
    After downloading the NVD JSON feeds, it's recommended to process them into the local database for the tool to use.

    ```bash
    python update_db.py
    ```

## 🐧 Linux Specific Instructions

### Installation on Linux

The installation process on Linux is identical to other platforms:

```bash
# Clone the repository
git clone https://github.com/rebarakaz/modular_reconx.git
cd modular_reconx

# Install as a package
pip install -e .
```

### Running with Correct Permissions

On Linux systems, you might encounter permission issues with some modules. If you experience problems:

1. Ensure your user has appropriate permissions:

    ```bash
    # Make sure Python scripts are executable
    chmod +x *.py
    ```

2. If you encounter issues with the port scanner, you might need to run with elevated privileges:

    ```bash
    # For extensive port scanning (optional)
    sudo reconx example.com
    ```

### Virtual Environment (Recommended)

For better isolation and to avoid permission issues, it's recommended to use a virtual environment:

```bash
# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install the package
pip install -e .

# Run the tool
reconx example.com

# Deactivate when done
deactivate
```

### Troubleshooting on Linux

If you encounter issues with data files not being found:

1. Verify the package is correctly installed:

    ```bash
    pip show modular-reconx
    ```

2. Check that data files are in the correct location:

    ```bash
    # After installation, data files should be accessible
    python -c "from app.modules.utils import get_resource_path; print(get_resource_path('data/subdomains.txt'))"
    ```

3. If you still have issues, try reinstalling:

    ```bash
    pip uninstall modular-reconx
    pip install -e .
    ```

## 🚀 How to Run

```bash
reconx example.com
# or
modular-reconx example.com
```

To speed up the scan, you can skip the slower modules like port scanning and path bruteforcing:

```bash
reconx example.com --skip-ports --skip-bruteforce
```

To generate reports in different formats:

```bash
# Generate HTML report with visualizations
reconx example.com --output html

# Generate CSV reports for spreadsheet analysis
reconx example.com --output csv
```

To enable domain correlation (compare WHOIS data of reverse IP results):

```bash
reconx example.com --correlate
```

To enable comprehensive bug hunting mode with advanced security analysis:

```bash
reconx example.com --bug-hunt
```

For enhanced privacy and security, you can use passive-only scanning mode:

```bash
reconx example.com --passive-only
```

To use a proxy for anonymizing requests:

```bash
reconx example.com --proxy http://127.0.0.1:8080
```

To set a custom user agent:

```bash
reconx example.com --user-agent "Custom User Agent String"
```

To add rate limiting between requests:

```bash
reconx example.com --rate-limit 1.0
```

You can combine multiple privacy and security options:

```bash
reconx example.com --passive-only --proxy http://127.0.0.1:8080 --rate-limit 0.5
```

```bash
reconx example.com --correlate
```

Results are saved as a JSON file in the `output/` directory.

## 🕵️ Advanced Usage

### Cloud & Metadata

```bash
reconx example.com --cloud --metadata
```

### Forensics & Social Engineering

```bash
reconx example.com --forensics --social --reverse
```

### Local File Analysis

You can run analysis directly on local files:

```bash
# Analyze an image for EXIF data
reconx image.jpg

# Analyze a document for metadata
reconx report.pdf
```

## 📋 CLI Reference

### New v1.2.0 Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--cloud` | Enable cloud storage enumeration (AWS/Azure/GCP) | `reconx example.com --cloud` |
| `--metadata` | Extract metadata from public documents (PDF/DOCX) | `reconx example.com --metadata` |
| `--forensics` | Analyze images for EXIF data | `reconx example.com --forensics` |
| `--social` | Generate Google Dorks and analyze email patterns | `reconx example.com --social` |
| `--reverse` | Generate reverse image search links | `reconx example.com --forensics --reverse` |

### Combined Usage Examples

```bash
# Full OSINT scan with all new features
reconx example.com --cloud --metadata --forensics --social --reverse

# Cloud security assessment
reconx example.com --cloud

# Document intelligence gathering
reconx example.com --metadata

# Image forensics investigation
reconx example.com --forensics --reverse

# Social engineering recon
reconx example.com --social

# Local file analysis (auto-detects file type)
reconx suspicious_image.jpg
reconx leaked_document.pdf
```

## 🆕 What's New in v1.2.0

### 🚀 Major New Features

#### Cloud Storage Enumeration

- **AWS S3 Bucket Discovery**: Automatically checks for public S3 buckets
- **Azure Blob Storage**: Detects exposed Azure storage containers
- **GCP Bucket Scanning**: Identifies publicly accessible Google Cloud buckets
- **Smart Permutations**: Tests common naming patterns (dev, staging, prod, backup, etc.)
- **Status Detection**: Distinguishes between public (200) and private (403) resources

#### Document Metadata Analysis

- **PDF Metadata Extraction**: Extracts author, creator, creation date, and software info
- **DOCX Metadata Extraction**: Analyzes Word documents for metadata leakage
- **Local File Support**: Analyze documents directly from your filesystem
- **Wayback Machine Integration**: Finds historical documents via archive.org

#### Image Forensics

- **EXIF Data Extraction**: Pulls GPS coordinates, camera model, software, and timestamps
- **Local & Remote Analysis**: Works with both local files and web-hosted images
- **Automatic Image Discovery**: Scrapes domains for images to analyze
- **Privacy Assessment**: Identifies metadata that could compromise privacy

#### Social Engineering Reconnaissance

- **Google Dork Generation**: Creates targeted dorks for:
  - LinkedIn employee discovery
  - Twitter/X account hunting
  - Sensitive file exposure (PDFs, DOCX, XLSX)
  - Login page identification
- **Email Pattern Analysis**: Automatically infers corporate email formats
- **Pattern Confidence Scoring**: Provides reliability metrics for discovered patterns

#### Reverse Image Search

- **Multi-Engine Support**: Generates search links for:
  - Google Lens
  - Google Images
  - Bing Visual Search
  - Yandex Images
  - TinEye
- **URL Encoding**: Properly handles special characters and spaces
- **One-Click Access**: Direct links to search results

#### Docker Support

- **Containerized Deployment**: Full Docker and Docker Compose support
- **Isolated Environment**: No dependency conflicts with host system
- **Easy Scaling**: Simple deployment across multiple systems
- **Volume Mapping**: Persistent output storage

#### Unified CLI for Files & Domains

- **Automatic Detection**: Tool recognizes whether input is a domain or file
- **Supported File Types**: JPG, PNG, HEIC, TIFF, PDF, DOCX
- **Seamless Workflow**: Same command structure for all input types

### 🔧 Improvements

- **Windows Compatibility**: Fixed all Unicode encoding issues for Windows users
- **Dependency Management**: Updated Pillow to v12.0.0 for Python 3.13 support
- **Error Handling**: Graceful handling of unsupported file types
- **Test Coverage**: Comprehensive test suite with 100% pass rate

### 📚 Documentation

- **CHANGELOG.md**: Detailed release notes
- **TESTING.md**: Complete testing documentation
- **Updated AGENTS.md**: New module documentation for AI assistants
- **Enhanced README**: Docker installation and advanced usage examples

---

## 📜 What's New in v1.1

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
- Enhanced WordPress plugin vulnerability scanning with multiple detection methods
- Certificate Transparency Log Monitoring for enhanced subdomain discovery
- Offline NVD database support for vulnerability checks
- Enhanced technology detection from HTTP headers

### Code Modernization

- Updated dependencies to latest versions
- Improved type hints and code documentation
- Better code organization and structure

## 📁 Directory Structure

- `app/data/`: Contains wordlists, GeoIP database, and NVD vulnerability database
- `app/modules/`: Individual OSINT modules
- `nvd_data/`: NVD JSON data files for offline vulnerability checking
- `output/`: JSON scan reports
- `app/scan.py`: Main execution script
- `setup.py`: Package installation script
- `requirements.txt`: Python dependencies
- `.env`: Configuration file for API keys
- `cache/`: Cache directory for DNS and WHOIS lookups (created automatically)

## 🎯 Bug Bounty Usage

Modular ReconX is an excellent tool for bug bounty hunters and security researchers. Here's how to use it effectively and responsibly:

### Quick Start for Bug Bounty

```bash
# Comprehensive reconnaissance on in-scope target
reconx target.com --cloud --metadata --forensics --social --correlate

# Passive-only scanning (stealthy)
reconx target.com --passive-only --rate-limit 1.0

# Focus on cloud misconfigurations
reconx target.com --cloud

# Document intelligence gathering
reconx target.com --metadata

# Image forensics for exposed data
reconx target.com --forensics --reverse
```

### Bug Bounty Best Practices

#### ✅ Before You Start

1. **Read the Program Rules**: Understand scope, out-of-scope items, and testing limitations
2. **Verify Authorization**: Ensure automated scanning is allowed
3. **Check Rate Limits**: Some programs prohibit aggressive scanning
4. **Use Appropriate Flags**: `--passive-only` and `--rate-limit` for respectful testing

#### 🎯 Recommended Workflow

```bash
# Phase 1: Passive Reconnaissance
reconx target.com --passive-only --correlate

# Phase 2: Cloud & Infrastructure
reconx target.com --cloud --metadata

# Phase 3: Deep Analysis
reconx target.com --forensics --social --reverse --bug-hunt

# Phase 4: Focused Testing
# Use findings to guide manual testing
```

#### 📊 What to Look For

- **Cloud Misconfigurations**: Public S3 buckets, Azure containers, GCP buckets
- **Metadata Leaks**: Author names, software versions, internal paths in documents
- **EXIF Data**: GPS coordinates, camera info, software details in images
- **Email Patterns**: Corporate email formats for social engineering tests
- **Subdomain Discovery**: Hidden or forgotten subdomains via CT logs
- **Technology Stack**: Vulnerable versions of software/frameworks

#### 🛡️ Responsible Disclosure

1. **Document Thoroughly**: Screenshot evidence, reproduction steps
2. **Assess Impact**: Understand the severity and exploitability
3. **Report Promptly**: Use the program's preferred reporting method
4. **Be Professional**: Clear, concise, and respectful communication
5. **Follow Up**: Respond to questions and provide additional info if needed

### Recommended Platforms

- [HackerOne](https://www.hackerone.com/) - Largest bug bounty platform
- [Bugcrowd](https://www.bugcrowd.com/) - Diverse program selection
- [Intigriti](https://www.intigriti.com/) - European focus
- [YesWeHack](https://www.yeswehack.com/) - Global programs

## 🛡️ Legal & Ethical Guidelines

**⚠️ IMPORTANT**: This tool is designed for authorized security testing only.

### ✅ Authorized Use

- Bug bounty programs (within scope)
- Penetration testing (with written authorization)
- Security research (on your own systems)
- Educational purposes (in lab environments)
- Corporate security assessments (with approval)

### ❌ Prohibited Use

- Scanning without explicit authorization
- Violating bug bounty program rules
- Accessing systems you don't own
- Any illegal reconnaissance activities

### 📚 Read the Full Guidelines

For comprehensive legal and ethical guidelines, please read:

- **[RESPONSIBLE_USE.md](RESPONSIBLE_USE.md)** - Detailed ethical framework and best practices
- **[SECURITY.md](SECURITY.md)** - Security policy and vulnerability reporting

### 🔒 Privacy & Data Protection

- Scan results may contain sensitive information
- Store results securely and encrypt when necessary
- Delete data when no longer needed
- Respect GDPR, CCPA, and other privacy regulations
- Redact PII from reports and findings

### ⚖️ Legal Disclaimer

**This tool is provided "as is" for educational and authorized security testing purposes only. Users are solely responsible for ensuring their use complies with all applicable laws and regulations. The authors and contributors are not liable for any misuse or illegal activities.**

**By using Modular ReconX, you acknowledge that you have read and agree to follow the guidelines in [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md).**

## 🛡️ Usage Guidelines

## 🤝 Contributing

Feel free to fork the repository and submit pull requests. For major changes, please open an issue first to discuss what you would like to change.

## 👤 Author

### **Reynov Christian aka BabyDev**

- Business: Chrisnov IT Solutions
- Website: <https://chrisnov.com>
