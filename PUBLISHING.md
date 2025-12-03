# Publishing Modular ReconX to GitHub

## Repository Information

- **Repository Name**: ModularReconX
- **Owner**: rebarakaz
- **URL**: <https://github.com/rebarakaz/modular_reconx>

## Project Overview

Modular ReconX is a comprehensive OSINT (Open Source Intelligence) tool built in Python for performing complete reconnaissance on domains or websites. It provides security professionals, penetration testers, and researchers with a powerful suite of tools for gathering intelligence using open-source techniques.

## Key Features Implemented

1. **Enhanced WordPress Scanner**
   - Automatic plugin detection via multiple methods (CSS/JS files, readme.txt, HTML signatures, REST API)
   - Version extraction and vulnerability assessment
   - Integration with WPScan API for vulnerability data
   - Detailed reporting with vulnerability information and fix versions

2. **Certificate Transparency Log Monitoring**
   - Multi-source CT log querying (crt.sh, CertSpotter, BufferOver)
   - Enhanced subdomain discovery beyond traditional wordlist-based enumeration
   - Passive reconnaissance capabilities
   - Recently issued certificate discovery

3. **Internationalization**

   - Translated all Indonesian text to English
   - Made the tool accessible to an international audience

4. **Email Breach Checking**

   - Integrated Mozilla Monitor as a free alternative to HIBP
   - Fallback mechanism when HIBP API key is not available

5. **Offline Vulnerability Database**

- NVD database support for offline vulnerability checking
- Database update script for maintaining current vulnerability data
- README.md with complete documentation
- LICENSE.txt
- .env.example for configuration
- data/ directory with wordlists and databases
- nvd_data/ directory for offline vulnerability data
- output/ directory (initially empty)
- cache/ directory (initially empty)

## Publishing Steps

1. Create a new repository on GitHub named "ModularReconX"
2. Clone the repository locally
3. Copy all files from this project to the cloned repository
4. Add and commit all files:

   ```bash
   git add .
   git commit -m "Initial commit: Complete Modular ReconX v1.2.0 with all features"
   ```

5. Push to GitHub:

   ```bash
   git push -u origin master
   ```

## Usage After Publishing

Users can clone and install the tool with:

```bash
git clone https://github.com/rebarakaz/modular_reconx.git
cd modular_reconx
pip install -e .
```

Then run scans with:

```bash
reconx example.com
# or
modular-reconx example.com
```

## Author Credits

### **Reynov Christian aka BabyDev**

- Business: Chrisnov IT Solutions
- Website: <https://chrisnov.com>

## License

MIT License (see LICENSE.txt)
