# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2025-12-03

### 🚀 New Features

- **Docker Support**: Added `Dockerfile` and `docker-compose.yml` for easy containerized deployment.
- **Cloud Enumeration**: Added `--cloud` flag to check for public AWS S3 buckets, Azure Blobs, and GCP Buckets.
- **Metadata Analysis**: Added `--metadata` flag to extract metadata (Author, Software, etc.) from public PDF and DOCX files.
- **Image Forensics**: Added `--forensics` flag to extract EXIF data (GPS, Camera, Software) from images.
- **Social Engineering Recon**: Added `--social` flag to generate Google Dorks and analyze email patterns for corporate targets.
- **Reverse Image Search**: Added `--reverse` flag to generate direct search links for Google Lens, Bing, Yandex, and TinEye.
- **Local File Support**: The tool now accepts local file paths (e.g., `image.jpg`, `report.pdf`) for direct analysis without a domain scan.

### 🛠️ Improvements

- **Unified CLI**: `scan.py` now intelligently handles both domain names and local file paths.
- **Dependency Updates**: Added `PyPDF2`, `python-docx`, and `Pillow` to `requirements.txt`.
- **Refactoring**: Modularized new features into dedicated files in `app/modules/`.

### 🐛 Fixes

- Fixed an issue with duplicate arguments in `scan.py`.
- Improved error handling for local file analysis.
