
import os
import requests
import zipfile
import tarfile
import argparse
from datetime import datetime
from dotenv import load_dotenv
from tqdm import tqdm

# --- Configuration ---
NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
NVD_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
NVD_START_YEAR = 2019  # Or any year you want to start from
NVD_DATA_DIR = "nvd_data"

GEOLITE_BASE_URL = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz"
DATA_DIR = "data"
GEOLITE_TAR_FILENAME = "GeoLite2-City.tar.gz"
GEOLITE_DB_FILENAME = "GeoLite2-City.mmdb"

# --- Helper Functions ---

def download_file(url, dest_path):
    """Downloads a file from a URL to a destination path with a progress bar."""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        total_size = int(response.headers.get("content-length", 0))
        
        with open(dest_path, "wb") as f, tqdm(
            desc=os.path.basename(dest_path),
            total=total_size,
            unit="iB",
            unit_scale=True,
            unit_divisor=1024,
        ) as bar:
            for chunk in response.iter_content(chunk_size=8192):
                size = f.write(chunk)
                bar.update(size)
        print(f"Successfully downloaded {os.path.basename(dest_path)}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return False

# --- Core Functions ---

def download_nvd_feeds():
    """Downloads and extracts NVD data feeds."""
    print("\n--- Downloading NVD Data Feeds ---")
    os.makedirs(NVD_DATA_DIR, exist_ok=True)
    current_year = datetime.now().year
    
    # Download yearly feeds
    for year in range(NVD_START_YEAR, current_year + 1):
        url = NVD_BASE_URL.format(year=year)
        zip_path = os.path.join(NVD_DATA_DIR, f"nvdcve-1.1-{year}.json.zip")
        if download_file(url, zip_path):
            try:
                with zipfile.ZipFile(zip_path, "r") as zip_ref:
                    zip_ref.extractall(NVD_DATA_DIR)
                print(f"Successfully extracted {os.path.basename(zip_path)}")
                os.remove(zip_path) # Clean up the zip file
            except zipfile.BadZipFile:
                print(f"Error: {os.path.basename(zip_path)} is not a valid zip file.")

    # Download modified feed
    zip_path = os.path.join(NVD_DATA_DIR, "nvdcve-1.1-modified.json.zip")
    if download_file(NVD_MODIFIED_URL, zip_path):
        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(NVD_DATA_DIR)
            print(f"Successfully extracted {os.path.basename(zip_path)}")
            os.remove(zip_path)
        except zipfile.BadZipFile:
            print(f"Error: {os.path.basename(zip_path)} is not a valid zip file.")

def download_geolite_db():
    """Downloads and extracts the GeoLite2 City database."""
    print("\n--- Downloading GeoLite2 City Database ---")
    load_dotenv()
    license_key = os.getenv("MAXMIND_LICENSE_KEY")

    if not license_key or license_key == "YourMaxMindLicenseKeyHere":
        print("Error: MAXMIND_LICENSE_KEY not found in .env file.")
        print("Please sign up for a free MaxMind account to get a license key and add it to your .env file.")
        return

    os.makedirs(DATA_DIR, exist_ok=True)
    url = GEOLITE_BASE_URL.format(key=license_key)
    tar_path = os.path.join(DATA_DIR, GEOLITE_TAR_FILENAME)

    if download_file(url, tar_path):
        try:
            with tarfile.open(tar_path, "r:gz") as tar:
                # Find the .mmdb file in the tar archive
                mmdb_member = None
                for member in tar.getmembers():
                    if member.name.endswith(GEOLITE_DB_FILENAME):
                        mmdb_member = member
                        break
                
                if not mmdb_member:
                    print(f"Error: Could not find {GEOLITE_DB_FILENAME} in the downloaded archive.")
                    return

                # Extract the .mmdb file to the data directory
                mmdb_member.name = os.path.basename(mmdb_member.name) # Remove folder structure
                tar.extract(mmdb_member, path=DATA_DIR)
                print(f"Successfully extracted {GEOLITE_DB_FILENAME} to {DATA_DIR}/")

        except tarfile.TarError as e:
            print(f"Error extracting {tar_path}: {e}")
        finally:
            os.remove(tar_path) # Clean up the tar.gz file

# --- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download data dependencies for Modular ReconX.")
    parser.add_argument("--nvd", action="store_true", help="Download NVD data feeds only.")
    parser.add_argument("--geoip", action="store_true", help="Download GeoLite2 database only.")
    args = parser.parse_args()

    if args.nvd and not args.geoip:
        download_nvd_feeds()
    elif args.geoip and not args.nvd:
        download_geolite_db()
    else:
        # Download both by default or if both flags are provided
        download_nvd_feeds()
        download_geolite_db()
        print("\nData download process complete.")
