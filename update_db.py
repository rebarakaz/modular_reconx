# update_db.py
import sqlite3
import json
import os
import glob  # To search for all .json files in a folder
from tqdm import tqdm  # For a nice progress bar

DB_PATH = "data/vulnerabilities.db"
NVD_DATA_DIR = "nvd_data"


def setup_database():
    """Create the database and table if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Create a table to store vulnerability data
    # Using "cve_id, product, version" as a composite primary key
    # to avoid duplication of identical data
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT NOT NULL,
            product TEXT NOT NULL,
            vendor TEXT NOT NULL,
            version TEXT NOT NULL,
            description TEXT,
            cvss_score REAL,
            link TEXT,
            PRIMARY KEY (cve_id, product, version)
        )
    """)
    conn.commit()
    conn.close()
    print(f"Database '{DB_PATH}' is ready to use.")


def parse_cpe_string(cpe_uri):
    """
    Helper function to parse a CPE string into its components.
    Example: cpe:2.3:a:apache:http_server:2.4.39 -> ('apache', 'http_server', '2.4.39')
    """
    parts = cpe_uri.split(":")
    if len(parts) >= 6:
        vendor = parts[3]
        product = parts[4]
        version = parts[5]
        return vendor, product, version
    return None, None, None


def process_nvd_file(filepath, cursor):
    """Process one NVD JSON file and insert its data into the database."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # We'll fill in the logic to loop and insert data here
    # pass # Remove 'pass' in the next step

    # --- THIS IS THE LOGIC WE'LL BUILD IN THE NEXT STEP ---
    vulnerabilities_to_insert = []

    for entry in data.get("vulnerabilities", []):
        cve_item = entry.get("cve", {})
        cve_id = cve_item.get("id")

        # Get description
        description = ""
        if cve_item.get("descriptions"):
            for desc in cve_item["descriptions"]:
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break

        # Get CVSS score
        cvss_score = None
        if cve_item.get("metrics", {}).get("cvssMetricV31"):
            cvss_score = cve_item["metrics"]["cvssMetricV31"][0]["cvssData"].get(
                "baseScore"
            )

        # Get reference link
        link = ""
        if cve_item.get("references"):
            link = cve_item["references"][0].get("url")

        # Parse configuration to get affected software
        if cve_item.get("configurations"):
            for node_container in cve_item["configurations"]:
                for node in node_container.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            cpe_uri = cpe_match.get("criteria")
                            vendor, product, version = parse_cpe_string(cpe_uri)
                            if vendor and product and version:
                                vulnerabilities_to_insert.append(
                                    (
                                        cve_id,
                                        product,
                                        vendor,
                                        version,
                                        description,
                                        cvss_score,
                                        link,
                                    )
                                )

    if vulnerabilities_to_insert:
        cursor.executemany(
            """
            INSERT OR IGNORE INTO vulnerabilities 
            (cve_id, product, vendor, version, description, cvss_score, link)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            vulnerabilities_to_insert,
        )


def main():
    """Main function to run the import process."""
    setup_database()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Find all .json files in the nvd_data directory
    json_files = glob.glob(os.path.join(NVD_DATA_DIR, "*.json"))

    print(f"Found {len(json_files)} NVD JSON files to process.")

    # Use tqdm for a beautiful progress bar
    for filepath in tqdm(json_files, desc="Processing NVD files"):
        process_nvd_file(filepath, cursor)

    conn.commit()
    conn.close()

    print("\n✅ Vulnerability data import completed!")


if __name__ == "__main__":
    main()