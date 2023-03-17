import requests
import re
import sys
import argparse
import logging
import os
import hashlib
import zipfile

logging.basicConfig(filename="nvdcve.log", level=logging.DEBUG, format="%(asctime)s: %(message)s")

def main():
    title = "GET-NVDCVE"
    print("=" * (len(title) + 4))
    print("| " + title + " |")
    print("=" * (len(title) + 4))

    # Parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-y", "--year", type=str, help="Download data for a specific year (yyyy) or range (yyyy-yyyy)")
    args = parser.parse_args()

    try:
        r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED', verify=True)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error("An error occurred while connecting to the server: %s" % e)
        sys.exit(1)

    if not os.path.exists("nvd"):
        os.makedirs("nvd")

    existing_hashes = read_existing_hashes()
    years = None

    # Check if the input is a range or an individual year
    if args.year:
        years = process_year_input(args.year)

    filenames = sorted(re.findall("nvdcve-1.1-[0-9]*\.json\.zip", r.text), reverse=True)

    if not years:
        # Download only the latest feed if no year is specified
        filenames = [filenames[0]]

    for filename in filenames:
        file_year_match = re.search(r'\d{4}', filename)
        if file_year_match:
            file_year = int(file_year_match.group(0))
        else:
            logging.warning(f"Unexpected filename format: {filename}")
            continue

        if years and file_year not in years:
            continue
        download_and_extract_file(filename)

    show_summary(existing_hashes)

def process_year_input(year_input):
    if '-' in year_input:
        start_year, end_year = map(int, year_input.split('-'))
        return list(range(start_year, end_year + 1))
    else:
        return [int(year_input)]

def download_metadata(filename):
    try:
        r_meta = requests.get(f'https://nvd.nist.gov/feeds/json/cve/1.1/{filename}.meta', verify=True)
        r_meta.raise_for_status()
        metadata = {}
        for line in r_meta.text.splitlines():
            key, value = line.split(":", 1)
            metadata[key.strip()] = value.strip()
        return metadata
    except requests.exceptions.RequestException as e:
        logging.error("An error occurred while downloading the metadata for %s: %s" % (filename, e))
        return None

def download_and_extract_file(filename):
    file_path = "nvd/" + filename

    if file_already_exists(file_path):
        print(f"{filename} already exists with the same hash. Skipping download.")
        return

    with requests.Session() as session:
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        try:
            r_file = session.get("https://static.nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
            r_file.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.error("An error occurred while downloading the file: %s" % e)
            return

        save_and_extract_file(r_file, file_path, filename)

def file_already_exists(file_path):
    if not os.path.exists(file_path):
        return False

    filename = os.path.basename(file_path).replace(".zip", "")
    metadata = download_metadata(filename)
    if metadata is None:
        return False

    with open(file_path, 'rb') as f:
        current_sha256 = hashlib.sha256(f.read()).hexdigest()
    return current_sha256 == metadata['SHA-256']

def save_and_extract_file(r_file, file_path, filename):
    with open(file_path, 'wb') as f:
        for chunk in r_file.iter_content(chunk_size=8192):
            f.write(chunk)
        downloaded = f.tell()
    print("Downloaded %.2f%% of %s" % (downloaded / int(r_file.headers['Content-Length']) * 100, filename))

    with zipfile.ZipFile(file_path, "r") as zip_ref:
        zip_ref.extractall("nvd")

    try:
        with open("nvdcve.log", "a") as logfile:
            logfile.write("Downloaded %s\n" % filename)
    except PermissionError as e:
        logging.error("PermissionError: %s" % e)
        print("PermissionError: %s" % e)

def remove_zip_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
        
def read_existing_hashes():
    if not os.path.exists("hashes.txt"):
        return {}

    with open("hashes.txt", 'r') as f_in:
        hashes = {}
        for line in f_in:
            if not line.strip():
                continue
            filename, file_size, file_hash = line.strip().split('\t')
            hashes[filename] = file_hash
        return hashes

def update_hashes_file(hashes, filename, file_hash):
    hashes[filename] = file_hash
    with open("hashes.txt", 'w') as f_out:
        for filename, file_hash in hashes.items():
            f_out.write(f"{filename}\t{file_hash}\n")        

def show_summary(existing_hashes):
    try:
        with open("summary.txt", 'w') as summary_file:
            print("-" * 120)
            print("Summary:".rjust(70))
            print("-" * 120)
            print("Filename".ljust(30), "Size".rjust(20), "sha256".rjust(50))
            print("-" * 120)
            summary_file.write("-" * 120 + "\n")
            summary_file.write("Summary:".rjust(70) + "\n")
            summary_file.write("-" * 120 + "\n")
            summary_file.write("Filename".ljust(30) + "Size".rjust(20) + "sha256".rjust(50) + "\n")
            summary_file.write("-" * 120 + "\n")
            
            for filename, file_hash in existing_hashes.items():
                file_path = "nvd/" + filename
                file_size = os.path.getsize(file_path)
                print(filename.ljust(30), str(file_size).rjust(20), file_hash.rjust(50))
                summary_file.write(filename.ljust(30) + str(file_size).rjust(20) + file_hash.rjust(50) + "\n")
            print("-" * 120)
            summary_file.write("-" * 120 + "\n")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        logging.error(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Error: {e}")
        
if __name__ == "__main__":
    main()        
