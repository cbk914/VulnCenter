# Author: cbk914
import requests
import re
import sys
import argparse
import logging
import os
import hashlib
import zipfile

logging.basicConfig(filename="nvdcve.log", level=logging.DEBUG, format="%(asctime)s: %(message)s")


# Parse the command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-y", "--year", type=int, help="Download data for specific year (yyyy)")
args = parser.parse_args()

try:
    # Verify SSL certificate for secure connection
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED', verify=True)
    r.raise_for_status()
except requests.exceptions.RequestException as e:
    logging.error("An error occurred while connecting to the server: %s" % e)
    sys.exit(1)

if not os.path.exists("nvd"):
    os.makedirs("nvd")

for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip",r.text):
    # Check if year is specified and continue to next iteration if the year is not in filename
    if args.year:
        if str(args.year) not in filename:
            continue
    
    # Use session to persist the connection and reuse it
    with requests.Session() as session:
        session.mount('https://', requests.adapters.HTTPAdapter(max_retries=3))
        try:
            r_file = session.get("https://static.nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
            r_file.raise_for_status()
        except requests.exceptions.RequestException as e:
            logging.error("An error occurred while downloading the file: %s" % e)
            continue
        # Check if file already exists and compare sha256
        file_path = "nvd/" + filename
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                current_sha256 = hashlib.sha256(f.read()).hexdigest()
            if current_sha256 == r_file.headers.get("X-Content-SHA256"):
                continue
        # Unzip the file
        with open("nvd/" + filename, 'wb') as f:
            for chunk in r_file.iter_content(chunk_size=8192):
                # write the content to the file in chunks to avoid memory exhaustion
                f.write(chunk)
                downloaded = f.tell()
                print("Downloaded %.2f%% of %s" % (downloaded / int(r_file.headers['Content-Length']) * 100, filename))
        with zipfile.ZipFile("nvd/" + filename, "r") as zip_ref:
	        zip_ref.extractall("nvd")
        
try:
    with open("nvdcve.log", "a") as logfile:
        logfile.write("Downloaded %s\n" % filename)
except PermissionError as e:
    logging.error("PermissionError: %s" % e)
    print("PermissionError: %s" % e)

# Show summary of downloaded files
try:
    print("-"*120)
    print("Summary:".rjust(70))
    print("-"*120)
    print("Filename".ljust(30), "Size".rjust(20), "sha256".rjust(50))
    print("-"*120)
    with open("hashes.txt", 'w') as f_out:
        for filename in os.listdir("nvd"):
            file_path = "nvd/" + filename
            file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
                print(filename.ljust(30), str(file_size).rjust(20), sha256.rjust(50))
                f_out.write("%s\t%d\t%s\n" % (filename, file_size, sha256))
    print("-"*120)
except FileNotFoundError as e:
    print(f"Error: {e}")
    logging.error(f"Error: {e}")
except Exception as e:
    print(f"Error: {e}")
    logging.error(f"Error: {e}")
