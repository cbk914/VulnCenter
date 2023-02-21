#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os
import requests
import json
import gzip
import shutil
import zipfile
import redis

def download_database(url, filename):
    """
    Download a database from the given URL and save it to the specified filename.
    """
    r = requests.get(url)
    with open(filename, "wb") as f:
        f.write(r.content)
        
def decompress_database(filename):
    """
    Decompress a gzip-compressed database.
    """
    if filename.endswith(".gz"):
        with gzip.open(filename, "rb") as f_in:
            with open(filename[:-3], "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(filename)
    elif filename.endswith(".zip"):
        with zipfile.ZipFile(filename, "r") as zip_ref:
            zip_ref.extractall(os.path.dirname(filename))
        os.remove(filename)
    else:
        raise ValueError("Unsupported file format: " + filename)
    
def search_database(r, search_string):
    """
    Search the specified database for the given search string.
    """
    # Execute the search query
    results = []
    for key in r.scan_iter("vulnerability:*"):
        if search_string in r.hget(key, "description").decode():
            results.append(r.hgetall(key))
    
    # Return the search results
    return results

def save_results(results, output_format, output_filename):
    """
    Save the search results to a file in the specified format.
    """
    if output_format == "txt":
        # Save results as plain text
        with open(output_filename, "w") as f:
            for result in results:
                f.write(str(result) + "\n")
     
    if output_format == "json":
	        # Save results as JSON
        with open(output_filename, "w") as f:
            json.dump(results, f)
            
    elif output_format == "xml":
        # Save results as XML
        xml_str = "<results>\n"
        for result in results:
            xml_str += "  <result>" + str(result) + "</result>\n"
    
def update_database(r, url, filename):
    """
    Download and update the specified database.
    """
    # Download the updated database
    r.flushall()
    r.set("db_url", url)
    r.set("db_filename", filename)
    download_database(url, filename)
    
    # Decompress the gzip-compressed database, if necessary
    if filename.endswith(".gz"):
        decompress_database(filename)
        filename = filename[:-3]
    
    # Insert data from the downloaded database into the new database
    if filename == "cve-allitems-cvrf.xml":
        # Parse the XML data and insert it into the database
        # (code not shown)
        pass
    elif filename.startswith("capec") and filename.endswith(".csv"):
        # Parse the CSV data and insert it into the database
        # (code not shown)
        pass
    elif filename.startswith("exploitdb") and filename.endswith(".csv"):
        # Parse the CSV data and insert it into the database
        # (code not shown)
        pass
    
def debug(debug_mode, message):
    """
    Print the specified message if debug mode is enabled.
    """
    if debug_mode:
        print(message)
                     
# Download the databases
# CVE
download_database("https://cve.mitre.org/data/downloads/allitems.csv.gz", "cve-allitems.csv.gz")
download_database("https://cve.mitre.org/data/downloads/allitems-cvrf.xml", "cve-allitems-cvrf.xml")
# download_database("https://cve.mitre.org/data/downloads/allitems.xml.gz", "cve-allitems.xml.gz")

# CAPEC
# Mechanisms of attack
download_database("https://capec.mitre.org/data/csv/1000.csv.zip", "capec1000.zip")
#download_database("https://capec.mitre.org/data/xml/views/1000.xml.zip", "capec1000.zip")
# Domains of attack
download_database("https://capec.mitre.org/data/csv/3000.csv.zip", "capec3000.zip")
# download_database("https://capec.mitre.org/data/csv/3000.xml.zip", "capec3000.zip")
# WASC Threat Classification 2.0
download_database("https://capec.mitre.org/data/csv/333.csv.zip", "capec333.zip")
# download_database("https://capec.mitre.org/data/csv/333.xml.zip", "capec333.zip")
# ATT&CK Related Patterns
download_database("https://capec.mitre.org/data/csv/658.csv.zip", "capec658.zip")
# download_database("https://capec.mitre.org/data/csv/658.xml.zip", "capec658.zip")
# OWASP Related Patterns
download_database("https://capec.mitre.org/data/csv/659.csv.zip", "capec659.zip")
# download_database("https://capec.mitre.org/data/xml/659.csv.zip", "capec659.zip")

# ExploitDB 
download_database("https://gitlab.com/exploit-database/exploitdb/-/blob/main/files_exploits.csv", "exploitdb-FE.csv")
download_database("https://gitlab.com/exploit-database/exploitdb/-/blob/main/files_shellcodes.csv", "exploitdb-FS.csv")
download_database("https://gitlab.com/exploit-database/exploitdb/-/blob/main/ghdb.xml", "exploitdb-GHDB.xml")

# Decompress the gzip-compressed databases
decompress_database("cve-allitems.csv.gz")
decompress_database("capec1000.zip")
decompress_database("capec3000.zip")
decompress_database("capec333.zip")
decompress_database("capec658.zip")
decompress_database("capec659.zip")

# Connect to Redis
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Check if the databases need to be updated
if r.get("db_url") != "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-recent.xml.gz":
    update_database(r, "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-recent.xml.gz", "cve.xml.gz")
if r.get("db_url") != "https://capec.mitre.org/data/xml/capec_v3.3.1.xml":
    update_database(r, "https://capec.mitre.org/data/xml/capec_v3.3.1.xml", "capec.xml")
if r.get("db_url") != "https://github.com/offensive-security/exploitdb/raw/master/files.csv":
    update_database(r, "https://github.com/offensive-security/exploitdb/raw/master/files.csv", "exploitdb.csv")

# Parse command line arguments
parser = argparse.ArgumentParser(description="Download and search vulnerabilities databases.")
parser.add_argument("-s", "--search", required=True, help="Search string to use in the databases")
parser.add_argument("-o", "--output", choices=["txt", "xml", "json"], help="Output format for the search results")
parser.add_argument("-f", "--output-file", help="Filename to save the search results to")
parser.add_argument("-u", "--update", action="store_true", help="Update the existing databases")
parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
args = parser.parse_args()

# Connect to Redis
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# Search the databases
results = []
for vulnerability_type in ["cve", "capec", "exploitdb"]:
    results += search_database(redis_client, vulnerability_type, args.search)

# Check if the databases need to be updated
if args.update:
    update_database(redis_client, "cve", "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-recent.xml.gz", "cve.xml.gz")
    update_database(redis_client, "capec", "https://capec.mitre.org/data/xml/capec_v3.3.1.xml", "capec.xml")
    update_database(redis_client, "exploitdb", "https://github.com/offensive-security/exploitdb/raw/master/files.csv", "exploitdb.csv")
