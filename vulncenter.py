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

DEFAULT_TIMEOUT = 30

def download_database(url, filename):
    """
    Download a database from the given URL and save it to the specified filename.

    Raises requests.HTTPError on a non-2xx response instead of silently writing
    the server's error page to disk as if it were the database.
    """
    r = requests.get(url, timeout=DEFAULT_TIMEOUT)
    r.raise_for_status()
    content = r.content
    # A proxy/captive-portal error page starts with '<'. Never persist that as
    # a database: it would only blow up later inside decompress_database().
    if content.lstrip()[:1] == b"<":
        raise ValueError(
            "Refusing to save an HTML document as database {!r} "
            "(is {!r} a raw file URL rather than a /blob/ web page?)".format(filename, url)
        )
    with open(filename, "wb") as f:
        f.write(content)

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

def search_database(r, vulnerability_type, search_string):
    """
    Search the specified database for the given search string.
    """
    # Execute the search query
    results = []
    for key in r.scan_iter("vulnerability:*"):
        # hget() returns None when the hash has no "description" field.
        description = r.hget(key, "description")
        if description is None:
            continue
        if search_string in description.decode():
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
        xml_str = "<results>\n"
        for result in results:
            xml_str += "  <result>" + str(result) + "</result>\n"

def update_database(r, vulnerability_type, url, filename):
    """
    Download and update the specified database.
    """
    # Download the updated database
    r.flushall()
    r.set("db_url", url)
    r.set("db_filename", filename)
    r.set("db_type", vulnerability_type)
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
# NOTE: the exploit-database URLs below must use GitLab's /-/raw/ path.
# /-/blob/ serves an HTML page, so the old URLs wrote a web page to disk and
# it was then handed to the gzip/zip parsers as if it were a database.
DATABASES = [
    # CVE
    ("cve", "https://cve.mitre.org/data/downloads/allitems.csv.gz", "cve-allitems.csv.gz"),
    ("cve", "https://cve.mitre.org/data/downloads/allitems-cvrf.xml", "cve-allitems-cvrf.xml"),
    # CAPEC
    # Mechanisms of attack
    ("capec", "https://capec.mitre.org/data/csv/1000.csv.zip", "capec1000.zip"),
    # Domains of attack
    ("capec", "https://capec.mitre.org/data/csv/3000.csv.zip", "capec3000.zip"),
    # WASC Threat Classification 2.0
    ("capec", "https://capec.mitre.org/data/csv/333.csv.zip", "capec333.zip"),
    # ATT&CK Related Patterns
    ("capec", "https://capec.mitre.org/data/csv/658.csv.zip", "capec658.zip"),
    # OWASP Related Patterns
    ("capec", "https://capec.mitre.org/data/csv/659.csv.zip", "capec659.zip"),
    # ExploitDB
    ("exploitdb", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", "exploitdb-FE.csv"),
    ("exploitdb", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_shellcodes.csv", "exploitdb-FS.csv"),
    ("exploitdb", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/ghdb.xml", "exploitdb-GHDB.xml"),
]

COMPRESSED = [
    "cve-allitems.csv.gz",
    "capec1000.zip",
    "capec3000.zip",
    "capec333.zip",
    "capec658.zip",
    "capec659.zip",
]

FEEDS = [
    ("cve", "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-recent.xml.gz", "cve.xml.gz"),
    ("capec", "https://capec.mitre.org/data/xml/capec_v3.3.1.xml", "capec.xml"),
    ("exploitdb", "https://github.com/offensive-security/exploitdb/raw/master/files.csv", "exploitdb.csv"),
]

def connect_redis():
    return redis.Redis(host='localhost', port=6379, db=0)

def main():
    # Download the databases
    for _vuln_type, _url, _filename in DATABASES:
        download_database(_url, _filename)

    # Decompress the gzip-compressed databases
    for _archive in COMPRESSED:
        decompress_database(_archive)

    # Connect to Redis
    redis_client = connect_redis()

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Download and search vulnerabilities databases.")
    parser.add_argument("-s", "--search", required=True, help="Search string to use in the databases")
    parser.add_argument("-o", "--output", choices=["txt", "xml", "json"], help="Output format for the search results")
    parser.add_argument("-f", "--output-file", help="Filename to save the search results to")
    parser.add_argument("-u", "--update", action="store_true", help="Update the existing databases")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    args = parser.parse_args()

    # Check if the databases need to be updated
    for vuln_type, url, filename in FEEDS:
        if redis_client.get("db_url") != url:
            update_database(redis_client, vuln_type, url, filename)

    # Search the databases
    results = []
    for vulnerability_type in ["cve", "capec", "exploitdb"]:
        results += search_database(redis_client, vulnerability_type, args.search)

    # Save the search results to a file
    if args.output and args.output_file:
        save_results(results, args.output, args.output_file)

    # Check if the databases need to be updated
    if args.update:
        for vuln_type, url, filename in FEEDS:
            update_database(redis_client, vuln_type, url, filename)

if __name__ == "__main__":
    main()