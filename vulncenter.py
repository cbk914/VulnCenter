import argparse
import os
import requests
import sqlite3
import json
import gzip
import shutil
import zipfile

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
    
def search_database(db_filename, search_string):
    """
    Search the specified database for the given search string.
    """
    # Connect to the database
    conn = sqlite3.connect(db_filename)
    c = conn.cursor()
    
    # Execute the search query
    c.execute(f"SELECT * FROM vulnerabilities WHERE description LIKE '%{search_string}%'")
    
    # Return the search results
    return c.fetchall()

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
            
def update_database(db_name, url, filename):
    """
    Download and update the specified database.
    """
    # Download the updated database
    r = requests.get(url)
    r.raise_for_status()
    with open(filename, "wb") as f:
        f.write(r.content)
        
    # Decompress the gzip-compressed database, if necessary
    if filename.endswith(".gz"):
        with gzip.open(filename, "rb") as f_in:
            with open(filename[:-3], "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(filename)
        filename = filename[:-3]
    
    # Connect to the database
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    
    # Delete all rows from the existing table
    c.execute("DELETE FROM vulnerabilities")
    
    # Insert data from the downloaded database into the existing table
    if db_name == "cve.db":
        # Parse the XML data and insert it into the table
        # (code not shown)
        pass
    elif db_name == "capec.db":
        # Parse the XML data and insert it into the table
        # (code not shown)
        pass
    elif db_name == "exploitdb.db":
        # Parse the CSV data and insert it into the table
        # (code not shown)
        pass
    
    # Save the changes and close the connection
    conn.commit()
    conn.close()

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

# Connect to the new database
conn = sqlite3.connect("vulnerabilities.db")
c = conn.cursor()

# Create tables for the different databases
c.execute('''CREATE TABLE cve (id text, description text)''')
c.execute('''CREATE TABLE capec (id text, name text, description text)''')
c.execute('''CREATE TABLE exploitdb (id text, description text, type text)''')

# Insert data from the downloaded databases into the new database
for row in search_database("cve-allitems-cvrf.xml", "*"):
    c.execute("INSERT INTO cve VALUES (?, ?)", row)
for row in search_database("capec*.csv", "*"):
    c.execute("INSERT INTO capec VALUES (?, ?, ?)", row)
for row in search_database("exploitdb-*.csv", "*"):
    c.execute("INSERT INTO exploitdb VALUES (?, ?, ?)", row)
for row in search_database("exploitdb-GHDB.xml", "*"):
    c.execute("INSERT INTO exploitdb VALUES (?, ?, ?)", row)    

# Save the changes and close the connection
conn.commit()
conn.close()

# Parse command line arguments
parser = argparse.ArgumentParser(description="Download and search vulnerabilities databases.")
parser.add_argument("-s", "--search", required=True, help="Search string to use in the databases")
parser.add_argument("-o", "--output", choices=["txt", "xml", "json"], help="Output format for the search results")
parser.add_argument("-f", "--output-file", help="Filename to save the search results to")
parser.add_argument("-u", "--update", action="store_true", help="Update the existing databases")
parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
args = parser.parse_args()

# Search the databases
results = []
for db_filename in ["cve.db", "capec.db", "exploitdb.db"]:
    results += search_database(db_filename, args.search)

# Check if the databases need to be updated
if args.update:
    update_database("cve.db", "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-recent.xml.gz", "cve.xml.gz")
    update_database("capec.db", "https://capec.mitre.org/data/xml/capec_v3.3.1.xml", "capec.xml")
    update_database("exploitdb.db", "https://github.com/offensive-security/exploitdb/raw/master/files.csv", "exploitdb.csv")

# Save results
if args.output_file:
    save_results(results, args.output, args.output_file)