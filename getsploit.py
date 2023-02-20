#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import vulners
import re
import os
import six
import texttable
import urllib
from six import string_types
from clint.textui import progress
from os.path import expanduser
import errno
import hashlib
import getpass

import redis

if six.PY2:
    import argparse
else:
    from optparse import OptionParser as argparse

if six.PY3:
    unicode_type = str
    bytes_type = bytes
else:
    unicode_type = unicode
    bytes_type = str


SCRIPTNAME = os.path.split(os.path.abspath(__file__))
DBPATH = os.path.join(expanduser("~"), '.getsploit')
DBFILE = os.path.join(DBPATH, 'getsploit.db')
KEYFILE = os.path.join(DBPATH, 'vulners.key')
MAX_ATTEMPTS = 3

if not os.path.exists(DBPATH):
    try:
        os.makedirs(DBPATH)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise

try:
    LOCAL_SEARCH_AVAILABLE = True
    redis_host = 'localhost'
    redis_port = 6379
    redis_password = None
    redis_db = 0
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        r = redis.from_url(redis_url)
    else:
        r = redis.StrictRedis(
            host=redis_host, port=redis_port, password=redis_password, db=redis_db)
    r.ping()
except Exception as e:
    print('Redis connection error: ', e)
    LOCAL_SEARCH_AVAILABLE = False


class RedisClient(vulners.Vulners):

    api_endpoints = {
        'search': "/api/v3/search/lucene/",
        'software': "/api/v3/burp/software/",
        'apiKey': "/api/v3/apiKey/valid/",
        'searchsploitdb': "/api/v3/archive/getsploit/"
    }

    def __init__(self, api_key=None):
        super(RedisClient, self).__init__(api_key=api_key)

    def check_api_key(self):
        response = self._Vulners__opener.get(self.vulners_urls['apiKey'])
        return json.loads(response.read().decode())

    def search_local(self, query, lookup_fields=None, limit=500, offset=0, fields=None):
        searchQuery, dataDocs = self.searchExploit(query, lookup_fields, limit, offset, fields)
        return dataDocs

    def search(self, query, lookup_fields=None, limit=500, offset=0, fields=None):
        searchQuery, dataDocs = self.searchExploit(query, lookup_fields, limit, offset, fields)
        return dataDocs

    def download_getsploit_db(self):
        """
        Downloads the getsploit exploit database from Vulners API.

        :return: The getsploit exploit data.
        :rtype: list of dict
        """
        if not LOCAL_SEARCH_AVAILABLE:
            raise Exception("Local search is not available")
        print("Downloading getsploit database archive. Please wait, it may take time. Usually around 5-10 minutes.")
        download_request = urllib.request.urlopen(self.vulners_urls['searchsploitdb'])
        data = download_request.read()
        # Store the data using SHA-512 as key
        key = hashlib.sha512(data).hexdigest()
        r.set(key, data)
        archive = zipfile.ZipFile(data)
        archive.extractall(expanduser("~/.getsploit"))
        archive.close()
        with open(expanduser("~/.getsploit/getsploit.json"), "r") as f:
            return json.loads(f.read())

def authenticate():
    """
    Authenticates the client using the provided API key.

    :return: The authenticated client.
    :rtype: RedisClient
    """
    api_key_file = expanduser("~/.getsploit/apikey.txt")
    if not os.path.exists(api_key_file):
        api_key = getpass.getpass("Enter Vulners API key: ")
        with open(api_key_file, "w") as f:
            f.write(hashlib.sha512(api_key.encode("utf-8")).hexdigest())
    else:
        with open(api_key_file, "r") as f:
            saved_api_key_hash = f.read().strip()
        for i in range(3):
            api_key = getpass.getpass("Enter Vulners API key: ")
            if hashlib.sha512(api_key.encode("utf-8")).hexdigest() == saved_api_key_hash:
                break
            else:
                print("Invalid API key")
        else:
            print("Too many failed attempts")
            sys.exit(1)
    return RedisClient(api_key)

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Exploit search and download utility")
    parser.add_argument("query", metavar="query", type=str, nargs="+",
                        help="Exploit search query. See https://vulners.com/help for the detailed manual.")
    parser.add_argument("-t", "--title", action="store_true",
                        help="Search JUST the exploit title (Default is description and source code).")
    parser.add_argument("-j", "--json", action="store_true",
                        help="Show result in JSON format.")
    parser.add_argument("-m", "--mirror", action="store_true",
                        help="Mirror (aka copies) search result exploit files to the subdirectory with your search query name.")
    parser.add_argument("-c", "--count", nargs=1, type=int, default=10,
                        help="Search limit. Default 10.")
    parser.add_argument("-l", "--local", action="store_true",
                        help="Perform search in the local database instead of searching online.")
    parser.add_argument("-u", "--update", action="store_true",
                        help="Update local database with latest information from Vulners API.")
    args = parser.parse_args()

    # Check if search query is provided
    if not args.query:
        print("No search query provided. Type software name and version to find exploit.")
        sys.exit(1)

    # Authenticate the client
    client = authenticate()

    # Update the database if requested
    if args.update:
        if not LOCAL_SEARCH_AVAILABLE:
            print("Local search is not available")
            sys.exit(1)
        try:
            searchsploit_data = client.download_getsploit_db()
            for data in searchsploit_data:
                query = "bulletinFamily:exploitdb AND id:{} AND type:exploitdb".format(data["id"])
                response = client.search(query)
                if response["total"] == 1:
                    doc = response["search"][0]
                    doc["sourceData"] = data["sourceData"]
                    client.insert(doc, "exploitdb")
                else:
                    data.pop("sourceData")
                    client.insert(data, "exploitdb")
            print("Database updated")
        except urllib.error.URLError:
            print("Could not download getsploit database. Please check your internet connection and try again.")
        sys.exit(0)

    # Search the database
    if args.local:
        search_results = client.search_local(args.query[0], fields=["title"] if args.title else None, limit=args.count)
    else:
        search_results = client.search(args.query[0], fields=["title"] if args.title else None, limit=args.count)

    # Display results
    if args.json:
        print(json.dumps(search_results))
    else:
        table = Texttable()
        table.set_cols_dtype(["t", "t", "t"])
        table.set_cols_align(["c", "l", "c"])
        table.set_cols_width(["20", "30", "100"])
        table.add_rows([["ID", "Exploit Title", "URL"]] + [[res["id"], res["title"], res["vhref"]] for res in search_results])
        print(table.draw())
