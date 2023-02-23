#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author:
import requests
import argparse

def download_files(api_key, collection):
    url = "https://vulners.com/api/v3/archive/collection/?type={}".format(collection)
    headers = {"X-Vulners-Api-Key": api_key}
    response = requests.get(url, headers=headers, verify=True)

    if response.status_code == 200:
        archive_url = response.json().get("data", {}).get("id")
        if archive_url:
            archive_response = requests.get(archive_url, headers=headers, verify=True)
            if archive_response.status_code == 200:
                with open("{}.zip".format(collection), "wb") as f:
                    f.write(archive_response.content)
                print("Downloaded archive for {}".format(collection))
            else:
                print("Error downloading archive for {}".format(collection))
        else:
            print("No archive URL found for {}".format(collection))
    else:
        print("Error getting archive URL for {}".format(collection))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--api-key", help="Vulners API key", required=True)
    args = parser.parse_args()

    collections = ["cnvd", "dsquare", "exploitdb", "exploitpack", "metasploit", "packetstorm", "saint", "seebug", "srcincite", "vulnerlab", "wpexploit", "zdt", "zeroscience"]
    for collection in collections:
        download_files(args.api_key, collection)

