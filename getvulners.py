#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: cbk914
import requests
import argparse
import os

def download(name, path_to_save, api_key):
    url = 'https://vulners.com/api/v3/archive/collection/'
    params = {'type': name}
    headers = {'X-Vulners-Api-Key': api_key}
    response = requests.get(url, headers=headers, params=params, verify=True)

    if response.status_code == 200:
        archive_url = response.json().get('data', {}).get('id')
        if archive_url:
            archive_response = requests.get(archive_url, headers=headers, verify=True)
            if archive_response.status_code == 200:
                file_size = int(archive_response.headers.get('content-length', 0))
                with open(os.path.join(path_to_save, name + '.zip'), 'wb') as f:
                    f.write(archive_response.content)
                return f"{name} - {file_size} bytes"
            else:
                return f"Error downloading archive for {name}"
        else:
            return f"No archive URL found for {name}"
    else:
        return f"Error getting archive URL for {name}"

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--api-key', help='Vulners API key', required=True)
    parser.add_argument('-p', '--path-to-save', help='Path to save downloaded archives', required=True)
    args = parser.parse_args()

    collections = ['cnvd', 'dsquare', 'exploitdb', 'exploitpack', 'metasploit', 'packetstorm', 'saint', 'seebug', 'srcincite', 'vulnerlab', 'wpexploit', 'zdt', 'zeroscience']
    for collection in collections:
        result = download(collection, args.path_to_save, args.api_key)
        print(result)
