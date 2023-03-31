import argparse
import hashlib
import logging
import os
import requests
import sys
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    filename="vulners.log", 
    level=logging.DEBUG, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def save_api_key_to_env(api_key):
    with open(".env", "a") as env_file:
        env_file.write(f"VULNERS_API_KEY={api_key}\n")

def download_vulners_links(api_key):
    links = [
        "https://vulners.com/api/v3/archive/collection/?type=exploitpack",
        "https://vulners.com/api/v3/archive/collection/?type=metasploit",
        "https://vulners.com/api/v3/archive/collection/?type=packetstorm",
        "https://vulners.com/api/v3/archive/collection/?type=saint",
        "https://vulners.com/api/v3/archive/collection/?type=seebug",
        "https://vulners.com/api/v3/archive/collection/?type=srcincite",
        "https://vulners.com/api/v3/archive/collection/?type=vulnerlab",
        "https://vulners.com/api/v3/archive/collection/?type=wpexploit",
        "https://vulners.com/api/v3/archive/collection/?type=zdt",
        "https://vulners.com/api/v3/archive/collection/?type=zeroscience"
    ]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "X-API-KEY": api_key
    }

    if not os.path.exists("vulners"):
        os.makedirs("vulners")

    for link in links:
        response = requests.get(link, headers=headers)

        if response.status_code != 200:
            logging.error(f"Error downloading {link}. Status code: {response.status_code}.")
            continue

        filename = link.split("=")[1] + ".json"
        filepath = os.path.join("vulners", filename)

        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
                response_hash = response.headers.get("X-SHA256", "")
            if current_hash == response_hash:
                logging.info(f"{filename} has already been downloaded.")
                continue

        with open(filepath, "wb") as f:
            f.write(response.content)
            logging.info(f"Downloaded {filename} successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download links from Vulners archive with API key parameter")
    parser.add_argument("-a", "--api-key", type=str, help="API key for Vulners archive")
    args = parser.parse_args()

    if not args.api_key:
        api_key = os.getenv("VULNERS_API_KEY")
        if not api_key:
            print("Please provide an API key with -a or save it in .env file with VULNERS_API_KEY variable.")
            sys.exit(1)
    else:
        api_key = args.api_key
        save_api_key_to_env(api_key)

    download_vulners_links(api_key)
