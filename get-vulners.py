import argparse
import hashlib
import logging
import os
import requests
import sys
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    filename="vulners.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def save_api_key_to_env(api_key):
    env_file_path = os.path.join(".", ".env")
    with open(env_file_path, "a") as env_file:
        env_file.write(f"VULNERS_API_KEY={api_key}\n")

def is_invalid_file_size(file_size):
    return file_size == 131

def get_api_key(args_api_key):
    if not args_api_key:
        api_key = os.getenv("VULNERS_API_KEY")
        if not api_key:
            print("Please provide an API key with -a or save it in .env file with VULNERS_API_KEY variable.")
            sys.exit(1)
    else:
        api_key = args_api_key
        save_api_key_to_env(api_key)

    return api_key

def create_vulners_directory():
    if not os.path.exists("vulners"):
        os.makedirs("vulners")

def get_vulners_links():
    return [
        "cnvd",
        "dsquare",
        "exploitdb",
        "exploitpack",
        "metasploit",
        "packetstorm",
        "saint",
        "seebug",
        "srcincite",
        "vulnerlab",
        "wpexploit",
        "zdt",
        "zeroscience"
    ]

def get_headers(api_key):
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
        "X-API-KEY": api_key
    }

def get_timestamped_filename(link):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{link}_{timestamp}.json"

def download_vulners_links(api_key):
    links = get_vulners_links()
    base_url = "https://vulners.com/api/v3/archive/collection/?type="
    headers = get_headers(api_key)

    create_vulners_directory()

    with requests.Session() as session:
        session.headers.update(headers)

        for link in links:
            url = base_url + link
            try:
                response = session.get(url)
            except requests.exceptions.RequestException as e:
                logging.error(f"Error downloading {link}: {e}")
                print(f"Error downloading {link}: {e}")
                continue

            if response.status_code != 200:
                logging.error(f"Error downloading {link}. Status code: {response.status_code}.")
                print(f"Error downloading {link}. Status code: {response.status_code}.")
                continue

            filename = get_timestamped_filename(link)
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
                file_size = f.tell()

            if is_invalid_file_size(file_size):
                os.remove(filepath)
                logging.warning(f"Downloaded {filename} is incorrect and has been removed.")
                print(f"Downloaded file {filename} is incorrect and has been removed.")
            else:
                logging.info(f"Downloaded {filename} successfully.")
                print(f"Downloaded file {filename} successfully.")

def main():
    parser = argparse.ArgumentParser(description="Download links from Vulners archive with API key parameter")
    parser.add_argument("-a", "--api-key", type=str, help="API key for Vulners archive")
    args = parser.parse_args()

    api_key = get_api_key(args.api_key)
    download_vulners_links(api_key)

if __name__ == "__main__":
    main()
