import requests
import argparse

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

    for link in links:
        response = requests.get(link, headers=headers)
        if response.status_code == 200:
            filename = link.split("=")[1] + ".json"
            with open(filename, "wb") as f:
                f.write(response.content)
                print(f"Downloaded {filename} successfully.")
        else:
            print(f"Error downloading {link}. Status code: {response.status_code}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download links from Vulners archive with API key parameter")
    parser.add_argument("-a", "--api-key", type=str, help="API key for Vulners archive", required=True)
    args = parser.parse_args()

    download_vulners_links(args.api_key)
