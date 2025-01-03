import requests

def dir_bruteforce(target, wordlist):
    print(f"Starting directory bruteforce on {target}...")
    found_dirs = []
    try:
        with open(wordlist, 'r') as f:
            for line in f:
                directory = line.strip()
                url = f"{target}/{directory}"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"⚠️  Found directory: {url}")
                    found_dirs.append(url)
        if found_dirs:
            return {"Directories": found_dirs}
        else:
            print(f"✅ No directories found at {target}.")
            return {"Directories": []}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error during directory bruteforce: {e}")
        return {"Directories": "Error"}
    except FileNotFoundError:
        print(f"❌ Wordlist file not found: {wordlist}")
        return {"Directories": "Error"}
