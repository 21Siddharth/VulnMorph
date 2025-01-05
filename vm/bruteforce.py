import requests

def bruteforce_scan(target, wordlist, mode="directory"):
    print(f"Starting {mode} bruteforce on {target}...")
    found_items = []
    try:
        with open(wordlist, 'r') as f:
            for line in f:
                item = line.strip()
                if mode == "directory":
                    url = f"{target}/{item}"
                elif mode == "subdomain":
                    url = f"http://{item}.{target}"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"⚠️  Found {mode}: {url}")
                    found_items.append(url)
        if found_items:
            return {f"{mode.capitalize()}s": found_items}
        else:
            print(f"✅ No {mode}s found at {target}.")
            return {f"{mode.capitalize()}s": []}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error during {mode} bruteforce: {e}")
        return {f"{mode.capitalize()}s": "Error"}
    except FileNotFoundError:
        print(f"❌ Wordlist file not found: {wordlist}")
        return {f"{mode.capitalize()}s": "Error"}
