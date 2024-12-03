import requests

def scan_sqli(target):
    print(f"Scanning {target} for SQL Injection...")
    try:
        test_payload = "' OR '1'='1"
        response = requests.get(f"{target}?id={test_payload}", timeout=5)
        if "syntax error" in response.text.lower() or "sql" in response.text.lower():
            print(f"⚠️  Possible SQL Injection vulnerability detected at {target}!")
            return {"SQL Injection": True}
        else:
            print(f"✅ No SQL Injection vulnerability found at {target}.")
            return {"SQL Injection": False}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning for SQL Injection: {e}")
        return {"SQL Injection": "Error"}
