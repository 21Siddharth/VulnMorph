import requests

def scan_sqli(target):
    print(f"Scanning {target} for SQL Injection...")
    test_payload = "' OR '1'='1"
    try:
        # Test GET request
        response = requests.get(f"{target}?id={test_payload}", timeout=5)
        if "syntax error" in response.text.lower() or "sql" in response.text.lower():
            print(f"⚠️  Possible SQL Injection vulnerability detected in GET request at {target}!")
            return {"SQL Injection": True}
        
        # Test POST request
        response = requests.post(target, data={"id": test_payload}, timeout=5)
        if "syntax error" in response.text.lower() or "sql" in response.text.lower():
            print(f"⚠️  Possible SQL Injection vulnerability detected in POST request at {target}!")
            return {"SQL Injection": True}
        
        print(f"✅ No SQL Injection vulnerability found at {target}.")
        return {"SQL Injection": False}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning for SQL Injection: {e}")
        return {"SQL Injection": "Error"}
