import requests

def scan_xss(target):
    print(f"Scanning {target} for Cross-Site Scripting (XSS)...")
    test_payload = "<script>alert('XSS')</script>"
    try:
        # Test GET request
        response = requests.get(f"{target}?search={test_payload}", timeout=5)
        if test_payload in response.text:
            print(f"⚠️  Possible XSS vulnerability detected in GET request at {target}!")
            return {"XSS": True}
        
        # Test POST request
        response = requests.post(target, data={"search": test_payload}, timeout=5)
        if test_payload in response.text:
            print(f"⚠️  Possible XSS vulnerability detected in POST request at {target}!")
            return {"XSS": True}
        
        print(f"✅ No XSS vulnerability found at {target}.")
        return {"XSS": False}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning for XSS: {e}")
        return {"XSS": "Error"}