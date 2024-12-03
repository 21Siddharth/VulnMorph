import requests

def scan_xss(target):
    print(f"Scanning {target} for Cross-Site Scripting (XSS)...")
    try:
        test_payload = "<script>alert('XSS')</script>"
        response = requests.get(f"{target}?search={test_payload}", timeout=5)
        if test_payload in response.text:
            print(f"⚠️  Possible XSS vulnerability detected at {target}!")
            return {"XSS": True}
        else:
            print(f"✅ No XSS vulnerability found at {target}.")
            return {"XSS": False}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning for XSS: {e}")
        return {"XSS": "Error"}