import requests
from bs4 import BeautifulSoup

def scan_xss(target, custom_payloads=None):
    print(f"Scanning {target} for Cross-Site Scripting (XSS)...")
    payloads = custom_payloads if custom_payloads else ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    try:
        for test_payload in payloads:
            # Test URL query parameter
            response = requests.get(f"{target}?search={test_payload}", timeout=5)
            if test_payload in response.text:
                print(f"⚠️  Possible XSS vulnerability detected at {target}!")
                return {"XSS": True, "XSS Payload": test_payload}
            
            # Test input fields in forms
            response = requests.get(target, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                data = {input.get('name'): test_payload for input in inputs if input.get('name')}
                form_target = action if action.startswith('http') else f"{target}/{action}"
                if method == 'post':
                    response = requests.post(form_target, data=data, timeout=5)
                else:
                    response = requests.get(form_target, params=data, timeout=5)
                if test_payload in response.text:
                    print(f"⚠️  Possible XSS vulnerability detected in form at {form_target}!")
                    return {"XSS": True, "XSS Payload": test_payload}
        
        print(f"✅ No XSS vulnerability found at {target}.")
        return {"XSS": False}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning for XSS: {e}")
        return {"XSS": "Error"}
