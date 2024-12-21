import requests
from bs4 import BeautifulSoup

def scan_sqli(target, custom_payloads=None):
    print(f"Scanning {target} for SQL Injection...")
    payloads = custom_payloads if custom_payloads else ["' OR '1'='1", "' OR '1'='1' --"]
    try:
        for test_payload in payloads:
            # Test URL query parameter
            response = requests.get(f"{target}?id={test_payload}", timeout=5)
            if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                print(f"⚠️  Possible SQL Injection vulnerability detected at {target}!")
                return {"SQL Injection": True, "SQL Injection Payload": test_payload}
            
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
                if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                    print(f"⚠️  Possible SQL Injection vulnerability detected in form at {form_target}!")
                    return {"SQL Injection": True, "SQL Injection Payload": test_payload}
        
        print(f"✅ No SQL Injection vulnerability found at {target}.")
        return {"SQL Injection": False}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error scanning for SQL Injection: {e}")
        return {"SQL Injection": "Error"}
