import requests

def analyze_headers(target):
    print(f"Analyzing HTTP headers for {target}...")
    try:
        response = requests.get(target, timeout=5)
        headers = response.headers

        # Define a checklist of security headers
        security_headers = {
            "Content-Security-Policy": "Content-Security-Policy",
            "Strict-Transport-Security": "Strict-Transport-Security",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "X-XSS-Protection",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy"
        }

        missing_headers = [header for header in security_headers if header not in headers]

        if missing_headers:
            print(f"⚠️  Missing security headers: {', '.join(missing_headers)}")
            return {"HTTP Header Analysis": "Missing Headers", "Missing Headers": missing_headers}
        else:
            print(f"✅ All security headers are present.")
            return {"HTTP Header Analysis": "All Headers Present"}
    except requests.exceptions.RequestException as e:
        print(f"❌ Error analyzing HTTP headers: {e}")
        return {"HTTP Header Analysis": "Error"}
