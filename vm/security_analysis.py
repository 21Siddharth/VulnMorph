import requests
import ssl
import socket
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def analyze_security(target):
    print(f"Analyzing security for {target}...")
    results = {}

    # Analyze HTTP headers
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
        recommendations = {
            "Content-Security-Policy": "Consider adding a Content-Security-Policy header to mitigate XSS attacks.",
            "Strict-Transport-Security": "Consider adding a Strict-Transport-Security header to enforce HTTPS.",
            "X-Content-Type-Options": "Consider adding an X-Content-Type-Options header to prevent MIME type sniffing.",
            "X-Frame-Options": "Consider adding an X-Frame-Options header to prevent clickjacking.",
            "X-XSS-Protection": "Consider adding an X-XSS-Protection header to enable XSS filtering.",
            "Referrer-Policy": "Consider adding a Referrer-Policy header to control the information sent in the Referer header.",
            "Permissions-Policy": "Consider adding a Permissions-Policy header to control the use of browser features."
        }

        if missing_headers:
            print(f"⚠️  Missing security headers: {', '.join(missing_headers)}")
            results["Missing Headers"] = missing_headers
            results["Recommendations"] = [recommendations[header] for header in missing_headers]
        else:
            print(f"✅ All security headers are present.")
            results["Missing Headers"] = []
            results["Recommendations"] = []

        # Check for CORS misconfiguration
        if "Access-Control-Allow-Origin" in headers:
            print(f"⚠️  CORS misconfiguration detected: Access-Control-Allow-Origin is set to {headers['Access-Control-Allow-Origin']}")
            results["CORS Misconfiguration"] = headers["Access-Control-Allow-Origin"]
        else:
            print(f"✅ No CORS misconfiguration detected.")
            results["CORS Misconfiguration"] = None

    except requests.exceptions.RequestException as e:
        print(f"❌ Error analyzing HTTP headers: {e}")
        results["HTTP Header Analysis"] = "Error"

    # Analyze SSL/TLS configuration
    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_info = ssock.getpeercert()
                print(f"✅ SSL/TLS certificate is valid for {hostname}.")
                results["SSL/TLS Certificate"] = "Valid"
    except Exception as e:
        print(f"❌ Error analyzing SSL/TLS configuration: {e}")
        results["SSL/TLS Certificate"] = "Error"

    # Detect vulnerable JavaScript files
    try:
        response = requests.get(target, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        vulnerable_js = []
        secret_keywords = [
            "API_KEY", "token", "secret", "password", "access_token", "auth", "key", "client_id", "client_secret"
        ]
        for script in scripts:
            js_url = urljoin(target, script['src'])
            js_response = requests.get(js_url, timeout=5)
            if any(re.search(keyword, js_response.text, re.IGNORECASE) for keyword in secret_keywords):
                print(f"⚠️  Possible vulnerable JavaScript file detected: {js_url}")
                vulnerable_js.append(js_url)
        results["Vulnerable JavaScript"] = vulnerable_js
    except requests.exceptions.RequestException as e:
        print(f"❌ Error analyzing JavaScript files: {e}")
        results["Vulnerable JavaScript"] = "Error"

    return {"Security Analysis": results}
