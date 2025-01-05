import requests
import ssl
import socket
from urllib.parse import urlparse

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

        if missing_headers:
            print(f"⚠️  Missing security headers: {', '.join(missing_headers)}")
            results["Missing Headers"] = missing_headers
        else:
            print(f"✅ All security headers are present.")
            results["Missing Headers"] = []

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

    return {"Security Analysis": results}
