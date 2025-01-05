import argparse
import json
import os
from vm.xss_scanner import scan_xss
from vm.sqli_scanner import scan_sqli
from vm.open_ports_scanner import scan_open_ports
from vm.crawler import crawl
from vm.bruteforce import bruteforce_scan  # Updated import
from vm.security_analysis import analyze_security  # Import the new security analysis function

# Mapping vulnerabilities to their scanner functions
SCANNERS = {
    "XSS": scan_xss,
    "SQL Injection": scan_sqli,
    "Open Ports": scan_open_ports,
    "Directory Bruteforce": bruteforce_scan,  # Updated mapping
    "Security Analysis": analyze_security,  # Add the new scanner to the mapping
}

# Scan execution
def perform_scan(target, vulnerabilities, custom_payloads, num_ports, max_depth, wordlist, bruteforce_mode):
    print(f"\n🚀 Starting scan on: {target}")
    results = {}

    # Check if only open ports or security analysis are being scanned
    if vulnerabilities == ["Open Ports"] or vulnerabilities == ["Security Analysis"]:
        for vuln in vulnerabilities:
            print(f"\n🔍 Scanning for {vuln} on: {target}")
            scanner = SCANNERS.get(vuln)
            if scanner:
                scan_result = scanner(target) if vuln == "Security Analysis" else scanner(target, num_ports=num_ports)
                results.update(scan_result)
    else:
        # Perform crawling for other vulnerabilities
        urls_to_scan = crawl(target, max_depth=max_depth)
        urls_to_scan.add(target)  # Ensure the target URL is included in the scan

        # Perform scans based on vulnerabilities
        for vuln in vulnerabilities:
            if vuln == "Open Ports" or vuln == "Security Analysis":
                print(f"\n🔍 Scanning for {vuln} on: {target}")
                scanner = SCANNERS.get(vuln)
                if scanner:
                    scan_result = scanner(target) if vuln == "Security Analysis" else scanner(target, num_ports=num_ports)
                    results.update(scan_result)
                continue  # Skip further processing for Open Ports and Security Analysis as they're not URL-specific

            # Scan for other vulnerabilities (e.g., XSS, SQL Injection) on crawled URLs
            for url in urls_to_scan:
                print(f"\n🔍 Scanning URL: {url}")
                scanner = SCANNERS.get(vuln)
                if scanner:
                    if vuln == "Directory Bruteforce":
                        scan_result = scanner(url, wordlist, mode=bruteforce_mode)
                    else:
                        payloads = custom_payloads.get(vuln)
                        scan_result = scanner(url, custom_payloads=payloads)
                    results.update(scan_result)
                else:
                    print(f"⚠️  No scanner implemented for {vuln}.")

    print("\n✅ Scan completed!")
    print("\n📊 Results:")
    print(json.dumps(results, indent=4))

    # Generate HTML report
    generate_html_report(target, results)

    return results

def generate_html_report(target, results):
    report_filename = f"{target.replace('http://', '').replace('https://', '').replace('/', '_')}_report.html"
    report_path = os.path.join(os.getcwd(), report_filename)
    with open(report_path, 'w') as report_file:
        report_file.write("<html><head><title>Scan Report</title></head><body>")
        report_file.write(f"<h1>Scan Report for {target}</h1>")
        report_file.write("<pre>")
        report_file.write(json.dumps(results, indent=4))
        report_file.write("</pre>")
        report_file.write("</body></html>")
    print(f"\n📄 Report saved to: {report_path}")

# Main function
def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner",
    )
    parser.add_argument(
        "-t", "--target", required=True, help="Target URL or IP to scan. Example: http://domain.com"
    )
    args = parser.parse_args()

    print("Select the vulnerabilities to scan for:")
    print("1. Cross-Site Scripting (XSS)")
    print("2. SQL Injection")
    print("3. Open Ports")
    print("4. Directory/Subdomain Bruteforce")
    print("5. Security Analysis (Headers, SSL/TLS, CORS, vulerable js and secrets)")
    print("6. All (! Might take longer to complete !)")
    choices = input("Enter your choices separated by commas (e.g., 1,3): ").split(',')

    vulnerabilities_to_scan = []
    if '6' in choices:
        print("Performing a full scan for all vulnerabilities...")
        vulnerabilities_to_scan = ["XSS", "SQL Injection", "Open Ports", "Directory Bruteforce", "Security Analysis"]
    else:
        if '1' in choices:
            vulnerabilities_to_scan.append("XSS")
        if '2' in choices:
            vulnerabilities_to_scan.append("SQL Injection")
        if '3' in choices:
            vulnerabilities_to_scan.append("Open Ports")
        if '4' in choices:
            vulnerabilities_to_scan.append("Directory Bruteforce")
        if '5' in choices:
            vulnerabilities_to_scan.append("Security Analysis")

    custom_payloads = {
        "XSS": None,
        "SQL Injection": None
    }

    if "XSS" in vulnerabilities_to_scan:
        xss_payloads = input("Enter custom XSS payloads separated by commas (or press Enter to use default): ")
        if xss_payloads:
            custom_payloads["XSS"] = xss_payloads.split(',')

    if "SQL Injection" in vulnerabilities_to_scan:
        sql_payloads = input("Enter custom SQL Injection payloads separated by commas (or press Enter to use default): ")
        if sql_payloads:
            custom_payloads["SQL Injection"] = sql_payloads.split(',')

    num_ports = 1024
    if "Open Ports" in vulnerabilities_to_scan:
        num_ports = input("Enter the number of ports to scan (default is 1024): ")
        if num_ports:
            num_ports = int(num_ports)

    max_depth = 2
    if any(vuln in vulnerabilities_to_scan for vuln in ["XSS", "SQL Injection", "Directory Bruteforce"]):
        max_depth = input("Enter the maximum depth for crawling (default is 2): ")
        if max_depth:
            max_depth = int(max_depth)

    wordlist = None
    bruteforce_mode = "directory"
    if "Directory Bruteforce" in vulnerabilities_to_scan:
        bruteforce_mode = input("Enter the mode for bruteforce (directory/subdomain): ").strip().lower()
        wordlist = input("Enter the path to the wordlist file: ")

    if vulnerabilities_to_scan:
        perform_scan(args.target, vulnerabilities_to_scan, custom_payloads, num_ports, max_depth, wordlist, bruteforce_mode)
    else:
        print("❌ Please specify at least one scan type.")

if __name__ == "__main__":
    main()