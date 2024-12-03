import argparse
import json
from xss_scanner import scan_xss
from sqli_scanner import scan_sqli
from open_ports_scanner import scan_open_ports

# Mapping vulnerabilities to their scanner functions
SCANNERS = {
    "XSS": scan_xss,
    "SQL Injection": scan_sqli,
    "Open Ports": scan_open_ports,
}

# Scan execution
def perform_scan(target, vulnerabilities):
    print(f"\n🚀 Starting scan on: {target}")
    results = {}
    for vuln in vulnerabilities:
        print(f"\n🔍 Checking for: {vuln}")
        scanner = SCANNERS.get(vuln)
        if scanner:
            results.update(scanner(target))
        else:
            print(f"⚠️  No scanner implemented for {vuln}.")
    print("\n✅ Scan completed!")
    print("\n📊 Results:")
    print(json.dumps(results, indent=4))
    return results

# Main function
def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument(
        "-t", "--target", required=True, help="Target URL or IP to scan."
    )
    parser.add_argument(
        "-x", "--xss", action="store_true", help="Scan for Cross-Site Scripting (XSS)."
    )
    parser.add_argument(
        "-s", "--sql", action="store_true", help="Scan for SQL Injection."
    )
    parser.add_argument(
        "-op", "--open-ports", action="store_true", help="Scan for Open Ports."
    )
    parser.add_argument(
        "-a", "--all", action="store_true", help="Scan for all vulnerabilities."
    )

    args = parser.parse_args()

    # print(f"🌐 Arguments received: {args}")  # Debugging output

    # Determine the scans to perform
    vulnerabilities_to_scan = []
    if args.all:
        print("Performing a full scan for all vulnerabilities...")
        vulnerabilities_to_scan = ["XSS", "SQL Injection", "Open Ports"]
    else:
        if args.xss:
            vulnerabilities_to_scan.append("XSS")
        if args.sql:
            vulnerabilities_to_scan.append("SQL Injection")
        if args.open_ports:
            vulnerabilities_to_scan.append("Open Ports")
    
    if vulnerabilities_to_scan:
        perform_scan(args.target, vulnerabilities_to_scan)
    else:
        print("❌ Please specify a scan type: --xss, --sql, --open-ports, or --all.")
        parser.print_help()

if __name__ == "__main__":
    main()