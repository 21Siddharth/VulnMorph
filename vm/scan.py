import argparse
import json
from vm.xss_scanner import scan_xss
from vm.sqli_scanner import scan_sqli
from vm.open_ports_scanner import scan_open_ports
from vm.crawler import crawl
from vm.dir_bruteforce import dir_bruteforce

# Mapping vulnerabilities to their scanner functions
SCANNERS = {
    "XSS": scan_xss,
    "SQL Injection": scan_sqli,
    "Open Ports": scan_open_ports,
    "Directory Bruteforce": dir_bruteforce,
}

# Scan execution
def perform_scan(target, vulnerabilities, custom_payloads, num_ports, max_depth, wordlist):
    print(f"\n🚀 Starting scan on: {target}")
    results = {}
    urls_to_scan = crawl(target, max_depth=max_depth)
    for url in urls_to_scan:
        print(f"\n🔍 Scanning URL: {url}")
        for vuln in vulnerabilities:
            print(f"\n🔍 Checking for: {vuln}")
            scanner = SCANNERS.get(vuln)
            if scanner:
                if vuln == "Open Ports":
                    scan_result = scanner(url, num_ports=num_ports)
                elif vuln == "Directory Bruteforce":
                    scan_result = scanner(url, wordlist)
                else:
                    payloads = custom_payloads.get(vuln)
                    scan_result = scanner(url, custom_payloads=payloads)
                results.update(scan_result)
            else:
                print(f"⚠️  No scanner implemented for {vuln}.")
    print("\n✅ Scan completed!")
    print("\n📊 Results:")
    print(json.dumps(results, indent=4))
    return results

# Main function
def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanner",
    )
    parser.add_argument(
        "-t", "--target", required=True, help="Target URL or IP to scan. Example: http://domain.com"
    )
    parser.add_argument(
        "-x", "--xss", action="store_true", help="Scan for Cross-Site Scripting (XSS). Example: python -m vm.scan -t http://domain.com -x"
    )
    parser.add_argument(
        "-s", "--sql", action="store_true", help="Scan for SQL Injection. Example: python -m vm.scan -t http://domain.com -s"
    )
    parser.add_argument(
        "-op", "--open-ports", action="store_true", help="Scan for Open Ports. Example: python -m vm.scan -t http://domain.com -op"
    )
    parser.add_argument(
        "-a", "--all", action="store_true", help="Scan for all vulnerabilities. Example: python -m vm.scan -t http://domain.com -a"
    )
    parser.add_argument(
        "--xss-payloads", nargs='+', help="Custom payloads for XSS testing. Example: python -m vm.scan -t http://domain.com -x --xss-payloads \"<script>alert('XSS1')</script>\" \"<img src=x onerror=alert('XSS2')>\""
    )
    parser.add_argument(
        "--sql-payloads", nargs='+', help="Custom payloads for SQL Injection testing. Example: python -m vm.scan -t http://domain.com -s --sql-payloads \"' OR '1'='1\" \"' OR '1'='1' --\""
    )
    parser.add_argument(
        "--num-ports", type=int, default=1024, help="Number of ports to scan for Open Ports. Example: python -m vm.scan -t http://domain.com -op --num-ports 500"
    )
    parser.add_argument(
        "--max-depth", type=int, default=2, help="Maximum depth for crawling. Example: python -m vm.scan -t http://domain.com -a --max-depth 3"
    )
    parser.add_argument(
        "-db", "--dir-bruteforce", action="store_true", help="Perform directory bruteforce. Example: python -m vm.scan -t http://domain.com -db --wordlist wordlist.txt"
    )
    parser.add_argument(
        "--wordlist", help="Wordlist file for directory bruteforce. Example: python -m vm.scan -t http://domain.com -db --wordlist wordlist.txt"
    )

    args = parser.parse_args()

    # print(f"🌐 Arguments received: {args}")  # Debugging output

    # Determine the scans to perform
    vulnerabilities_to_scan = []
    if args.all:
        print("Performing a full scan for all vulnerabilities...")
        vulnerabilities_to_scan = ["XSS", "SQL Injection", "Open Ports", "Directory Bruteforce"]
    else:
        if args.xss:
            vulnerabilities_to_scan.append("XSS")
        if args.sql:
            vulnerabilities_to_scan.append("SQL Injection")
        if args.open_ports:
            vulnerabilities_to_scan.append("Open Ports")
        if args.dir_bruteforce:
            vulnerabilities_to_scan.append("Directory Bruteforce")
    
    custom_payloads = {
        "XSS": args.xss_payloads,
        "SQL Injection": args.sql_payloads
    }

    if vulnerabilities_to_scan:
        perform_scan(args.target, vulnerabilities_to_scan, custom_payloads, args.num_ports, args.max_depth, args.wordlist)
    else:
        print("❌ Please specify a scan type: --xss, --sql, --open-ports, --dir-bruteforce, or --all.")
        parser.print_help()

if __name__ == "__main__":
    main()