import socket
from urllib.parse import urlparse

def scan_open_ports(target, num_ports=1024):
    # Extract the domain name from the URL 
    parsed_url = urlparse(target)
    hostname = parsed_url.hostname

    if not hostname:
        print("❌ Invalid URL format: Unable to extract hostname.")
        return {"Open Ports": "Error"}

    print(f"Scanning {hostname} for Open Ports (first {num_ports} ports)...")
    print()
    open_ports = []
    try:
        for port in range(1, num_ports + 1):  # Scan up to the specified number of ports
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)  # Reduced timeout to 0.1 seconds
                if s.connect_ex((hostname, port)) == 0:
                    open_ports.append(port)
        if open_ports:
            print(f"⚠️  Open ports detected on {hostname}: {open_ports}")
            return {"Open Ports": open_ports}
        else:
            print(f"✅ No open ports detected on {hostname}.")
            return {"Open Ports": []}
    except socket.error as e:
        print(f"❌ Error scanning for Open Ports: {e}")
        return {"Open Ports": "Error"}
