# Vulnerability Scanner

This tool scans for Cross-Site Scripting (XSS), SQL Injection, Open Ports, performs Directory and Subdomain Bruteforcing, Security Header Analysis, Secrets Detection and Report Generation.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/ankitsinghtd/VulnMorph.git
    cd VulnMorph
    ```

2. Install the dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

```sh
python -m vm.scan -t <target_url>

-h for help
```