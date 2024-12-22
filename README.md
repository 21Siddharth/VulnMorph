# Vulnerability Scanner

This tool scans for Cross-Site Scripting (XSS), SQL Injection, and Open Ports vulnerabilities.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/ankitsinghtd/VulnMorph.git
    cd vulnmorph
    ```

2. Install the dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

```sh
python scanner.py -t <target_url> [options]
-h for help
```

## Test Commands

### Scan for XSS
```sh
python scanner.py -t http://testphp.vulnweb.com -x
```

### Scan for SQL Injection
```sh
python scanner.py -t http://testphp.vulnweb.com -s
```

### Scan for Open Ports
```sh
python scanner.py -t http://testphp.vulnweb.com -op
```

### Scan for All Vulnerabilities
```sh
python scanner.py -t http://testphp.vulnweb.com -a
```

### Scan with Custom XSS Payloads
```sh
python scanner.py -t http://testphp.vulnweb.com -x --xss-payloads "<script>alert('XSS1')</script>" "<img src=x onerror=alert('XSS2')>"
```

### Scan with Custom SQL Injection Payloads
```sh
python scanner.py -t http://testphp.vulnweb.com -s --sql-payloads "' OR '1'='1" "' OR '1'='1' --"
```

### Scan Open Ports with Custom Number of Ports
```sh
python scanner.py -t http://testphp.vulnweb.com -op --num-ports 500
```