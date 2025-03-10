# README.md

This repo contains a simple workflow to gather open-source intelligence (OSINT), perform network scans, conduct web enumeration, and run basic vulnerability checks against the fictional domain **wayneindustries.xyz**.

## What’s Included

`scan-local.go`: A Go script that automates the workflow by calling four open-source CLIs:
  1. [osintscan](https://github.com/method-security/osintscan/)
  2. [networkscan](https://github.com/method-security/networkscan/)
  3. [webscan](https://github.com/method-security/webscan/)
  4. [methodwebtest](https://github.com/method-security/methodwebtest/)

`results_local/`: A folder containing JSON and text files with scan results (OSINT data, open ports, web server probes, vulnerability tests, etc.).

## Prerequisites

1. macOS ARM64 Binaries: Download the macOS ARM64 tarballs for all four CLIs (osintscan, networkscan, webscan, methodwebtest) from their respective GitHub releases.  
2. System PATH Setup: Place the unzipped CLI binaries in a directory included in your `PATH`. For example:
```
mv osintscan networkscan webscan methodwebtest /usr/local/bin
chmod +x /usr/local/bin/osintscan /usr/local/bin/networkscan /usr/local/bin/webscan /usr/local/bin/methodwebtest
```
3. Go (optional): If you plan to modify or rebuild scan-local.go, install Go (1.18+).

## How to Run the Automated Scan
  1. Clone or Copy this repository into your working environment.
  2. Enter the directory containing scan-local.go.
  3. Build the Go script:
```
go build -o scan-local scan-local.go
```
  4. Execute the scan script:
```
./scan-local
```
You’ll see informational logs and references to generated files in results_local/.
Note: If you see “exec format error” on macOS, ensure you have the correct ARM64 versions of the CLIs.

## Reproducing the Results
The script targets wayneindustries.xyz. It gathers DNS info (including subdomains), then scans each discovered subdomain for open ports, performs web enumeration if ports 80/443 are open, and finally attempts a few common vulnerability checks. To replicate these steps manually:

  1. OSINT:
      ```
      osintscan dns records --domain wayneindustries.xyz
      osintscan dns subenum passive --domain wayneindustries.xyz -o json
      osintscan dns zonetransfer --domains wayneindustries.xyz
      osintscan shodan hostname --hostname wayneindustries.xyz --query "hostname:wayneindustries.xyz"
      ```
  2. Network Scan:
      ```
      networkscan port scan --target SUBDOMAIN --topports 1000 -o json
      ```
  3. Web Enumeration:
      ```
      webscan webserver probe --targets http://SUBDOMAIN
      webscan spider --targets http://SUBDOMAIN -o json
      webscan pagecapture html request --target http://SUBDOMAIN
      webscan pagecapture screenshot browser --target http://SUBDOMAIN
      ```
  4. Vulnerability Checks:
      ```
      methodwebtest general path traversal \
      --targets http://SUBDOMAIN \
      --paths "/etc/passwd,/.git/config" -o json

      methodwebtest general header misconfigured \
      --targets http://SUBDOMAIN \
      --event CORS -o json
      ```
Replace SUBDOMAIN with each discovered subdomain that has port 80 or 443 open.
