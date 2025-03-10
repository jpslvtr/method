# REPORT.md

## Introduction
This report details a point-in-time external assessment of a fictional Wayne Industries at the request of a prospective buyer. The objective is to identify internet-facing assets and quickly check for potential vulnerabilities that could impact negotiations or overall risk posture.

## Why This Matters
When assessing an organization for acquisition, it's important to understand its exposed attack surface. If the external infrastructure has obvious weaknesses (e.g., outdated services, open file repositories, or trivial DNS misconfigurations), attackers can use these weaknesses to gain unauthorized access or exfiltrate data. Such findings can:
- Inform negotiation (e.g., highlight remediation costs).
- Reveal immediate security enhancements needed post-acquisition.
- Validate or question assumptions about the target’s security maturity.

Weak external systems can harm the business. They might leak sensitive data, harm reputation, and require significant resources to fix. That’s why this preliminary scan is important.

## Methodology
Four open-source CLIs published by Method Security were used:
1. osintscan: Gathers publicly available information, such as DNS records or subdomains.
2. networkscan: Probes discovered hosts to see which network ports are open.
3. webscan: Crawls any identified web endpoints to reveal site structures and technology fingerprints.
4. methodwebtest: Performs basic vulnerability checks (e.g., path traversal or header misconfigurations).

The process:
1. Passive Recon (OSINT)
   - Enumerate DNS records and subdomains via open sources.
   - Attempt a DNS zone transfer to see if any misconfiguration reveals domain data.
   - Query Shodan to spot known open ports or services on public IPs.

2. Active Port Scanning
   - For each discovered subdomain, scan the top 1,000 most common ports to identify running services.
   - This step reveals services (HTTP on 80, HTTPS on 443, DNS on 53, SSH on 22, etc.).

3. Web Enumeration
   - For subdomains that expose HTTP/HTTPS: fetch basic pages, capture HTML content, take screenshots, and spider links to better understand what the server hosts.

4. Vulnerability Checks
   - Test common scenarios: path traversal attempts (like /.git/config access) and potentially misconfigured CORS headers.
   - Where relevant, note if the site uses authentication or has suspicious file exposures.

### Example CLI Usage
Below is a sample of testing `batcave-webpage-xss.resources.wayneindustries.xyz` for path traversal vulnerabilities:
```
methodwebtest general path traversal \
  --targets http://batcave-webpage-xss.resources.wayneindustries.xyz \
  --paths "/etc/passwd,/.git/config" \
  -o json
```
This command attempts to retrieve typical sensitive files. If it succeeds, the tool flags a possible path traversal issue.

## Key Findings
1. Subdomain Discovery
   - 24 Subdomains uncovered, including:
      ```
      batcave-apache-rce.resources.wayneindustries.xyz
      batcave-webpage-xss.resources.wayneindustries.xyz
      leaky.batcave-bucket.resources.wayneindustries.xyz
      batcave-cm-waf-misconfig.resources.wayneindustries.xyz
      ...
      ```
   - Some subdomains are placeholders; some run no obvious services. Others present multiple open ports, raising concerns.
   - Why It’s Relevant: Each subdomain potentially hosts unique apps or configurations. Attackers often target lesser-known subdomains because organizations may overlook them.

2. Open Ports & Running Services
   - Port scans found:
      - Port 53 (DNS) on several batcave-*.resources.* subdomains. This is unusual unless those hosts are intentionally DNS servers.
      - Port 80 (HTTP) on subdomains like batcave-apache-rce.resources.wayneindustries.xyz, batcave-webpage-basic-auth.resources.wayneindustries.xyz, etc.
      - Port 443 (HTTPS) on leaky.batcave-bucket.resources.wayneindustries.xyz (two IP addresses).
      - Port 22 (SSH) is open on batcave-cm-waf-misconfig.resources.wayneindustries.xyz.
   - Why It’s Relevant: Attackers could exploit unpatched or misconfigured services. For example, old Apache or SSH daemons with known CVEs can be compromised quickly.

3. Web Enumeration Insights
   - `batcave-webpage-basic-auth.resources.wayneindustries.xyz`: Returns a 401 HTTP status code without credentials, meaning BasicAuth is required. Saw no sign of HTTPS enforcement, suggesting credentials might be exposed in plain text if used incorrectly.
   - `leaky.batcave-bucket.resources.wayneindustries.xyz`: Name implies a storage “bucket.” The site responded on ports 80, 443, 8080, and 444. That many open ports can indicate multiple services or a misconfigured environment.
   - Why It’s Relevant:
      - BasicAuth can be easily sniffed if not served over TLS.
      - Publicly accessible “bucket” subdomains often inadvertently expose files, credentials, or sensitive logs.

4. Quick Vulnerability Checks
   - Path Traversal: Attempted to retrieve /etc/passwd or /.git/config. The basic scans failed to retrieve these, so no trivial path traversal was clear.
   - CORS Misconfigurations: Scanned for cross-origin header issues that could let unauthorized scripts read or modify site data. The checks didn’t report any major misconfigurations.
   - Why It’s Relevant: Path traversal vulnerabilities can lead to immediate file exposure. CORS issues might allow an attacker to capture user data from another origin. While not found, a more thorough or manual test could still reveal deeper issues.

## Risk & Relevance Summary
   1. Potential DNS Exposure: If port 53 is open unintentionally, it might enable partial zone transfers or recon.
   2. HTTP Without HTTPS: BasicAuth or any sensitive data in transit is at risk on plain HTTP.
   3. Multiple Ports on “Leaky” Buckets: The subdomain “leaky.batcave-bucket” suggests potential misconfigurations or leftover test services that an attacker could exploit.
   4. SSH Access: If default credentials or known vulnerabilities exist on port 22, attackers can gain a foothold.

## Recommendations
1. Restrict or Secure DNS: Close unnecessary DNS ports or confirm they are intentionally exposed. Ensure zone transfers require authentication.
2. Use HTTPS Everywhere: Especially for batcave-webpage-basic-auth.*, BasicAuth should only be used with TLS to avoid transmitting credentials in the clear.
3. Harden Buckets: Inspect leaky.batcave-bucket thoroughly. Validate whether file listings or test endpoints are publicly accessible. Remove or secure them if not required.
4. Improve Visibility: Regularly run these external scans (automated or integrated into a CI pipeline). Keep track of newly created subdomains.
5. Deeper Manual Testing: A dedicated penetration test (with manual reviews) might find additional issues. For potential SSH weaknesses, credentials or ephemeral tokens, conduct a more extensive check.

### Example Remediation Snippet
```
# If batcave-webpage-basic-auth site is truly needed:
sudo a2enmod ssl        # Enable SSL on Apache (if it's Apache)
sudo certbot --apache   # Obtain and install an HTTPS certificate
```
This is an example for enabling HTTPS.

## Next Steps
- Integrate these scans into your build pipeline or monthly audit routine.
- Discuss with Wayne Industries whether these subdomains are valid, which services are intentionally public, and how they secure them.