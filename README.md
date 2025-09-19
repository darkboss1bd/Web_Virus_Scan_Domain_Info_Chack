# Web_Virus_Scan_Domain_Info_Chack
Website SCan &amp; Domain -Hosting info chack

# How to Use the DarkBoss1BD Scanner
```bash
First install the required packages:
pip install requests beautifulsoup4 python-whois dnspython pdfkit jinja2 ipwhois tldextract geoip2 python-nmap builtwith
```

```bash
# Ubuntu/Debian
sudo apt-get install wkhtmltopdf

# macOS
brew install wkhtmltopdf

# Windows: Download from https://wkhtmltopdf.org/downloads.html
```
```bash
Download GeoLite2 database (optional for geolocation):
# Download from https://dev.maxmind.com/geoip/geoip2/geolite2/
# Place GeoLite2-City.mmdb in the same directory as the script
```


```
Run the scanner:
```bash

# Comprehensive scan with JSON report
```bash
python Web_Virus_Scan_ Domain_Info_Chack.py https://example.com

```
# Comprehensive scan with HTML report
```bash
python Web_Virus_Scan_ Domain_Info_Chack.py https://example.com -f html

```
# Comprehensive scan with PDF report and email
```bash
python Web_Virus_Scan_ Domain_Info_Chack.py https://example.com -f pdf -e your_email@example.com
```
# Quick scan (fewer checks)
```bash
python Web_Virus_Scan_ Domain_Info_Chack.py https://example.com -q
```
# Verbose output
```bash
python Web_Virus_Scan_ Domain_Info_Chack.py https://example.com -v
```

# View all options
```bash
python Web_Virus_Scan_ Domain_Info_Chack.py
```

# Features of DarkBoss1BD Scanner

```bash
Domain Information (A to Z)
WHOIS Information: Registrar, creation date, expiration date, name servers

DNS Records: A, AAAA, MX, NS, TXT, CNAME, SOA records

IP Information: IP address, IP WHOIS, ASN details

Geolocation: Country, city, coordinates, timezone

TLD Analysis: Domain, suffix, subdomain extraction
```

# Hosting Information
```bash
Server Headers: Server type, powered-by information

Open Ports: Common ports scanning with service detection

Reverse DNS: Hostname and aliases

CDN Detection: Cloudflare, CloudFront, Akamai, etc.

Network Information: ASN, network range, country
```

# Technology Stack Detection
```bash
CMS Detection: WordPress, Joomla, Drupal, Magento, Shopify

JavaScript Frameworks: React, Angular, Vue, jQuery

Server Technologies: PHP, ASP.NET, Node.js, Python, Ruby

BuiltWith Analysis: Comprehensive technology profiling
```
# Security Scanning
```bash
SSL/TLS Certificate: Validity, expiration, issuer

Malicious Code: Patterns, scripts, iframes, eval functions

External Links: Suspicious domains, phishing links

Blacklist Status: Spamhaus, Barracuda, SORBS

File Upload Forms: Multipart forms detection

HTTP Headers: Security headers analysis

SQL Injection: Basic vulnerability testing

XSS Vulnerability: Reflected input testing
```

# Reporting Features
```bash
Multiple Formats: JSON, HTML, CSV, PDF

Email Reports: Automatic report delivery

Comprehensive Summary: Risk assessment, issue count

Detailed Findings: Evidence, examples, recommendations
```
# Report Structure
```bash
The scanner generates comprehensive reports with these sections:

Scan Information: Target, date, duration, version

Domain Information: Complete WHOIS and DNS details

Hosting Information: Server, ports, CDN, network

Technology Stack: CMS, frameworks, server technologies

Security Scan Results: All security checks with status

Summary: Risk level, total issues, recommendations
```

