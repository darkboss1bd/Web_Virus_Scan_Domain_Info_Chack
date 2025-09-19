#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DarkBoss1BD - Advanced Website & Domain Information Scanner
Created by: Security Researcher
"""

import requests
import re
import os
import sys
import argparse
import hashlib
import json
import time
import csv
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import whois
import dns.resolver
import socket
import ssl
from datetime import datetime
import concurrent.futures
import tempfile
import pdfkit
from jinja2 import Template
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import shodan
import builtwith
import warnings
import ipwhois
import tldextract
import sslcert
import nmap
import subprocess
import geoip2.database

# Suppress warnings
warnings.filterwarnings('ignore')

class AdvancedDarkBoss1BDScanner:
    def __init__(self):
        self.banner = """
        ██████╗  █████╗ ██████╗ ██╗  ██╗██████╗  ██████╗ ███████╗██████╗ ██╗██████╗ ██████╗ 
        ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗██╔═══██╗██╔════╝██╔══██╗██║██╔══██╗██╔══██╗
        ██║  ██║███████║██████╔╝█████╔╝ ██║  ██║██║   ██║███████╗██████╔╝██║██████╔╝██║  ██║
        ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██║  ██║██║   ██║╚════██║██╔══██╗██║██╔══██╗██║  ██║
        ██████╔╝██║  ██║██║  ██║██║  ██╗██████╔╝╚██████╔╝███████║██║  ██║██║██║  ██║██████╔╝
        ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═════╝ 
        
        ██╗   ██╗██╗██████╗ ██╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
        ██║   ██║██║██╔══██╗██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
        ██║   ██║██║██████╔╝██║   ██║███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
        ╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
         ╚████╔╝ ██║██║  ██║╚██████╔╝███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
          ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
        
        Advanced Website & Domain Information Scanner
        Version: 4.0
        Developer: DarkBoss1BD
        """
        print(self.banner)
        
        # Initialize scan results
        self.scan_results = {
            'scan_info': {
                'target_url': '',
                'target_domain': '',
                'scan_date': '',
                'scan_duration': '',
                'scanner_version': '4.0'
            },
            'domain_info': {},
            'hosting_info': {},
            'security_scan': {},
            'technology_stack': {},
            'summary': {
                'total_checks': 0,
                'issues_found': 0,
                'risk_level': 'Low'
            }
        }
        
        # Known malicious patterns
        self.malicious_patterns = [
            r"eval\(.*\)", r"document\.write\(.*\)", r"fromCharCode\(.*\)",
            r"<script.*>.*</script>", r"<iframe.*>.*</iframe>", r"<embed.*>.*</embed>",
            r"window\.location=", r"\.php\?cmd=", r"base64_decode\(", r"gzinflate\(",
            r"shell_exec\(", r"passthru\(", r"exec\(", r"system\(", r"javascript:.*\(\)",
            r"onload=.*\(\)", r"onerror=.*\(\)", r"onclick=.*\(\)",
        ]
        
        # Create reports directory
        self.reports_dir = "darkboss1bd_reports"
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def get_domain_info(self, domain):
        """Get comprehensive domain information"""
        print(f"[+] Gathering comprehensive domain information for {domain}")
        
        domain_info = {}
        try:
            # WHOIS information
            w = whois.whois(domain)
            domain_info['whois'] = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
        except Exception as e:
            domain_info['whois'] = {'error': str(e)}
        
        try:
            # DNS information
            dns_info = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(r) for r in answers]
                except:
                    dns_info[record_type] = []
            domain_info['dns_records'] = dns_info
        except Exception as e:
            domain_info['dns_records'] = {'error': str(e)}
        
        try:
            # IP information
            ip = socket.gethostbyname(domain)
            domain_info['ip_address'] = ip
            
            # IP WHOIS information
            ipwhois_result = ipwhois.IPWhois(ip).lookup_rdap()
            domain_info['ip_whois'] = {
                'asn': ipwhois_result.get('asn'),
                'asn_description': ipwhois_result.get('asn_description'),
                'network': ipwhois_result.get('network'),
                'country': ipwhois_result.get('asn_country_code')
            }
        except Exception as e:
            domain_info['ip_address'] = 'Unknown'
            domain_info['ip_whois'] = {'error': str(e)}
        
        try:
            # Geolocation information
            with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
                response = reader.city(ip)
                domain_info['geolocation'] = {
                    'country': response.country.name,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'timezone': response.location.time_zone
                }
        except:
            domain_info['geolocation'] = {'info': 'GeoLite2 database not available'}
        
        try:
            # TLD extraction
            extracted = tldextract.extract(domain)
            domain_info['tld_info'] = {
                'domain': extracted.domain,
                'suffix': extracted.suffix,
                'subdomain': extracted.subdomain,
                'fqdn': extracted.fqdn
            }
        except Exception as e:
            domain_info['tld_info'] = {'error': str(e)}
        
        return domain_info
    
    def get_hosting_info(self, domain, ip):
        """Get comprehensive hosting information"""
        print(f"[+] Gathering comprehensive hosting information for {domain}")
        
        hosting_info = {}
        try:
            # Server information via HTTP headers
            response = requests.get(f"http://{domain}", timeout=10, headers={'User-Agent': 'DarkBoss1BD-Scanner/4.0'})
            headers = response.headers
            
            hosting_info['server_headers'] = {
                'server': headers.get('server', 'Unknown'),
                'x-powered-by': headers.get('x-powered-by', 'Unknown'),
                'x-aspnet-version': headers.get('x-aspnet-version', 'Unknown'),
                'x-aspnetmvc-version': headers.get('x-aspnetmvc-version', 'Unknown')
            }
        except Exception as e:
            hosting_info['server_headers'] = {'error': str(e)}
        
        try:
            # Port scanning (common ports)
            nm = nmap.PortScanner()
            nm.scan(ip, '21,22,23,25,53,80,110,143,443,465,587,993,995,2082,2083,2086,2087,2095,2096,3306,3389')
            
            open_ports = {}
            for port in nm[ip]['tcp']:
                if nm[ip]['tcp'][port]['state'] == 'open':
                    open_ports[port] = {
                        'service': nm[ip]['tcp'][port]['name'],
                        'product': nm[ip]['tcp'][port]['product'],
                        'version': nm[ip]['tcp'][port]['version']
                    }
            
            hosting_info['open_ports'] = open_ports
        except Exception as e:
            hosting_info['open_ports'] = {'error': str(e)}
        
        try:
            # Reverse IP lookup
            try:
                reverse_dns = socket.gethostbyaddr(ip)
                hosting_info['reverse_dns'] = {
                    'hostname': reverse_dns[0],
                    'aliases': reverse_dns[1],
                    'ip': reverse_dns[2]
                }
            except:
                hosting_info['reverse_dns'] = {'info': 'No reverse DNS record found'}
        except Exception as e:
            hosting_info['reverse_dns'] = {'error': str(e)}
        
        try:
            # CDN detection
            cdn_headers = ['server', 'x-cache', 'x-cache-hits', 'x-served-by', 'x-cdn']
            cdn_info = {}
            for header in cdn_headers:
                if header in response.headers:
                    cdn_info[header] = response.headers[header]
            
            # Known CDN patterns
            cdn_patterns = {
                'cloudflare': ['cloudflare', 'cf-ray'],
                'cloudfront': ['cloudfront', 'x-amz-cf-id'],
                'akamai': ['akamai', 'x-akamai'],
                'fastly': ['fastly', 'x-fastly'],
                'maxcdn': ['maxcdn', 'netdna-cache']
            }
            
            detected_cdn = 'Unknown'
            for cdn, patterns in cdn_patterns.items():
                if any(pattern in str(response.headers).lower() for pattern in patterns):
                    detected_cdn = cdn
                    break
            
            hosting_info['cdn'] = {
                'detected': detected_cdn,
                'headers': cdn_info
            }
        except Exception as e:
            hosting_info['cdn'] = {'error': str(e)}
        
        return hosting_info
    
    def get_technology_stack(self, url):
        """Detect technology stack"""
        print(f"[+] Detecting technology stack for {url}")
        
        tech_stack = {}
        try:
            # BuiltWith technology detection
            technologies = builtwith.parse(url)
            tech_stack['builtwith'] = technologies
        except Exception as e:
            tech_stack['builtwith'] = {'error': str(e)}
        
        try:
            # Wappalyzer-like detection
            response = requests.get(url, timeout=10, headers={'User-Agent': 'DarkBoss1BD-Scanner/4.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detect CMS
            cms_detection = {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
                'joomla': ['joomla', 'media/jui', 'templates/ja_'],
                'drupal': ['drupal', 'sites/all', 'misc/drupal'],
                'magento': ['magento', 'skin/frontend', 'media/css'],
                'shopify': ['shopify', 'cdn.shopify.com']
            }
            
            detected_cms = 'Unknown'
            for cms, patterns in cms_detection.items():
                if any(pattern in response.text.lower() for pattern in patterns):
                    detected_cms = cms
                    break
            
            tech_stack['cms'] = detected_cms
            
            # Detect JavaScript frameworks
            js_frameworks = {
                'react': ['react', 'react-dom'],
                'angular': ['angular', 'ng-'],
                'vue': ['vue', 'v-'],
                'jquery': ['jquery', 'jQuery']
            }
            
            detected_js = []
            for framework, patterns in js_frameworks.items():
                if any(pattern in response.text.lower() for pattern in patterns):
                    detected_js.append(framework)
            
            tech_stack['javascript_frameworks'] = detected_js
            
            # Detect server-side technologies
            server_tech = {
                'php': ['.php', 'php/', 'x-powered-by: php'],
                'asp.net': ['.aspx', 'asp.net', 'x-aspnet-version'],
                'node.js': ['node.js', 'express', 'x-powered-by: express'],
                'python': ['python', 'django', 'flask'],
                'ruby': ['ruby', 'rails', 'x-rails']
            }
            
            detected_server = []
            for tech, patterns in server_tech.items():
                if any(pattern in response.text.lower() for pattern in patterns):
                    detected_server.append(tech)
            
            tech_stack['server_technologies'] = detected_server
            
        except Exception as e:
            tech_stack['error'] = str(e)
        
        return tech_stack
    
    def security_scan(self, url, domain):
        """Perform security scanning"""
        print(f"[+] Performing security scan for {url}")
        
        security_results = {}
        
        # SSL/TLS check
        security_results['ssl_tls'] = self.check_ssl_certificate(url)
        
        # Malicious code scan
        security_results['malicious_code'] = self.scan_for_malicious_code(url)
        
        # External links check
        security_results['external_links'] = self.check_external_links(url)
        
        # Blacklist status
        security_results['blacklist_status'] = self.check_blacklist_status(domain)
        
        # File upload forms
        security_results['file_uploads'] = self.scan_file_uploads(url)
        
        # HTTP headers security
        security_results['headers_security'] = self.check_headers_security(url)
        
        # SQL injection test
        security_results['sql_injection'] = self.check_sql_injection(url)
        
        # XSS vulnerability test
        security_results['xss_vulnerability'] = self.check_xss_vulnerability(url)
        
        return security_results
    
    def check_ssl_certificate(self, url):
        """Check SSL certificate validity"""
        result = {'status': 'danger', 'message': 'SSL certificate check failed', 'details': ''}
        
        try:
            hostname = urlparse(url).hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry > 30:
                        result['status'] = 'safe'
                        result['message'] = f'SSL Certificate is valid for {days_until_expiry} more days'
                    elif days_until_expiry > 0:
                        result['status'] = 'warning'
                        result['message'] = f'SSL Certificate will expire in {days_until_expiry} days'
                    else:
                        result['message'] = 'SSL Certificate has expired!'
                    
                    result['details'] = f"Issuer: {cert['issuer']}, Expiry: {cert['notAfter']}"
            
        except Exception as e:
            result['details'] = str(e)
        
        return result
    
    def scan_for_malicious_code(self, url):
        """Scan website for malicious code patterns"""
        result = {'status': 'safe', 'message': 'No malicious code patterns detected', 'details': ''}
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'DarkBoss1BD-Scanner/4.0'})
            content = response.text
            
            found_patterns = []
            for pattern in self.malicious_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    found_patterns.append({
                        'pattern': pattern,
                        'count': len(matches),
                        'examples': matches[:3]
                    })
            
            if found_patterns:
                result['status'] = 'danger'
                result['message'] = f'Found {len(found_patterns)} malicious code patterns'
                result['details'] = json.dumps(found_patterns, indent=2)
            
        except Exception as e:
            result['status'] = 'warning'
            result['message'] = 'Error scanning for malicious code'
            result['details'] = str(e)
        
        return result
    
    def check_external_links(self, url):
        """Check for suspicious external links"""
        result = {'status': 'safe', 'message': 'No suspicious external links detected', 'details': ''}
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'DarkBoss1BD-Scanner/4.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            suspicious_links = []
            all_links = []
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http'):
                    parsed_url = urlparse(href)
                    domain = parsed_url.netloc
                    all_links.append(href)
                    
                    # Check for suspicious domains
                    suspicious_domains = ['free', 'hack', 'crack', 'nulled', 'warez', 'pirate']
                    if any(sd in domain.lower() for sd in suspicious_domains):
                        suspicious_links.append(href)
            
            if suspicious_links:
                result['status'] = 'danger'
                result['message'] = f'Found {len(suspicious_links)} suspicious external links'
                result['details'] = f"Suspicious links: {', '.join(suspicious_links[:5])}"
                if len(suspicious_links) > 5:
                    result['details'] += f" ... and {len(suspicious_links) - 5} more"
            
            result['details'] += f" | Total links found: {len(all_links)}"
            
        except Exception as e:
            result['status'] = 'warning'
            result['message'] = 'Error checking external links'
            result['details'] = str(e)
        
        return result
    
    def check_blacklist_status(self, domain):
        """Check if domain is blacklisted"""
        result = {'status': 'safe', 'message': 'Domain is not listed in major blacklists', 'details': ''}
        
        blacklists = [
            "zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
            "dnsbl.sorbs.net", "spam.dnsbl.sorbs.net"
        ]
        
        try:
            ip = socket.gethostbyname(domain)
            reversed_ip = ".".join(ip.split(".")[::-1])
            
            blacklisted_in = []
            for blacklist in blacklists:
                try:
                    query = f"{reversed_ip}.{blacklist}"
                    dns.resolver.resolve(query, "A")
                    blacklisted_in.append(blacklist)
                except:
                    pass
            
            if blacklisted_in:
                result['status'] = 'danger'
                result['message'] = f'Domain is listed in {len(blacklisted_in)} blacklists'
                result['details'] = f"Blacklists: {', '.join(blacklisted_in)}"
            
        except Exception as e:
            result['status'] = 'warning'
            result['message'] = 'Error checking blacklist status'
            result['details'] = str(e)
        
        return result
    
    def scan_file_uploads(self, url):
        """Check for suspicious file upload forms"""
        result = {'status': 'safe', 'message': 'No file upload forms detected', 'details': ''}
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'DarkBoss1BD-Scanner/4.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            upload_forms = []
            for form in soup.find_all('form'):
                if form.get('enctype') == 'multipart/form-data':
                    form_html = str(form)
                    upload_forms.append(form_html[:200] + "..." if len(form_html) > 200 else form_html)
            
            if upload_forms:
                result['status'] = 'warning'
                result['message'] = f'Found {len(upload_forms)} file upload forms'
                result['details'] = f"Forms: {json.dumps(upload_forms[:2], indent=2)}"
                if len(upload_forms) > 2:
                    result['details'] += f" ... and {len(upload_forms) - 2} more"
            
        except Exception as e:
            result['status'] = 'warning'
            result['message'] = 'Error scanning for file upload forms'
            result['details'] = str(e)
        
        return result
    
    def check_headers_security(self, url):
        """Check HTTP headers for security issues"""
        result = {'status': 'safe', 'message': 'HTTP headers are properly configured', 'details': ''}
        
        try:
            response = requests.get(url, timeout=10, headers={'User-Agent': 'DarkBoss1BD-Scanner/4.0'})
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Missing',
                'X-XSS-Protection': 'Missing',
                'X-Content-Type-Options': 'Missing',
                'Strict-Transport-Security': 'Missing',
                'Content-Security-Policy': 'Missing'
            }
            
            issues = []
            for header in security_headers:
                if header in headers:
                    security_headers[header] = 'Present'
                else:
                    issues.append(header)
            
            if issues:
                result['status'] = 'warning'
                result['message'] = f'Missing {len(issues)} security headers'
                result['details'] = f"Missing: {', '.join(issues)} | Present: {', '.join([h for h, v in security_headers.items() if v == 'Present'])}"
            else:
                result['details'] = "All security headers are present"
            
        except Exception as e:
            result['status'] = 'warning'
            result['message'] = 'Error checking HTTP headers'
            result['details'] = str(e)
        
        return result
    
    def check_sql_injection(self, url):
        """Check for potential SQL injection vulnerabilities"""
        result = {'status': 'safe', 'message': 'No obvious SQL injection vulnerabilities detected', 'details': ''}
        
        try:
            test_payloads = ["'", "\"", "' OR '1'='1", "' OR '1'='1' --", "'; DROP TABLE users; --"]
            vulnerable = False
            
            for payload in test_payloads:
                test_url = f"{url}{payload}" if "?" in url else f"{url}?id={payload}"
                response = requests.get(test_url, timeout=10)
                
                if "sql" in response.text.lower() or "syntax" in response.text.lower() or "mysql" in response.text.lower():
                    vulnerable = True
                    break
            
            if vulnerable:
                result['status'] = 'danger'
                result['message'] = 'Potential SQL injection vulnerability detected'
                result['details'] = 'Website responded with database error messages'
            
        except Exception as e:
            result['status'] = 'warning'
            result['message'] = 'Error testing for SQL injection'
            result['details'] = str(e)
        
        return result
    
    def check_xss_vulnerability(self, url):
        """Check for potential XSS vulnerabilities"""
        result = {'status': 'safe', 'message': 'No obvious XSS vulnerabilities detected', 'details': ''}
        
        try:
            test_payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "\"><script>alert('XSS')</script>"
            ]
            vulnerable = False
            
            for payload in test_payloads:
                test_url = f"{url}{payload}" if "?" in url else f"{url}?search={payload}"
                response = requests.get(test_url, timeout=10)
                
                if payload in response.text:
                    vulnerable = True
                    break
            
            if vulnerable:
                result['status'] = 'danger'
                result['message'] = 'Potential XSS vulnerability detected'
                result['details'] = 'Website reflected user input without proper sanitization'
            
        except Exception as e:
            result['status'] = 'warning'
            result['message'] = 'Error testing for XSS'
            result['details'] = str(e)
        
        return result
    
    def save_results(self, format_type='json'):
        """Save scan results in specified format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.reports_dir}/darkboss1bd_scan_report_{timestamp}"
        
        if format_type == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=4)
        
        elif format_type == 'html':
            filename += '.html'
            self.generate_html_report(filename)
        
        elif format_type == 'csv':
            filename += '.csv'
            self.generate_csv_report(filename)
        
        elif format_type == 'pdf':
            filename += '.pdf'
            self.generate_pdf_report(filename)
        
        print(f"[+] Report saved as: {filename}")
        return filename
    
    def generate_html_report(self, filename):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>DarkBoss1BD Comprehensive Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                .header { background-color: #2c3e50; color: white; padding: 30px; border-radius: 10px; }
                .section { background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .check { margin: 15px 0; padding: 15px; border-left: 5px solid #ddd; }
                .safe { border-color: #27ae60; background-color: #e8f5e9; }
                .warning { border-color: #f39c12; background-color: #fff3e0; }
                .danger { border-color: #e74c3c; background-color: #ffebee; }
                .summary { background-color: #34495e; color: white; padding: 20px; border-radius: 10px; }
                .info-table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                .info-table th, .info-table td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                .info-table th { background-color: #f2f2f2; }
                h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                h3 { color: #34495e; }
                pre { background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>DarkBoss1BD Comprehensive Scan Report</h1>
                <p><strong>Target URL:</strong> {{ scan_info.target_url }}</p>
                <p><strong>Target Domain:</strong> {{ scan_info.target_domain }}</p>
                <p><strong>Scan Date:</strong> {{ scan_info.scan_date }}</p>
                <p><strong>Scan Duration:</strong> {{ scan_info.scan_duration }} seconds</p>
                <p><strong>Scanner Version:</strong> {{ scan_info.scanner_version }}</p>
            </div>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Total Checks:</strong> {{ summary.total_checks }}</p>
                <p><strong>Issues Found:</strong> {{ summary.issues_found }}</p>
                <p><strong>Risk Level:</strong> <span style="color: {% if summary.risk_level == 'High' %}#e74c3c{% elif summary.risk_level == 'Medium' %}#f39c12{% else %}#27ae60{% endif %}">{{ summary.risk_level }}</span></p>
            </div>
            
            <!-- Domain Information Section -->
            <div class="section">
                <h2>Domain Information</h2>
                {% for category, info in domain_info.items() %}
                <h3>{{ category|upper }}</h3>
                <pre>{{ info|tojson(indent=2) }}</pre>
                {% endfor %}
            </div>
            
            <!-- Hosting Information Section -->
            <div class="section">
                <h2>Hosting Information</h2>
                {% for category, info in hosting_info.items() %}
                <h3>{{ category|upper }}</h3>
                <pre>{{ info|tojson(indent=2) }}</pre>
                {% endfor %}
            </div>
            
            <!-- Technology Stack Section -->
            <div class="section">
                <h2>Technology Stack</h2>
                {% for category, info in technology_stack.items() %}
                <h3>{{ category|upper }}</h3>
                <pre>{{ info|tojson(indent=2) }}</pre>
                {% endfor %}
            </div>
            
            <!-- Security Scan Results -->
            <div class="section">
                <h2>Security Scan Results</h2>
                {% for check_name, check_result in security_scan.items() %}
                <div class="check {{ check_result.status }}">
                    <h3>{{ check_name|title }}</h3>
                    <p><strong>Status:</strong> <span style="color: {% if check_result.status == 'safe' %}#27ae60{% elif check_result.status == 'warning' %}#f39c12{% else %}#e74c3c{% endif %}">{{ check_result.status|upper }}</span></p>
                    <p><strong>Message:</strong> {{ check_result.message }}</p>
                    {% if check_result.details %}
                    <p><strong>Details:</strong> {{ check_result.details }}</p>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            scan_info=self.scan_results['scan_info'],
            domain_info=self.scan_results['domain_info'],
            hosting_info=self.scan_results['hosting_info'],
            technology_stack=self.scan_results['technology_stack'],
            security_scan=self.scan_results['security_scan'],
            summary=self.scan_results['summary']
        )
        
        with open(filename, 'w') as f:
            f.write(html_content)
    
    def generate_csv_report(self, filename):
        """Generate CSV report"""
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['Category', 'Check', 'Status', 'Message', 'Details']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            # Add security scan results
            for check_name, check_result in self.scan_results['security_scan'].items():
                writer.writerow({
                    'Category': 'Security Scan',
                    'Check': check_name,
                    'Status': check_result['status'],
                    'Message': check_result['message'],
                    'Details': check_result.get('details', '')
                })
            
            # Add domain info
            for category, info in self.scan_results['domain_info'].items():
                writer.writerow({
                    'Category': 'Domain Information',
                    'Check': category,
                    'Status': 'Info',
                    'Message': 'Domain information retrieved',
                    'Details': json.dumps(info, indent=2)
                })
            
            # Add hosting info
            for category, info in self.scan_results['hosting_info'].items():
                writer.writerow({
                    'Category': 'Hosting Information',
                    'Check': category,
                    'Status': 'Info',
                    'Message': 'Hosting information retrieved',
                    'Details': json.dumps(info, indent=2)
                })
    
    def generate_pdf_report(self, filename):
        """Generate PDF report (requires wkhtmltopdf)"""
        try:
            # First generate HTML report
            html_filename = filename.replace('.pdf', '.html')
            self.generate_html_report(html_filename)
            
            # Convert to PDF
            pdfkit.from_file(html_filename, filename)
            os.remove(html_filename)  # Remove temporary HTML file
        except Exception as e:
            print(f"[!] PDF generation failed: {e}. Install wkhtmltopdf for PDF reports.")
    
    def send_email_report(self, recipient_email, report_file):
        """Send report via email (requires SMTP configuration)"""
        try:
            # SMTP configuration (update with your SMTP server details)
            smtp_server = "smtp.gmail.com"
            smtp_port = 587
            smtp_username = "your_email@gmail.com"
            smtp_password = "your_app_password"
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = smtp_username
            msg['To'] = recipient_email
            msg['Subject'] = f"DarkBoss1BD Scan Report for {self.scan_results['scan_info']['target_url']}"
            
            # Add body
            body = f"Scan completed on {self.scan_results['scan_info']['scan_date']}. Please find the report attached."
            msg.attach(MIMEText(body, 'plain'))
            
            # Add attachment
            with open(report_file, "rb") as f:
                attach = MIMEApplication(f.read(), _subtype="pdf")
                attach.add_header('Content-Disposition', 'attachment', filename=os.path.basename(report_file))
                msg.attach(attach)
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)
            server.quit()
            
            print(f"[+] Report sent to {recipient_email}")
        except Exception as e:
            print(f"[!] Email sending failed: {e}")
    
    def comprehensive_scan(self, url):
        """Run a comprehensive scan on the website"""
        print(f"\n[+] Starting comprehensive scan for {url}")
        print("="*80)
        
        start_time = time.time()
        
        # Parse URL to get domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not domain:
            print("[✗] Invalid URL provided")
            return
        
        # Initialize scan results
        self.scan_results['scan_info']['target_url'] = url
        self.scan_results['scan_info']['target_domain'] = domain
        self.scan_results['scan_info']['scan_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get IP address
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "Unknown"
        
        # Run all information gathering
        print("[+] Gathering domain information...")
        self.scan_results['domain_info'] = self.get_domain_info(domain)
        
        print("[+] Gathering hosting information...")
        self.scan_results['hosting_info'] = self.get_hosting_info(domain, ip)
        
        print("[+] Detecting technology stack...")
        self.scan_results['technology_stack'] = self.get_technology_stack(url)
        
        print("[+] Performing security scan...")
        self.scan_results['security_scan'] = self.security_scan(url, domain)
        
        # Calculate summary
        self.scan_results['summary']['total_checks'] = len(self.scan_results['security_scan'])
        self.scan_results['summary']['issues_found'] = sum(
            1 for result in self.scan_results['security_scan'].values() 
            if result['status'] in ['warning', 'danger']
        )
        
        # Calculate risk level
        danger_count = sum(1 for result in self.scan_results['security_scan'].values() if result['status'] == 'danger')
        warning_count = sum(1 for result in self.scan_results['security_scan'].values() if result['status'] == 'warning')
        
        if danger_count > 0:
            self.scan_results['summary']['risk_level'] = 'High'
        elif warning_count > 2:
            self.scan_results['summary']['risk_level'] = 'Medium'
        elif warning_count > 0:
            self.scan_results['summary']['risk_level'] = 'Low'
        else:
            self.scan_results['summary']['risk_level'] = 'Very Low'
        
        # Calculate scan duration
        end_time = time.time()
        scan_duration = end_time - start_time
        self.scan_results['scan_info']['scan_duration'] = f"{scan_duration:.2f}"
        
        # Generate summary
        print("\n" + "="*80)
        print("COMPREHENSIVE SCAN SUMMARY:")
        print("="*80)
        
        print(f"Target URL: {url}")
        print(f"Target Domain: {domain}")
        print(f"IP Address: {ip}")
        print(f"Scan Date: {self.scan_results['scan_info']['scan_date']}")
        print(f"Scan Duration: {scan_duration:.2f} seconds")
        print(f"Total Security Checks: {self.scan_results['summary']['total_checks']}")
        print(f"Security Issues Found: {self.scan_results['summary']['issues_found']}")
        print(f"Risk Level: {self.scan_results['summary']['risk_level']}")
        
        # Display domain information summary
        print("\n" + "-"*40)
        print("DOMAIN INFORMATION SUMMARY:")
        print("-"*40)
        if 'whois' in self.scan_results['domain_info']:
            whois_info = self.scan_results['domain_info']['whois']
            print(f"Registrar: {whois_info.get('registrar', 'Unknown')}")
            print(f"Creation Date: {whois_info.get('creation_date', 'Unknown')}")
            print(f"Expiration Date: {whois_info.get('expiration_date', 'Unknown')}")
        
        # Display hosting information summary
        print("\n" + "-"*40)
        print("HOSTING INFORMATION SUMMARY:")
        print("-"*40)
        if 'server_headers' in self.scan_results['hosting_info']:
            server_info = self.scan_results['hosting_info']['server_headers']
            print(f"Server: {server_info.get('server', 'Unknown')}")
            print(f"Powered By: {server_info.get('x-powered-by', 'Unknown')}")
        
        if 'open_ports' in self.scan_results['hosting_info']:
            open_ports = self.scan_results['hosting_info']['open_ports']
            if not isinstance(open_ports, dict) or 'error' not in open_ports:
                print(f"Open Ports: {len(open_ports)}")
        
        # Display technology stack summary
        print("\n" + "-"*40)
        print("TECHNOLOGY STACK SUMMARY:")
        print("-"*40)
        if 'cms' in self.scan_results['technology_stack']:
            print(f"CMS: {self.scan_results['technology_stack']['cms']}")
        if 'javascript_frameworks' in self.scan_results['technology_stack']:
            print(f"JS Frameworks: {', '.join(self.scan_results['technology_stack']['javascript_frameworks'])}")
        if 'server_technologies' in self.scan_results['technology_stack']:
            print(f"Server Technologies: {', '.join(self.scan_results['technology_stack']['server_technologies'])}")
        
        # Display security issues
        print("\n" + "-"*40)
        print("SECURITY ISSUES SUMMARY:")
        print("-"*40)
        for check_name, check_result in self.scan_results['security_scan'].items():
            if check_result['status'] in ['warning', 'danger']:
                print(f"[{check_result['status'].upper()}] {check_name}: {check_result['message']}")
        
        if self.scan_results['summary']['issues_found'] == 0:
            print("\n[✓] No security issues detected. Website appears clean.")
        else:
            print(f"\n[!] {self.scan_results['summary']['issues_found']} potential security issues detected.")
            print("    It is recommended to investigate further.")
        
        print("="*80)
        
        return self.scan_results

def main():
    parser = argparse.ArgumentParser(description="DarkBoss1BD - Advanced Website & Domain Information Scanner")
    parser.add_argument("url", help="URL of the website to scan")
    parser.add_argument("-f", "--format", choices=['json', 'html', 'csv', 'pdf'], default='json',
                       help="Output format for the report (default: json)")
    parser.add_argument("-e", "--email", help="Email address to send the report to")
    parser.add_argument("-q", "--quick", action="store_true", help="Run quick scan (fewer checks)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    scanner = AdvancedDarkBoss1BDScanner()
    
    # Run comprehensive scan
    results = scanner.comprehensive_scan(args.url)
    
    # Save report
    report_file = scanner.save_results(args.format)
    
    # Send email if requested
    if args.email:
        if args.format != 'pdf':
            # Convert to PDF for email attachment
            pdf_report = report_file.replace(f'.{args.format}', '.pdf')
            scanner.generate_pdf_report(pdf_report)
            scanner.send_email_report(args.email, pdf_report)
            os.remove(pdf_report)  # Clean up temporary PDF
        else:
            scanner.send_email_report(args.email, report_file)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python darkboss1bd_advanced.py <url> [options]")
        print("Options:")
        print("  -f, --format FORMAT   Output format: json, html, csv, pdf (default: json)")
        print("  -e, --email EMAIL     Email address to send the report to")
        print("  -q, --quick           Run quick scan (fewer checks)")
        print("  -v, --verbose         Verbose output")
        sys.exit(1)
    
    main()
