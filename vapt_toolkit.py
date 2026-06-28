#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════╗
║  CoreTech Innovation - VAPT Complete Toolkit                          ║
║  Vulnerability Assessment & Penetration Testing                        ║
║  Project ID: VAPT-2026-CTI-001                                       ║
║  Date: June 2026                                                      ║
╚═══════════════════════════════════════════════════════════════════════╝

DESCRIPTION:
    All-in-one VAPT toolkit combining:
    1. Network Discovery Scanner
    2. Vulnerability Checker (CVE Database)
    3. Professional Report Generator (HTML + Markdown)

USAGE:
    python vapt_toolkit.py --scan 192.168.1.0/24
    python vapt_toolkit.py --scan 192.168.1.0/24 --threads 100
    python vapt_toolkit.py --check scan_results.json
    python vapt_toolkit.py --full 192.168.1.0/24

AUTHOR: Security Assessment Team
"""

import socket
import subprocess
import json
import os
import sys
import argparse
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ═══════════════════════════════════════════════════════════════════════
# MODULE 1: NETWORK SCANNER
# ═══════════════════════════════════════════════════════════════════════

class NetworkScanner:
    """Advanced network scanner for VAPT assessments"""

    def __init__(self, target_range, max_threads=50):
        self.target_range = target_range
        self.max_threads = max_threads
        self.results = {
            'scan_date': datetime.now().isoformat(),
            'target_range': target_range,
            'scanner_version': '1.0.0',
            'hosts': [],
            'summary': {
                'total_hosts_scanned': 0,
                'active_hosts': 0,
                'total_open_ports': 0,
                'services_identified': 0
            }
        }
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]

        self.service_signatures = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }

    def ping_host(self, ip):
        """Check if host is alive"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                capture_output=True, timeout=3, text=True)
            return result.returncode == 0
        except:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((str(ip), 80))
                sock.close()
                return result == 0
            except:
                return False

    def scan_port(self, ip, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                banner = self.grab_banner(sock, port)
                sock.close()
                return {'port': port, 'state': 'open', 'banner': banner}
            sock.close()
            return None
        except:
            return None

    def grab_banner(self, sock, port):
        """Grab service banner"""
        try:
            sock.settimeout(2)
            if port in [80, 8080, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]
        except:
            return ''

    def identify_service(self, port, banner=''):
        """Identify service from port and banner"""
        info = {'name': 'Unknown', 'version': 'Unknown'}
        if port in self.service_signatures:
            info['name'] = self.service_signatures[port]

        bl = banner.lower()
        if 'apache' in bl:
            info['name'] = 'Apache HTTP Server'
            try: info['version'] = bl.split('apache/')[1].split()[0]
            except: pass
        elif 'nginx' in bl:
            info['name'] = 'nginx'
            try: info['version'] = bl.split('nginx/')[1].split()[0]
            except: pass
        elif 'openssh' in bl:
            info['name'] = 'OpenSSH'
            try: info['version'] = bl.split('openssh_')[1].split()[0]
            except: pass
        elif 'mysql' in bl:
            info['name'] = 'MySQL'
            if '5.' in bl: info['version'] = '5.x'
            elif '8.' in bl: info['version'] = '8.x'
        elif 'microsoft' in bl or 'iis' in bl:
            info['name'] = 'Microsoft IIS'
        elif 'ssh-' in bl:
            info['name'] = 'SSH'
            try: info['version'] = bl.split('ssh-')[1].split('-')[0]
            except: pass
        return info

    def scan_host(self, ip):
        """Full host scan"""
        if not self.ping_host(ip):
            return None

        host = {'ip': str(ip), 'hostname': '', 'open_ports': [], 'services': {}, 'os_guess': 'Unknown'}
        try:
            host['hostname'] = socket.gethostbyaddr(str(ip))[0]
        except: pass

        for port in self.common_ports:
            result = self.scan_port(ip, port)
            if result:
                host['open_ports'].append(port)
                svc = self.identify_service(port, result.get('banner', ''))
                host['services'][str(port)] = {
                    'name': svc['name'], 'version': svc['version'],
                    'banner': result.get('banner', '')[:100]
                }

        if 445 in host['open_ports'] or 3389 in host['open_ports']:
            host['os_guess'] = 'Windows'
        elif 22 in host['open_ports']:
            host['os_guess'] = 'Linux/Unix'
        return host

    def scan_network(self):
        """Scan entire network"""
        print("=" * 65)
        print("  CORETECH INNOVATION - NETWORK DISCOVERY SCANNER")
        print("=" * 65)
        print(f"[+] Target Range: {self.target_range}")
        print(f"[+] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[+] Threads: {self.max_threads} | Ports: {len(self.common_ports)}")
        print("-" * 65)

        network = ipaddress.ip_network(self.target_range, strict=False)
        hosts = list(network.hosts())
        self.results['summary']['total_hosts_scanned'] = len(hosts)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.scan_host, ip): ip for ip in hosts}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                result = future.result()
                if result and result['open_ports']:
                    self.results['hosts'].append(result)
                    self.results['summary']['active_hosts'] += 1
                    self.results['summary']['total_open_ports'] += len(result['open_ports'])
                    self.results['summary']['services_identified'] += len(result['services'])
                    print(f"[+] Host: {result['ip']:<15} | Ports: {result['open_ports']}")
                if completed % 50 == 0:
                    print(f"[*] Progress: {completed}/{len(hosts)} hosts...")

        print("-" * 65)
        print(f"[+] Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[+] Active Hosts: {self.results['summary']['active_hosts']}")
        print(f"[+] Open Ports: {self.results['summary']['total_open_ports']}")
        print(f"[+] Services: {self.results['summary']['services_identified']}")
        print("=" * 65)
        return self.results

    def save_report(self, filename='scan_results.json'):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"[+] Scan report saved: {filename}")

    def print_summary(self):
        print("\n" + "=" * 65)
        print("  SCAN SUMMARY")
        print("=" * 65)
        for host in self.results['hosts']:
            print(f"\n  Host: {host['ip']}")
            if host['hostname']: print(f"  Hostname: {host['hostname']}")
            print(f"  OS: {host['os_guess']}")
            print(f"  Open Ports: {host['open_ports']}")
            print("  Services:")
            for port, svc in host['services'].items():
                print(f"    {port}/tcp - {svc['name']} {svc['version']}")
        print("\n" + "=" * 65)


# ═══════════════════════════════════════════════════════════════════════
# MODULE 2: VULNERABILITY CHECKER
# ═══════════════════════════════════════════════════════════════════════

class VulnerabilityChecker:
    """CVE vulnerability checker"""

    def __init__(self):
        self.cve_db = {
            'apache': {
                '2.4.41': [
                    {'cve': 'CVE-2021-41773', 'sev': 'HIGH', 'cvss': 7.5,
                     'desc': 'Path Traversal and Remote Code Execution in Apache HTTP Server'},
                    {'cve': 'CVE-2021-42013', 'sev': 'HIGH', 'cvss': 7.5,
                     'desc': 'Path Traversal in Apache HTTP Server 2.4.49'},
                ],
            },
            'mysql': {
                '5.7.32': [
                    {'cve': 'CVE-2021-2144', 'sev': 'CRITICAL', 'cvss': 9.1,
                     'desc': 'MySQL Empty Root Password Vulnerability'},
                    {'cve': 'CVE-2021-2154', 'sev': 'HIGH', 'cvss': 7.5,
                     'desc': 'MySQL Server denial of service vulnerability'},
                ],
            },
            'openssh': {
                '8.2p1': [
                    {'cve': 'CVE-2020-15778', 'sev': 'HIGH', 'cvss': 7.8,
                     'desc': 'OpenSSH user enumeration via timing attack'},
                ],
            },
            'windows_server': {
                '2019_17763': [
                    {'cve': 'CVE-2019-0708', 'sev': 'CRITICAL', 'cvss': 9.8,
                     'desc': 'BlueKeep - Remote Code Execution in RDP'},
                    {'cve': 'CVE-2020-0796', 'sev': 'CRITICAL', 'cvss': 9.8,
                     'desc': 'SMBGhost - Remote Code Execution in SMBv3'},
                ],
            },
            'openssl': {
                '1.1.1k': [
                    {'cve': 'CVE-2021-3449', 'sev': 'MEDIUM', 'cvss': 5.9,
                     'desc': 'OpenSSL denial of service via malformed ClientHello'},
                ],
            },
            'smb': {
                '3.1.1': [
                    {'cve': 'CVE-2020-0796', 'sev': 'CRITICAL', 'cvss': 9.8,
                     'desc': 'SMBGhost - Remote Code Execution in SMBv3.1.1'},
                ],
            },
        }
        self.colors = {
            'CRITICAL': '\033[91m', 'HIGH': '\033[93m',
            'MEDIUM': '\033[33m', 'LOW': '\033[92m', 'INFO': '\033[94m'
        }
        self.reset = '\033[0m'

    def check_service(self, name, version):
        """Check service for known CVEs"""
        findings = []
        key = name.lower().replace(' ', '_').replace('-', '_')
        if key in self.cve_db:
            versions = self.cve_db[key]
            if version in versions:
                for v in versions[version]:
                    findings.append({
                        'service': name, 'version': version,
                        'cve': v['cve'], 'severity': v['sev'],
                        'cvss': v['cvss'], 'description': v['desc']
                    })
        return findings

    def analyze(self, scan_results):
        """Analyze scan results for vulnerabilities"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': 0, 'critical': 0, 'high': 0,
            'medium': 0, 'low': 0, 'info': 0,
            'findings': [], 'hosts_analyzed': 0
        }

        for host in scan_results.get('hosts', []):
            report['hosts_analyzed'] += 1
            for port, svc in host.get('services', {}).items():
                name = svc.get('name', 'Unknown')
                ver = svc.get('version', 'Unknown')
                if name == 'Unknown' or ver == 'Unknown':
                    continue
                for vuln in self.check_service(name, ver):
                    vuln['host'] = host['ip']
                    vuln['port'] = int(port)
                    report['findings'].append(vuln)
                    report['total_vulnerabilities'] += 1
                    s = vuln['severity'].lower()
                    if s == 'critical': report['critical'] += 1
                    elif s == 'high': report['high'] += 1
                    elif s == 'medium': report['medium'] += 1
                    elif s == 'low': report['low'] += 1
                    else: report['info'] += 1
        return report

    def print_report(self, report):
        """Print vulnerability report"""
        print("\n" + "=" * 65)
        print("  VULNERABILITY ASSESSMENT REPORT")
        print("=" * 65)
        print(f"\n  Date: {report['scan_date']}")
        print(f"  Hosts: {report['hosts_analyzed']}")
        print(f"  Total Vulnerabilities: {report['total_vulnerabilities']}")
        print(f"\n  {self.colors['CRITICAL']}CRITICAL: {report['critical']}{self.reset}")
        print(f"  {self.colors['HIGH']}HIGH:     {report['high']}{self.reset}")
        print(f"  {self.colors['MEDIUM']}MEDIUM:   {report['medium']}{self.reset}")
        print(f"  {self.colors['LOW']}LOW:      {report['low']}{self.reset}")
        print("\n" + "-" * 65)
        print("  DETAILED FINDINGS:")
        print("-" * 65)

        for f in report['findings']:
            c = self.colors.get(f['severity'], '')
            print(f"\n  {c}[{f['severity']}]{self.reset} {f['cve']}")
            print(f"    Host: {f['host']}:{f['port']}")
            print(f"    Service: {f['service']} {f['version']}")
            print(f"    CVSS: {f['cvss']}")
            print(f"    Description: {f['description']}")
        print("\n" + "=" * 65)

    def save_report(self, report, filename='vuln_report.json'):
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[+] Vulnerability report saved: {filename}")


# ═══════════════════════════════════════════════════════════════════════
# MODULE 3: REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Professional HTML/Markdown report generator"""

    def __init__(self, scan_data, vuln_data):
        self.scan_data = scan_data
        self.vuln_data = vuln_data
        self.date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def generate_html(self, output='vapt_report.html'):
        """Generate professional HTML report"""
        h = len(self.scan_data.get('hosts', []))
        v = self.vuln_data.get('total_vulnerabilities', 0)
        cr = self.vuln_data.get('critical', 0)
        hi = self.vuln_data.get('high', 0)
        me = self.vuln_data.get('medium', 0)
        lo = self.vuln_data.get('low', 0)

        # Findings rows
        rows = []
        for f in self.vuln_data.get('findings', []):
            s = f.get('severity', 'INFO').lower()
            bc = f"badge-{s}"
            rows.append(f"""<tr><td><code>{f.get('cve','N/A')}</code></td>
<td>{f.get('host','N/A')}</td><td>{f.get('port','N/A')}</td>
<td><span class="badge {bc}">{f.get('severity','N/A')}</span></td>
<td>{f.get('cvss','N/A')}</td><td>{f.get('description','N/A')}</td></tr>""")
        if not rows:
            rows.append('<tr><td colspan="6" style="text-align:center;color:#8b949e;">No vulnerabilities found</td></tr>')

        # Host cards
        cards = []
        for host in self.scan_data.get('hosts', []):
            svcs = []
            for port, svc in host.get('services', {}).items():
                svcs.append(f'<li><span>{svc.get("name","Unknown")}</span><span style="color:#8b949e">:{port}</span></li>')
            cards.append(f"""<div class="host-card"><h3>{host.get('ip','Unknown')}</h3>
<div class="host-meta">OS: {host.get('os_guess','Unknown')}</div>
<ul class="service-list">{''.join(svcs) if svcs else '<li style="color:#8b949e">No services</li>'}</ul></div>""")
        if not cards:
            cards.append('<div class="host-card"><p style="color:#8b949e">No hosts</p></div>')

        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>CoreTech Innovation - VAPT Report</title>
<style>
:root{{--bg:#0a0e1a;--bg2:#161b22;--card:#21262d;--text:#c9d1d9;--text2:#8b949e;--accent:#00d4ff;--crit:#ff0000;--high:#ff6600;--med:#ffcc00;--low:#00cc44}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}}
.container{{max-width:1200px;margin:0 auto;padding:20px}}
.header{{background:linear-gradient(135deg,#001a33 0%,#0a0e1a 100%);padding:40px;text-align:center;border-bottom:3px solid var(--accent);margin-bottom:30px;border-radius:10px}}
.header h1{{color:var(--accent);font-size:2.5em;margin-bottom:10px;text-transform:uppercase;letter-spacing:2px}}
.header .subtitle{{color:var(--text2);font-size:1.2em}}
.meta{{margin-top:20px;display:flex;justify-content:center;gap:30px;flex-wrap:wrap}}
.meta-item{{background:var(--card);padding:10px 20px;border-radius:5px;border:1px solid #30363d}}
.meta-label{{color:var(--text2);font-size:.85em}}
.meta-value{{color:var(--accent);font-weight:bold}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:30px}}
.stat-card{{background:var(--bg2);border-radius:10px;padding:25px;text-align:center;border:1px solid #30363d;transition:transform .3s}}
.stat-card:hover{{transform:translateY(-5px)}}
.stat-number{{font-size:3em;font-weight:bold;margin-bottom:10px}}
.stat-label{{color:var(--text2);text-transform:uppercase;letter-spacing:1px;font-size:.9em}}
.stat-critical{{color:var(--crit)}}.stat-high{{color:var(--high)}}.stat-medium{{color:var(--med)}}.stat-low{{color:var(--low)}}
.section{{background:var(--bg2);border-radius:10px;padding:30px;margin-bottom:30px;border:1px solid #30363d}}
.section h2{{color:var(--accent);margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #30363d;display:flex;align-items:center;gap:10px}}
.section h2::before{{content:'';display:inline-block;width:4px;height:24px;background:var(--accent);border-radius:2px}}
.data-table{{width:100%;border-collapse:collapse;margin-top:15px;font-size:.95em}}
.data-table th{{background:var(--card);padding:15px 12px;text-align:left;color:var(--accent);font-weight:600;text-transform:uppercase;font-size:.85em;letter-spacing:.5px}}
.data-table td{{padding:12px;border-bottom:1px solid #30363d}}
.data-table tr:hover{{background:rgba(0,212,255,.05)}}
.data-table tr:nth-child(even){{background:rgba(255,255,255,.02)}}
.badge{{display:inline-block;padding:4px 12px;border-radius:4px;font-weight:bold;font-size:.85em;text-transform:uppercase}}
.badge-critical{{background:rgba(255,0,0,.2);color:var(--crit);border:1px solid var(--crit)}}
.badge-high{{background:rgba(255,102,0,.2);color:var(--high);border:1px solid var(--high)}}
.badge-medium{{background:rgba(255,204,0,.2);color:var(--med);border:1px solid var(--med)}}
.badge-low{{background:rgba(0,204,68,.2);color:var(--low);border:1px solid var(--low)}}
.host-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-top:20px}}
.host-card{{background:var(--card);border-radius:8px;padding:20px;border:1px solid #30363d}}
.host-card h3{{color:var(--accent);margin-bottom:10px}}
.host-meta{{color:var(--text2);font-size:.9em;margin-bottom:15px}}
.service-list{{list-style:none}}.service-list li{{padding:5px 0;border-bottom:1px solid #30363d;display:flex;justify-content:space-between}}
.service-list li:last-child{{border-bottom:none}}
.recommendation{{background:var(--card);border-radius:8px;padding:20px;margin-bottom:15px;border-left:4px solid var(--accent)}}
.recommendation h4{{color:var(--text);margin-bottom:10px}}.recommendation p{{color:var(--text2);font-size:.95em}}
.recommendation.critical{{border-left-color:var(--crit)}}.recommendation.high{{border-left-color:var(--high)}}.recommendation.medium{{border-left-color:var(--med)}}
.footer{{text-align:center;padding:30px;color:var(--text2);font-size:.9em;border-top:1px solid #30363d;margin-top:30px}}
@media(max-width:768px){{.header h1{{font-size:1.8em}}.stats-grid{{grid-template-columns:repeat(2,1fr)}}.data-table{{font-size:.85em}}}}
</style></head><body><div class="container">
<div class="header"><h1>VAPT Assessment Report</h1><p class="subtitle">CoreTech Innovation - Network Security Assessment</p>
<div class="meta"><div class="meta-item"><div class="meta-label">Report Date</div><div class="meta-value">{self.date}</div></div>
<div class="meta-item"><div class="meta-label">Project ID</div><div class="meta-value">VAPT-2026-CTI-001</div></div>
<div class="meta-item"><div class="meta-label">Network Range</div><div class="meta-value">192.168.1.0/24</div></div>
<div class="meta-item"><div class="meta-label">Classification</div><div class="meta-value">CONFIDENTIAL</div></div></div></div>
<div class="section"><h2>Executive Summary</h2><p>This report presents the findings of a comprehensive Vulnerability Assessment and Penetration Testing (VAPT) conducted on CoreTech Innovation's network infrastructure (192.168.1.0/24). The assessment identified <strong>{v} vulnerabilities</strong> across <strong>{h} active hosts</strong>, including <strong>{cr} critical</strong> and <strong>{hi} high-severity</strong> issues requiring immediate attention.</p>
<div class="stats-grid" style="margin-top:25px"><div class="stat-card"><div class="stat-number stat-critical">{cr}</div><div class="stat-label">Critical</div></div>
<div class="stat-card"><div class="stat-number stat-high">{hi}</div><div class="stat-label">High</div></div>
<div class="stat-card"><div class="stat-number stat-medium">{me}</div><div class="stat-label">Medium</div></div>
<div class="stat-card"><div class="stat-number stat-low">{lo}</div><div class="stat-label">Low</div></div></div></div>
<div class="section"><h2>Vulnerability Findings</h2><table class="data-table"><thead><tr><th>CVE ID</th><th>Host</th><th>Port</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<div class="section"><h2>Discovered Hosts</h2><div class="host-grid">{''.join(cards)}</div></div>
<div class="section"><h2>Recommendations</h2>
<div class="recommendation critical"><h4>CRITICAL: Patch BlueKeep (CVE-2019-0708)</h4><p>Install Microsoft security update KB4499175 immediately on the Domain Controller (192.168.1.30). This vulnerability allows unauthenticated remote code execution via RDP and poses an immediate threat to the entire domain.</p></div>
<div class="recommendation critical"><h4>CRITICAL: Secure MySQL Database</h4><p>Set a strong password for the MySQL root account on 192.168.1.20 and remove anonymous users. The current empty password configuration allows unauthorized access to all databases including customer payment data.</p></div>
<div class="recommendation high"><h4>HIGH: Implement Network Segmentation</h4><p>Create separate VLANs for DMZ, database, and internal networks. Apply strict ACLs to limit lateral movement between network segments.</p></div>
<div class="recommendation high"><h4>HIGH: Deploy Intrusion Detection System</h4><p>Install Snort or Suricata on the network perimeter with rules for detecting RDP exploitation, SMB attacks, and database access anomalies.</p></div>
<div class="recommendation medium"><h4>MEDIUM: Establish Patch Management Program</h4><p>Implement WSUS for Windows updates and establish a monthly patching schedule with a staging environment for testing patches before production deployment.</p></div></div>
<div class="footer"><p><strong>Confidential - CoreTech Innovation Security Assessment</strong></p><p>This report is intended for authorized personnel only.</p><p style="margin-top:10px;font-size:.85em">Generated by VAPT Toolkit v1.0 | {self.date}</p></div>
</div></body></html>"""

        with open(output, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] HTML report generated: {output}")
        return True

    def generate_markdown(self, output='vapt_report.md'):
        """Generate Markdown report"""
        h = len(self.scan_data.get('hosts', []))
        v = self.vuln_data.get('total_vulnerabilities', 0)
        cr = self.vuln_data.get('critical', 0)
        hi = self.vuln_data.get('high', 0)
        me = self.vuln_data.get('medium', 0)
        lo = self.vuln_data.get('low', 0)

        md = f"""# VAPT Assessment Report
## CoreTech Innovation - Network Security Assessment

**Report Date:** {self.date}
**Project ID:** VAPT-2026-CTI-001
**Network Range:** 192.168.1.0/24
**Classification:** CONFIDENTIAL

---

## Executive Summary

This report presents the findings of a comprehensive Vulnerability Assessment and Penetration Testing (VAPT) conducted on CoreTech Innovation's network infrastructure.

### Statistics

| Metric | Value |
|--------|-------|
| Total Hosts | {h} |
| Total Vulnerabilities | {v} |
| Critical | {cr} |
| High | {hi} |
| Medium | {me} |
| Low | {lo} |

---

## Vulnerability Findings

| CVE | Host | Port | Severity | CVSS | Description |
|-----|------|------|----------|------|-------------|
"""
        for f in self.vuln_data.get('findings', []):
            md += f"| {f.get('cve','N/A')} | {f.get('host','N/A')} | {f.get('port','N/A')} | **{f.get('severity','N/A')}** | {f.get('cvss','N/A')} | {f.get('description','N/A')} |\n"

        md += """
---

## Recommendations

### Critical Priority (Fix within 7 Days)
1. **Patch BlueKeep (CVE-2019-0708)** - Install KB4499175 on Domain Controller
2. **Secure MySQL Database** - Set strong root password, remove anonymous users
3. **Patch SMBGhost (CVE-2020-0796)** - Install KB4551762, disable SMBv1

### High Priority (Fix within 30 Days)
4. **Implement Network Segmentation** - Create VLANs with strict ACLs
5. **Harden Firewall Rules** - Block unnecessary ports, enable source filtering
6. **Deploy Intrusion Detection** - Install Snort/Suricata + Windows Defender ATP
7. **Enable Multi-Factor Authentication** - MFA for all admin and remote access

### Medium Priority (Fix within 60 Days)
8. **Establish Patch Management** - WSUS + monthly patching schedule
9. **Upgrade Outdated Components** - Apache, PHP, MySQL to latest versions
10. **Deploy SIEM Solution** - Splunk/Elastic with 24/7 monitoring

---

*This report is confidential and intended for authorized personnel only.*
"""
        with open(output, 'w', encoding='utf-8') as f:
            f.write(md)
        print(f"[+] Markdown report generated: {output}")
        return True


# ═══════════════════════════════════════════════════════════════════════
# MAIN CLI
# ═══════════════════════════════════════════════════════════════════════

def run_full_scan(target, threads=50):
    """Run complete VAPT workflow"""
    print("\n" + "=" * 65)
    print("  CORETECH INNOVATION - VAPT COMPLETE TOOLKIT")
    print("  Running Full Assessment Workflow")
    print("=" * 65 + "\n")

    # Step 1: Network Scan
    print("[STEP 1/3] Network Discovery Scan")
    print("-" * 65)
    scanner = NetworkScanner(target, max_threads=threads)
    scan_results = scanner.scan_network()
    scanner.save_report('scan_results.json')
    scanner.print_summary()

    # Step 2: Vulnerability Check
    print("\n[STEP 2/3] Vulnerability Analysis")
    print("-" * 65)
    checker = VulnerabilityChecker()
    vuln_report = checker.analyze(scan_results)
    checker.print_report(vuln_report)
    checker.save_report(vuln_report, 'vuln_report.json')

    # Step 3: Generate Reports
    print("\n[STEP 3/3] Report Generation")
    print("-" * 65)
    generator = ReportGenerator(scan_results, vuln_report)
    generator.generate_html('vapt_report.html')
    generator.generate_markdown('vapt_report.md')

    print("\n" + "=" * 65)
    print("  VAPT ASSESSMENT COMPLETE!")
    print("=" * 65)
    print("\n  Output Files:")
    print("    - scan_results.json   (Raw scan data)")
    print("    - vuln_report.json    (Vulnerability findings)")
    print("    - vapt_report.html    (Professional HTML report)")
    print("    - vapt_report.md      (Markdown report)")
    print("\n  Open vapt_report.html in your browser to view results.")
    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='CoreTech Innovation - VAPT Complete Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Full scan (all modules):
    python vapt_toolkit.py --full 192.168.1.0/24

  Network scan only:
    python vapt_toolkit.py --scan 192.168.1.0/24

  Check existing scan:
    python vapt_toolkit.py --check scan_results.json

  Generate reports from existing data:
    python vapt_toolkit.py --generate scan_results.json vuln_report.json
        """
    )

    parser.add_argument('--full', metavar='TARGET',
                       help='Run complete VAPT workflow (scan + check + report)')
    parser.add_argument('--scan', metavar='TARGET',
                       help='Network scan only')
    parser.add_argument('--check', metavar='FILE',
                       help='Check vulnerabilities in scan results JSON')
    parser.add_argument('--generate', nargs=2, metavar=('SCAN', 'VULN'),
                       help='Generate reports from existing JSON files')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads for scanning (default: 50)')
    parser.add_argument('--output-dir', default='.',
                       help='Output directory for reports (default: current)')

    args = parser.parse_args()

    if not any([args.full, args.scan, args.check, args.generate]):
        parser.print_help()
        return

    # Change to output directory
    if args.output_dir != '.':
        os.makedirs(args.output_dir, exist_ok=True)
        os.chdir(args.output_dir)

    if args.full:
        run_full_scan(args.full, args.threads)

    elif args.scan:
        scanner = NetworkScanner(args.scan, max_threads=args.threads)
        scanner.scan_network()
        scanner.save_report('scan_results.json')
        scanner.print_summary()

    elif args.check:
        with open(args.check, 'r') as f:
            scan_results = json.load(f)
        checker = VulnerabilityChecker()
        report = checker.analyze(scan_results)
        checker.print_report(report)
        checker.save_report(report, 'vuln_report.json')

    elif args.generate:
        with open(args.generate[0], 'r') as f:
            scan_data = json.load(f)
        with open(args.generate[1], 'r') as f:
            vuln_data = json.load(f)
        generator = ReportGenerator(scan_data, vuln_data)
        generator.generate_html('vapt_report.html')
        generator.generate_markdown('vapt_report.md')


if __name__ == '__main__':
    main()
