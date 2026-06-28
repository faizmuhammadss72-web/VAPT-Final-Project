#!/usr/bin/env python3
"""
CoreTech Innovation - VAPT Report Generator
Author: Security Assessment Team
Date: June 2026
Description: Generates professional HTML reports from scan data
"""

import json
import os
from datetime import datetime
from typing import Dict, List

class ReportGenerator:
    """Professional HTML report generator for VAPT assessments"""

    def __init__(self, scan_data: Dict, vuln_data: Dict):
        self.scan_data = scan_data
        self.vuln_data = vuln_data
        self.report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def generate_html_report(self, output_file: str = 'vapt_report.html'):
        """Generate professional HTML report"""

        # Calculate statistics
        total_hosts = len(self.scan_data.get('hosts', []))
        total_vulns = self.vuln_data.get('total_vulnerabilities', 0)
        critical = self.vuln_data.get('critical', 0)
        high = self.vuln_data.get('high', 0)
        medium = self.vuln_data.get('medium', 0)
        low = self.vuln_data.get('low', 0)

        # Generate findings table rows
        findings_rows = self._generate_findings_rows()

        # Generate host summary cards
        host_cards = self._generate_host_cards()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CoreTech Innovation - VAPT Report</title>
    <style>
        :root {{
            --bg-primary: #0a0e1a;
            --bg-secondary: #161b22;
            --bg-card: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #00d4ff;
            --critical: #ff0000;
            --high: #ff6600;
            --medium: #ffcc00;
            --low: #00cc44;
            --info: #2196f3;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #001a33 0%, #0a0e1a 100%);
            padding: 40px;
            text-align: center;
            border-bottom: 3px solid var(--accent);
            margin-bottom: 30px;
            border-radius: 10px;
        }}

        .header h1 {{
            color: var(--accent);
            font-size: 2.5em;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}

        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 1.2em;
        }}

        .header .meta {{
            margin-top: 20px;
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }}

        .meta-item {{
            background: var(--bg-card);
            padding: 10px 20px;
            border-radius: 5px;
            border: 1px solid #30363d;
        }}

        .meta-label {{
            color: var(--text-secondary);
            font-size: 0.85em;
        }}

        .meta-value {{
            color: var(--accent);
            font-weight: bold;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            border: 1px solid #30363d;
            transition: transform 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}

        .stat-label {{
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
        }}

        .stat-critical {{ color: var(--critical); }}
        .stat-high {{ color: var(--high); }}
        .stat-medium {{ color: var(--medium); }}
        .stat-low {{ color: var(--low); }}
        .stat-info {{ color: var(--info); }}

        /* Section */
        .section {{
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid #30363d;
        }}

        .section h2 {{
            color: var(--accent);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #30363d;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .section h2::before {{
            content: '';
            display: inline-block;
            width: 4px;
            height: 24px;
            background: var(--accent);
            border-radius: 2px;
        }}

        /* Table */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.95em;
        }}

        .data-table th {{
            background: var(--bg-card);
            padding: 15px 12px;
            text-align: left;
            color: var(--accent);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}

        .data-table td {{
            padding: 12px;
            border-bottom: 1px solid #30363d;
        }}

        .data-table tr:hover {{
            background: rgba(0, 212, 255, 0.05);
        }}

        .data-table tr:nth-child(even) {{
            background: rgba(255, 255, 255, 0.02);
        }}

        /* Severity Badges */
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }}

        .badge-critical {{
            background: rgba(255, 0, 0, 0.2);
            color: var(--critical);
            border: 1px solid var(--critical);
        }}

        .badge-high {{
            background: rgba(255, 102, 0, 0.2);
            color: var(--high);
            border: 1px solid var(--high);
        }}

        .badge-medium {{
            background: rgba(255, 204, 0, 0.2);
            color: var(--medium);
            border: 1px solid var(--medium);
        }}

        .badge-low {{
            background: rgba(0, 204, 68, 0.2);
            color: var(--low);
            border: 1px solid var(--low);
        }}

        /* Host Cards */
        .host-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}

        .host-card {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            border: 1px solid #30363d;
        }}

        .host-card h3 {{
            color: var(--accent);
            margin-bottom: 10px;
        }}

        .host-meta {{
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-bottom: 15px;
        }}

        .service-list {{
            list-style: none;
        }}

        .service-list li {{
            padding: 5px 0;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
        }}

        .service-list li:last-child {{
            border-bottom: none;
        }}

        /* Recommendations */
        .recommendation {{
            background: var(--bg-card);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--accent);
        }}

        .recommendation h4 {{
            color: var(--text-primary);
            margin-bottom: 10px;
        }}

        .recommendation p {{
            color: var(--text-secondary);
            font-size: 0.95em;
        }}

        .recommendation.critical {{
            border-left-color: var(--critical);
        }}

        .recommendation.high {{
            border-left-color: var(--high);
        }}

        .recommendation.medium {{
            border-left-color: var(--medium);
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9em;
            border-top: 1px solid #30363d;
            margin-top: 30px;
        }}

        /* Print Styles */
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .header {{
                background: #f0f0f0;
            }}
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 1.8em;
            }}
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .data-table {{
                font-size: 0.85em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>VAPT Assessment Report</h1>
            <p class="subtitle">CoreTech Innovation - Network Security Assessment</p>
            <div class="meta">
                <div class="meta-item">
                    <div class="meta-label">Report Date</div>
                    <div class="meta-value">{self.report_date}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Project ID</div>
                    <div class="meta-value">VAPT-2026-CTI-001</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Network Range</div>
                    <div class="meta-value">192.168.1.0/24</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Classification</div>
                    <div class="meta-value">CONFIDENTIAL</div>
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <p>This report presents the findings of a comprehensive Vulnerability Assessment and 
            Penetration Testing (VAPT) conducted on CoreTech Innovation's network infrastructure 
            (192.168.1.0/24). The assessment identified <strong>{total_vulns} vulnerabilities</strong> 
            across <strong>{total_hosts} active hosts</strong>, including <strong>{critical} critical</strong> 
            and <strong>{high} high-severity</strong> issues requiring immediate attention.</p>

            <div class="stats-grid" style="margin-top: 25px;">
                <div class="stat-card">
                    <div class="stat-number stat-critical">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-high">{high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-medium">{medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number stat-low">{low}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>

        <!-- Vulnerability Findings -->
        <div class="section">
            <h2>Vulnerability Findings</h2>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Host</th>
                        <th>Port</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>

        <!-- Host Summary -->
        <div class="section">
            <h2>Discovered Hosts</h2>
            <div class="host-grid">
                {host_cards}
            </div>
        </div>

        <!-- Recommendations -->
        <div class="section">
            <h2>Recommendations</h2>

            <div class="recommendation critical">
                <h4>CRITICAL: Patch BlueKeep (CVE-2019-0708)</h4>
                <p>Install Microsoft security update KB4499175 immediately on the Domain Controller 
                (192.168.1.30). This vulnerability allows unauthenticated remote code execution via RDP 
                and poses an immediate threat to the entire domain.</p>
            </div>

            <div class="recommendation critical">
                <h4>CRITICAL: Secure MySQL Database</h4>
                <p>Set a strong password for the MySQL root account on 192.168.1.20 and remove 
                anonymous users. The current empty password configuration allows unauthorized access 
                to all databases including customer payment data.</p>
            </div>

            <div class="recommendation high">
                <h4>HIGH: Implement Network Segmentation</h4>
                <p>Create separate VLANs for DMZ, database, and internal networks. Apply strict 
                ACLs to limit lateral movement between network segments.</p>
            </div>

            <div class="recommendation high">
                <h4>HIGH: Deploy Intrusion Detection System</h4>
                <p>Install Snort or Suricata on the network perimeter with rules for detecting 
                RDP exploitation, SMB attacks, and database access anomalies.</p>
            </div>

            <div class="recommendation medium">
                <h4>MEDIUM: Establish Patch Management Program</h4>
                <p>Implement WSUS for Windows updates and establish a monthly patching schedule 
                with a staging environment for testing patches before production deployment.</p>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p><strong>Confidential - CoreTech Innovation Security Assessment</strong></p>
            <p>This report is intended for authorized personnel only. Distribution is restricted.</p>
            <p style="margin-top: 10px; font-size: 0.85em;">Generated by VAPT Report Generator v1.0 | {self.report_date}</p>
        </div>
    </div>
</body>
</html>"""

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
            print(f"[+] HTML report generated: {output_file}")
            print(f"[+] Open in browser: file://{os.path.abspath(output_file)}")
            return True
        except Exception as e:
            print(f"[!] Error generating report: {e}")
            return False

    def _generate_findings_rows(self) -> str:
        """Generate HTML table rows for vulnerability findings"""
        rows = []

        for finding in self.vuln_data.get('findings', []):
            severity = finding.get('severity', 'INFO').lower()
            badge_class = f"badge-{severity}"

            row = f"""<tr>
                <td><code>{finding.get('cve', 'N/A')}</code></td>
                <td>{finding.get('host', 'N/A')}</td>
                <td>{finding.get('port', 'N/A')}</td>
                <td><span class="badge {badge_class}">{finding.get('severity', 'N/A')}</span></td>
                <td>{finding.get('cvss', 'N/A')}</td>
                <td>{finding.get('description', 'N/A')}</td>
            </tr>"""
            rows.append(row)

        if not rows:
            rows.append('<tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">No vulnerabilities found</td></tr>')

        return '\n'.join(rows)

    def _generate_host_cards(self) -> str:
        """Generate HTML cards for discovered hosts"""
        cards = []

        for host in self.scan_data.get('hosts', []):
            services_html = []
            for port, service in host.get('services', {}).items():
                services_html.append(
                    f'<li><span>{service.get("name", "Unknown")}</span> <span style="color: var(--text-secondary);">:{port}</span></li>'
                )

            card = f"""<div class="host-card">
                <h3>{host.get('ip', 'Unknown')}</h3>
                <div class="host-meta">
                    {f"Hostname: {host.get('hostname', 'N/A')} | " if host.get('hostname') else ''}
                    OS: {host.get('os_guess', 'Unknown')}
                </div>
                <ul class="service-list">
                    {''.join(services_html) if services_html else '<li style="color: var(--text-secondary);">No services identified</li>'}
                </ul>
            </div>"""
            cards.append(card)

        if not cards:
            cards.append('<div class="host-card"><p style="color: var(--text-secondary);">No hosts discovered</p></div>')

        return '\n'.join(cards)

    def generate_markdown_report(self, output_file: str = 'vapt_report.md'):
        """Generate Markdown report"""
        md = f"""# VAPT Assessment Report

## CoreTech Innovation - Network Security Assessment

**Report Date:** {self.report_date}
**Project ID:** VAPT-2026-CTI-001
**Network Range:** 192.168.1.0/24
**Classification:** CONFIDENTIAL

---

## Executive Summary

This report presents the findings of a comprehensive Vulnerability Assessment and Penetration Testing (VAPT) conducted on CoreTech Innovation's network infrastructure.

### Statistics

| Metric | Value |
|--------|-------|
| Total Hosts | {len(self.scan_data.get('hosts', []))} |
| Total Vulnerabilities | {self.vuln_data.get('total_vulnerabilities', 0)} |
| Critical | {self.vuln_data.get('critical', 0)} |
| High | {self.vuln_data.get('high', 0)} |
| Medium | {self.vuln_data.get('medium', 0)} |
| Low | {self.vuln_data.get('low', 0)} |

---

## Vulnerability Findings

| CVE | Host | Port | Severity | CVSS | Description |
|-----|------|------|----------|------|-------------|
"""

        for finding in self.vuln_data.get('findings', []):
            md += f"| {finding.get('cve', 'N/A')} | {finding.get('host', 'N/A')} | {finding.get('port', 'N/A')} | **{finding.get('severity', 'N/A')}** | {finding.get('cvss', 'N/A')} | {finding.get('description', 'N/A')} |\n"

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

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(md)
            print(f"[+] Markdown report generated: {output_file}")
            return True
        except Exception as e:
            print(f"[!] Error generating markdown report: {e}")
            return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='CoreTech Innovation - VAPT Report Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python report_generator.py -s scan.json -v vuln.json
  python report_generator.py -s scan.json -v vuln.json -o report.html
  python report_generator.py -s scan.json -v vuln.json --format markdown
        """
    )

    parser.add_argument('-s', '--scan', required=True,
                       help='Input scan results JSON file')
    parser.add_argument('-v', '--vuln', required=True,
                       help='Input vulnerability report JSON file')
    parser.add_argument('-o', '--output', default='vapt_report.html',
                       help='Output file name (default: vapt_report.html)')
    parser.add_argument('--format', choices=['html', 'markdown', 'both'], default='html',
                       help='Report format (default: html)')

    args = parser.parse_args()

    # Load input files
    try:
        with open(args.scan, 'r') as f:
            scan_data = json.load(f)
        print(f"[+] Loaded scan results: {args.scan}")
    except Exception as e:
        print(f"[!] Error loading scan results: {e}")
        return

    try:
        with open(args.vuln, 'r') as f:
            vuln_data = json.load(f)
        print(f"[+] Loaded vulnerability data: {args.vuln}")
    except Exception as e:
        print(f"[!] Error loading vulnerability data: {e}")
        return

    # Generate reports
    generator = ReportGenerator(scan_data, vuln_data)

    if args.format in ['html', 'both']:
        generator.generate_html_report(args.output)

    if args.format in ['markdown', 'both']:
        md_file = args.output.replace('.html', '.md')
        generator.generate_markdown_report(md_file)

    print("\n[+] Report generation complete!")


if __name__ == '__main__':
    main()
