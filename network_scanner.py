#!/usr/bin/env python3
"""
CoreTech Innovation - Network Discovery Scanner
Author: Security Assessment Team
Date: June 2026
Description: Automated network discovery and port scanning tool
"""

import socket
import subprocess
import sys
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

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

        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
            3306, 3389, 5432, 8080, 8443,
        ]

        # Service signatures
        self.service_signatures = {
            21: {'name': 'FTP', 'banner': b'220'},
            22: {'name': 'SSH', 'banner': b'SSH-'},
            23: {'name': 'Telnet', 'banner': b''},
            25: {'name': 'SMTP', 'banner': b'220'},
            53: {'name': 'DNS', 'banner': b''},
            80: {'name': 'HTTP', 'banner': b'HTTP/'},
            110: {'name': 'POP3', 'banner': b'+OK'},
            143: {'name': 'IMAP', 'banner': b'* OK'},
            443: {'name': 'HTTPS', 'banner': b''},
            445: {'name': 'SMB', 'banner': b''},
            3306: {'name': 'MySQL', 'banner': b''},
            3389: {'name': 'RDP', 'banner': b''},
            5432: {'name': 'PostgreSQL', 'banner': b''},
            8080: {'name': 'HTTP-Proxy', 'banner': b'HTTP/'},
            8443: {'name': 'HTTPS-Alt', 'banner': b''},
        }

    def ping_host(self, ip):
        """Check if host is alive using ICMP ping"""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(ip)],
                capture_output=True,
                timeout=3,
                text=True
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((str(ip), 80))
                sock.close()
                return result == 0
            except:
                return False

    def scan_port(self, ip, port):
        """Scan a single port on a host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((str(ip), port))

            if result == 0:
                banner = self.grab_banner(sock, port)
                sock.close()
                return {
                    'port': port,
                    'state': 'open',
                    'banner': banner
                }

            sock.close()
            return None
        except Exception as e:
            return None

    def grab_banner(self, sock, port):
        """Grab service banner from open port"""
        try:
            sock.settimeout(2)
            if port in [80, 8080, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            else:
                sock.send(b'\r\n')

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:200]
        except:
            return ''

    def identify_service(self, port, banner=''):
        """Identify service based on port and banner"""
        service_info = {
            'name': 'Unknown',
            'version': 'Unknown',
            'port': port
        }

        if port in self.service_signatures:
            service_info['name'] = self.service_signatures[port]['name']

        banner_lower = banner.lower()

        if 'apache' in banner_lower:
            service_info['name'] = 'Apache HTTP Server'
            if 'apache/' in banner_lower:
                try:
                    version = banner_lower.split('apache/')[1].split()[0]
                    service_info['version'] = version
                except:
                    pass
        elif 'nginx' in banner_lower:
            service_info['name'] = 'nginx'
            if 'nginx/' in banner_lower:
                try:
                    version = banner_lower.split('nginx/')[1].split()[0]
                    service_info['version'] = version
                except:
                    pass
        elif 'openssh' in banner_lower:
            service_info['name'] = 'OpenSSH'
            if 'openssh_' in banner_lower:
                try:
                    version = banner_lower.split('openssh_')[1].split()[0]
                    service_info['version'] = version
                except:
                    pass
        elif 'mysql' in banner_lower:
            service_info['name'] = 'MySQL'
            if '5.' in banner_lower:
                service_info['version'] = '5.x'
            elif '8.' in banner_lower:
                service_info['version'] = '8.x'
        elif 'microsoft' in banner_lower or 'iis' in banner_lower:
            service_info['name'] = 'Microsoft IIS'
        elif 'ssh-' in banner_lower:
            service_info['name'] = 'SSH'
            if 'ssh-' in banner_lower:
                try:
                    version = banner_lower.split('ssh-')[1].split('-')[0]
                    service_info['version'] = version
                except:
                    pass

        return service_info

    def scan_host(self, ip):
        """Perform full scan on a single host"""
        if not self.ping_host(ip):
            return None

        host_data = {
            'ip': str(ip),
            'hostname': '',
            'open_ports': [],
            'services': {},
            'os_guess': 'Unknown'
        }

        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            host_data['hostname'] = hostname
        except:
            pass

        open_ports_found = []
        for port in self.common_ports:
            result = self.scan_port(ip, port)
            if result:
                open_ports_found.append(result)

        for port_info in open_ports_found:
            port = port_info['port']
            banner = port_info.get('banner', '')
            service = self.identify_service(port, banner)

            host_data['open_ports'].append(port)
            host_data['services'][str(port)] = {
                'name': service['name'],
                'version': service['version'],
                'banner': banner[:100] if banner else ''
            }

        if 445 in host_data['open_ports'] or 3389 in host_data['open_ports']:
            host_data['os_guess'] = 'Windows'
        elif 22 in host_data['open_ports']:
            host_data['os_guess'] = 'Linux/Unix'

        return host_data

    def scan_network(self):
        """Scan entire network range"""
        print("=" * 60)
        print("  CoreTech Innovation - Network Discovery Scanner")
        print("=" * 60)
        print(f"[+] Target Range: {self.target_range}")
        print(f"[+] Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[+] Threads: {self.max_threads}")
        print(f"[+] Ports to Scan: {len(self.common_ports)}")
        print("-" * 60)

        try:
            network = ipaddress.ip_network(self.target_range, strict=False)
            hosts = list(network.hosts())
        except ValueError:
            print(f"[!] Invalid network range: {self.target_range}")
            print("[!] Example: 192.168.1.0/24")
            return None

        self.results['summary']['total_hosts_scanned'] = len(hosts)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip): ip for ip in hosts}

            completed = 0
            for future in as_completed(future_to_ip):
                completed += 1
                ip = future_to_ip[future]

                try:
                    result = future.result()
                    if result and result['open_ports']:
                        self.results['hosts'].append(result)
                        self.results['summary']['active_hosts'] += 1
                        self.results['summary']['total_open_ports'] += len(result['open_ports'])
                        self.results['summary']['services_identified'] += len(result['services'])

                        print(f"[+] Host Found: {result['ip']:<15} | Ports: {result['open_ports']}")
                except Exception as e:
                    print(f"[!] Error scanning {ip}: {e}")

                if completed % 50 == 0:
                    print(f"[*] Progress: {completed}/{len(hosts)} hosts scanned...")

        print("-" * 60)
        print(f"[+] Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[+] Active Hosts: {self.results['summary']['active_hosts']}")
        print(f"[+] Open Ports: {self.results['summary']['total_open_ports']}")
        print(f"[+] Services: {self.results['summary']['services_identified']}")
        print("=" * 60)

        return self.results

    def save_report(self, filename='network_scan_report.json'):
        """Save scan results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"[+] Report saved: {filename}")
        except Exception as e:
            print(f"[!] Error saving report: {e}")

    def print_summary(self):
        """Print formatted summary to console"""
        print("\n" + "=" * 60)
        print("  SCAN SUMMARY")
        print("=" * 60)

        for host in self.results['hosts']:
            print(f"\nHost: {host['ip']}")
            if host['hostname']:
                print(f"Hostname: {host['hostname']}")
            print(f"OS Guess: {host['os_guess']}")
            print(f"Open Ports: {host['open_ports']}")
            print("Services:")
            for port, service in host['services'].items():
                print(f"  {port}/tcp - {service['name']} {service['version']}")

        print("\n" + "=" * 60)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='CoreTech Innovation - Network Discovery Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py -t 192.168.1.0/24
  python network_scanner.py -t 192.168.1.0/24 -o scan_results.json
  python network_scanner.py -t 192.168.1.0/24 --threads 100
        """
    )

    parser.add_argument('-t', '--target', required=True,
                       help='Target network range (e.g., 192.168.1.0/24)')
    parser.add_argument('-o', '--output', default='network_scan_report.json',
                       help='Output file name (default: network_scan_report.json)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of concurrent threads (default: 50)')

    args = parser.parse_args()

    scanner = NetworkScanner(args.target, max_threads=args.threads)
    scanner.scan_network()
    scanner.print_summary()
    scanner.save_report(args.output)


if __name__ == '__main__':
    main()
