#!/usr/bin/env python3
"""
Python Vulnerability Analyzer
Security scanning tool for analyzing code and systems
"""

import os
import re
import json
import hashlib
import subprocess
import requests
import socket
import ssl
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import xml.etree.ElementTree as ET
import csv
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    """Main vulnerability analysis engine"""
    
    def __init__(self, output_dir: str = "scan_results"):
        self.output_dir = output_dir
        self.results = []
        self.vulnerabilities_found = 0
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Known vulnerability patterns
        self.vuln_patterns = {
            'sql_injection': [
                r"SELECT.*FROM.*WHERE.*\$\{.*\}",
                r"execute.*\(\s*\$\{",
                r"query.*\(\s*['\"]SELECT.*['\"]\s*\+\s*",
                r"\.format\(.*SELECT.*\)",
                r"f['\"].*SELECT.*['\"]"
            ],
            'xss': [
                r"innerHTML\s*=\s*.*[\+\&].*userInput",
                r"document\.write\(.*[\+\&].*user",
                r"eval\(.*request\.GET",
                r"<script>.*\{.*\}.*</script>"
            ],
            'command_injection': [
                r"os\.system\(.*[\+\&].*input",
                r"subprocess\.call\(.*shell=True.*\)",
                r"popen\(.*[\+\&]",
                r"exec\(.*\{.*\}",
                r"eval\(.*input\("
            ],
            'path_traversal': [
                r"open\(.*\.\./",
                r"file\.read\(.*\.\./",
                r"\.\./\.\./",
                r"\.\.%2f"
            ],
            'hardcoded_secrets': [
                r"password\s*=\s*['\"][^'\"]{8,}['\"]",
                r"api_key\s*=\s*['\"][^'\"]{20,}['\"]",
                r"secret\s*=\s*['\"][^'\"]{10,}['\"]",
                r"token\s*=\s*['\"][^'\"]{10,}['\"]",
                r"AWS_ACCESS_KEY_ID",
                r"AWS_SECRET_ACCESS_KEY"
            ],
            'weak_crypto': [
                r"md5\(",
                r"sha1\(",
                r"DES\(",
                r"RC4\(",
                r"base64\.b64encode\(.*password"
            ]
        }
        
        # CVSS severity mapping
        self.cvss_severity = {
            'CRITICAL': 9.0,
            'HIGH': 7.0,
            'MEDIUM': 4.0,
            'LOW': 0.1
        }
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file for vulnerabilities"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Check for each vulnerability pattern
                for vuln_type, patterns in self.vuln_patterns.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            # Find line number
                            line_num = 0
                            current_pos = 0
                            for i, line in enumerate(lines):
                                current_pos += len(line) + 1
                                if current_pos > match.start():
                                    line_num = i + 1
                                    break
                            
                            issue = {
                                'file': file_path,
                                'line': line_num,
                                'vulnerability_type': vuln_type.upper(),
                                'pattern': pattern,
                                'matched_text': match.group()[:100],
                                'severity': self._determine_severity(vuln_type),
                                'timestamp': datetime.now().isoformat()
                            }
                            issues.append(issue)
                            self.vulnerabilities_found += 1
                            logger.warning(f"Found {vuln_type} in {file_path}:{line_num}")
                
                # Additional checks
                self._check_additional_vulns(file_path, content, lines, issues)
                
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
        
        return issues
    
    def _check_additional_vulns(self, file_path: str, content: str, lines: List[str], issues: List[Dict]):
        """Perform additional vulnerability checks"""
        
        # Check for debug statements in production code
        debug_patterns = [
            r"print\(.*password",
            r"console\.log\(.*secret",
            r"logger\.debug\(.*key"
        ]
        
        for pattern in debug_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = self._find_line_number(match.start(), lines)
                issues.append({
                    'file': file_path,
                    'line': line_num,
                    'vulnerability_type': 'INFO_DISCLOSURE',
                    'pattern': pattern,
                    'matched_text': match.group()[:100],
                    'severity': 'MEDIUM',
                    'timestamp': datetime.now().isoformat()
                })
    
    def _find_line_number(self, position: int, lines: List[str]) -> int:
        """Find line number from character position"""
        current_pos = 0
        for i, line in enumerate(lines):
            current_pos += len(line) + 1
            if current_pos > position:
                return i + 1
        return 0
    
    def _determine_severity(self, vuln_type: str) -> str:
        """Determine severity based on vulnerability type"""
        severity_map = {
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'xss': 'HIGH',
            'path_traversal': 'HIGH',
            'hardcoded_secrets': 'HIGH',
            'weak_crypto': 'MEDIUM',
            'info_disclosure': 'MEDIUM'
        }
        return severity_map.get(vuln_type, 'LOW')
    
    def scan_directory(self, directory_path: str, extensions: List[str] = None) -> Dict[str, Any]:
        """Scan a directory recursively for vulnerabilities"""
        if extensions is None:
            extensions = ['.py', '.js', '.java', '.php', '.html', '.xml', '.json']
        
        all_issues = []
        scanned_files = 0
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', 'venv']]
            
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    file_path = os.path.join(root, file)
                    issues = self.scan_file(file_path)
                    all_issues.extend(issues)
                    scanned_files += 1
        
        return {
            'scanned_files': scanned_files,
            'vulnerabilities_found': len(all_issues),
            'issues': all_issues,
            'scan_time': datetime.now().isoformat()
        }
    
    def scan_web_url(self, url: str) -> Dict[str, Any]:
        """Scan a web URL for common vulnerabilities"""
        results = {
            'url': url,
            'checks': [],
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Check for HTTPS
            if not url.startswith('https://'):
                results['checks'].append({
                    'check': 'HTTPS_ENABLED',
                    'status': 'FAIL',
                    'severity': 'HIGH',
                    'message': 'Site does not use HTTPS'
                })
            
            # Perform basic security headers check
            try:
                response = requests.get(url, timeout=10)
                headers = response.headers
                
                security_headers = {
                    'X-Frame-Options': 'MEDIUM',
                    'X-Content-Type-Options': 'LOW',
                    'Strict-Transport-Security': 'HIGH',
                    'Content-Security-Policy': 'MEDIUM'
                }
                
                for header, severity in security_headers.items():
                    if header not in headers:
                        results['checks'].append({
                            'check': f'HEADER_{header}',
                            'status': 'FAIL',
                            'severity': severity,
                            'message': f'Missing security header: {header}'
                        })
                
            except requests.RequestException as e:
                results['checks'].append({
                    'check': 'CONNECTIVITY',
                    'status': 'ERROR',
                    'severity': 'INFO',
                    'message': f'Failed to connect: {e}'
                })
            
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {e}")
        
        return results
    
    def check_dependencies(self, requirements_file: str = "requirements.txt") -> Dict[str, Any]:
        """Check Python dependencies for known vulnerabilities"""
        vulnerabilities = []
        
        if not os.path.exists(requirements_file):
            return {'status': 'ERROR', 'message': 'Requirements file not found'}
        
        try:
            # Parse requirements file
            with open(requirements_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple check - in real implementation, use safety db or similar
                        if 'django' in line.lower() and '1.11' in line:
                            vulnerabilities.append({
                                'package': 'django',
                                'version': '1.11',
                                'vulnerability': 'Outdated version with known security issues',
                                'severity': 'HIGH'
                            })
        
        except Exception as e:
            logger.error(f"Error checking dependencies: {e}")
        
        return {
            'dependencies_checked': True,
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities
        }
    
    def generate_report(self, scan_results: Dict[str, Any], report_format: str = 'json') -> str:
        """Generate vulnerability report in specified format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if report_format == 'json':
            report_file = os.path.join(self.output_dir, f"vuln_scan_{timestamp}.json")
            with open(report_file, 'w') as f:
                json.dump(scan_results, f, indent=2)
        
        elif report_format == 'html':
            report_file = os.path.join(self.output_dir, f"vuln_scan_{timestamp}.html")
            self._generate_html_report(scan_results, report_file)
        
        elif report_format == 'csv':
            report_file = os.path.join(self.output_dir, f"vuln_scan_{timestamp}.csv")
            self._generate_csv_report(scan_results, report_file)
        
        else:
            report_file = os.path.join(self.output_dir, f"vuln_scan_{timestamp}.txt")
            self._generate_text_report(scan_results, report_file)
        
        logger.info(f"Report generated: {report_file}")
        return report_file
    
    def _generate_html_report(self, results: Dict[str, Any], output_file: str):
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .vuln { margin: 10px 0; padding: 10px; border-left: 4px solid; }
                .critical { border-color: #e74c3c; background: #fadbd8; }
                .high { border-color: #e67e22; background: #fdebd0; }
                .medium { border-color: #f1c40f; background: #fef9e7; }
                .low { border-color: #27ae60; background: #d5f4e6; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #34495e; color: white; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔒 Vulnerability Scan Report</h1>
                <p>Generated: {timestamp}</p>
            </div>
            
            <div class="summary">
                <h2>📊 Scan Summary</h2>
                <p>Files Scanned: {files_scanned}</p>
                <p>Vulnerabilities Found: {vuln_count}</p>
            </div>
            
            {vulnerabilities_table}
        </body>
        </html>
        """
        
        # Create vulnerabilities table
        vuln_table = "<h2>🚨 Vulnerabilities Found</h2><table>"
        vuln_table += "<tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Details</th></tr>"
        
        for issue in results.get('issues', []):
            severity_class = issue['severity'].lower()
            vuln_table += f"""
            <tr class="{severity_class}">
                <td>{issue.get('file', 'N/A')}</td>
                <td>{issue.get('line', 'N/A')}</td>
                <td>{issue.get('vulnerability_type', 'N/A')}</td>
                <td><strong>{issue.get('severity', 'N/A')}</strong></td>
                <td>{issue.get('matched_text', 'N/A')}</td>
            </tr>
            """
        
        vuln_table += "</table>"
        
        # Fill template
        html_content = html_template.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            files_scanned=results.get('scanned_files', 0),
            vuln_count=results.get('vulnerabilities_found', 0),
            vulnerabilities_table=vuln_table
        )
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def _generate_csv_report(self, results: Dict[str, Any], output_file: str):
        """Generate CSV report"""
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['file', 'line', 'vulnerability_type', 'severity', 'pattern', 'matched_text', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for issue in results.get('issues', []):
                writer.writerow(issue)
    
    def _generate_text_report(self, results: Dict[str, Any], output_file: str):
        """Generate plain text report"""
        with open(output_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("VULNERABILITY SCAN REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Files Scanned: {results.get('scanned_files', 0)}\n")
            f.write(f"Vulnerabilities Found: {results.get('vulnerabilities_found', 0)}\n\n")
            
            f.write("-" * 60 + "\n")
            f.write("DETAILED FINDINGS:\n")
            f.write("-" * 60 + "\n\n")
            
            for issue in results.get('issues', []):
                f.write(f"File: {issue.get('file')}\n")
                f.write(f"Line: {issue.get('line')}\n")
                f.write(f"Type: {issue.get('vulnerability_type')}\n")
                f.write(f"Severity: {issue.get('severity')}\n")
                f.write(f"Pattern: {issue.get('pattern')[:50]}...\n")
                f.write(f"Match: {issue.get('matched_text')}\n")
                f.write("-" * 40 + "\n")

class NetworkScanner:
    """Network vulnerability scanner component"""
    
    @staticmethod
    def scan_ports(target: str, ports: List[int] = None) -> List[Dict]:
        """Scan open ports on target"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432]
        
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = NetworkScanner._get_service_name(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'OPEN'
                    })
                sock.close()
            except:
                pass
        
        return open_ports
    
    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get service name for common ports"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL'
        }
        return services.get(port, 'Unknown')

# Example usage and main function
def main():
    """Main function demonstrating the vulnerability analyzer"""
    
    print("🔒 Python Vulnerability Analyzer")
    print("=" * 40)
    
    # Initialize analyzer
    analyzer = VulnerabilityAnalyzer()
    
    # Menu-driven interface
    while True:
        print("\nSelect scan type:")
        print("1. Scan directory for code vulnerabilities")
        print("2. Scan web URL")
        print("3. Check dependencies")
        print("4. Network port scan")
        print("5. Exit")
        
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == '1':
            path = input("Enter directory path to scan: ").strip()
            if os.path.exists(path):
                print(f"Scanning directory: {path}")
                results = analyzer.scan_directory(path)
                
                # Generate reports
                analyzer.generate_report(results, 'json')
                analyzer.generate_report(results, 'html')
                
                print(f"\nScan complete!")
                print(f"Files scanned: {results['scanned_files']}")
                print(f"Vulnerabilities found: {results['vulnerabilities_found']}")
                
                # Show top vulnerabilities
                if results['issues']:
                    print("\nTop vulnerabilities:")
                    for issue in results['issues'][:5]:
                        print(f"  {issue['vulnerability_type']} - {issue['severity']}: {issue['file']}:{issue['line']}")
            else:
                print("Invalid directory path!")
        
        elif choice == '2':
            url = input("Enter URL to scan (include http:// or https://): ").strip()
            results = analyzer.scan_web_url(url)
            
            print(f"\nWeb scan results for{url}:")
      for check in results['checks']:
               