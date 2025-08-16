"""
Tool Runner Module
Handles execution of external security tools like nmap, sqlmap, nikto, etc.
"""

import subprocess
import json
import logging
import shutil
import tempfile
import os
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

class ToolRunner:
    """Manages and executes external security tools"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.available_tools = self._check_available_tools()
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check which security tools are available on the system"""
        tools = {
            'nmap': shutil.which('nmap') is not None,
            'sqlmap': shutil.which('sqlmap') is not None,
            'nikto': shutil.which('nikto') is not None,
            'wpscan': shutil.which('wpscan') is not None,
            'dirb': shutil.which('dirb') is not None,
            'gobuster': shutil.which('gobuster') is not None,
            'masscan': shutil.which('masscan') is not None,
            'zap-cli': shutil.which('zap-cli') is not None
        }
        
        available = [tool for tool, installed in tools.items() if installed]
        if available:
            self.logger.info(f"Available tools: {', '.join(available)}")
        else:
            self.logger.warning("No security tools found. Please install nmap, sqlmap, nikto, etc.")
        
        return tools
    
    def list_available_tools(self):
        """Display available tools and their status"""
        print("\\n=== RedSentinel AI - Available Tools ===")
        print(f"{'Tool':<15} {'Status':<15} {'Description'}")
        print("-" * 60)
        
        tool_descriptions = {
            'nmap': 'Network port scanner and service detection',
            'sqlmap': 'SQL injection detection and exploitation',
            'nikto': 'Web server vulnerability scanner',
            'wpscan': 'WordPress security scanner',
            'dirb': 'Web directory/file brute forcer',
            'gobuster': 'Fast directory/file brute forcer',
            'masscan': 'High-speed port scanner',
            'zap-cli': 'OWASP ZAP command line interface'
        }
        
        for tool, available in self.available_tools.items():
            status = "✓ Installed" if available else "✗ Not Found"
            description = tool_descriptions.get(tool, "Security tool")
            print(f"{tool:<15} {status:<15} {description}")
        
        print("\\n=== Installation Instructions ===")
        print("To install missing tools:")
        print("• nmap: https://nmap.org/download.html")
        print("• sqlmap: pip install sqlmap")
        print("• nikto: Available in most Linux repos")
        print("• wpscan: gem install wpscan")
        print("• gobuster: https://github.com/OJ/gobuster")
        print("")
    
    def run_vulnerability_scan(self, target: str, tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run vulnerability scanning tools against target (verbose logging)"""
        self.logger.info(f"[ToolRunner] Starting vulnerability scan for target: {target}")
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scans_run': [],
            'vulnerabilities': []
        }
        if not tools:
            tools = ['nmap', 'nikto']
        available_tools = [tool for tool in tools if self.available_tools.get(tool, False)]
        if not available_tools:
            self.logger.warning("[ToolRunner] No requested tools are available")
            results['error'] = "No requested tools available"
            return results
        try:
            for tool in available_tools:
                self.logger.info(f"[ToolRunner] Running {tool} scan...")
                if tool == 'nmap':
                    scan_result = self._run_nmap_scan(target)
                elif tool == 'nikto':
                    scan_result = self._run_nikto_scan(target)
                elif tool == 'sqlmap':
                    scan_result = self._run_sqlmap_scan(target)
                elif tool == 'wpscan':
                    scan_result = self._run_wpscan_scan(target)
                else:
                    self.logger.warning(f"[ToolRunner] Tool {tool} not implemented yet")
                    continue
                self.logger.info(f"[ToolRunner] {tool} scan completed. Status: {scan_result.get('status', 'unknown')}")
                results['scans_run'].append({
                    'tool': tool,
                    'result': scan_result,
                    'timestamp': datetime.now().isoformat()
                })
                vulns = self._extract_vulnerabilities(tool, scan_result)
                if vulns:
                    self.logger.info(f"[ToolRunner] {tool} found {len(vulns)} vulnerabilities.")
                results['vulnerabilities'].extend(vulns)
            self.logger.info(f"[ToolRunner] Vulnerability scanning completed. Found {len(results['vulnerabilities'])} potential issues.")
        except Exception as e:
            self.logger.error(f"[ToolRunner] Vulnerability scanning failed: {str(e)}")
            results['error'] = str(e)
        return results
    
    def _run_nmap_scan(self, target: str) -> Dict[str, Any]:
        """Run nmap port scan with service detection"""
        try:
            # Basic nmap command with service detection
            cmd = [
                'nmap',
                '-sV',  # Service version detection
                '-sC',  # Default scripts
                '--script=vuln',  # Vulnerability scripts
                '-oX', '-',  # XML output to stdout
                target
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                return {
                    'status': 'success',
                    'output': result.stdout,
                    'stderr': result.stderr,
                    'command': ' '.join(cmd)
                }
            else:
                return {
                    'status': 'error',
                    'error': result.stderr,
                    'command': ' '.join(cmd)
                }
                
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': 'Nmap scan timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _run_nikto_scan(self, target: str) -> Dict[str, Any]:
        """Run nikto web vulnerability scan"""
        try:
            # Ensure target has protocol
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            
            cmd = [
                'nikto',
                '-h', target,
                '-output', '-',
                '-Format', 'json'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            return {
                'status': 'success' if result.returncode == 0 else 'completed_with_findings',
                'output': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': 'Nikto scan timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _run_sqlmap_scan(self, target: str) -> Dict[str, Any]:
        """Run sqlmap SQL injection scan"""
        try:
            # Ensure target has protocol
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            
            cmd = [
                'sqlmap',
                '-u', target,
                '--batch',  # Non-interactive mode
                '--crawl=2',  # Crawl depth
                '--level=1',  # Test level
                '--risk=1',   # Risk level
                '--output-dir', tempfile.gettempdir()
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minute timeout
            )
            
            return {
                'status': 'success' if result.returncode == 0 else 'completed_with_findings',
                'output': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': 'SQLMap scan timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _run_wpscan_scan(self, target: str) -> Dict[str, Any]:
        """Run WPScan for WordPress vulnerability scanning"""
        try:
            # Ensure target has protocol
            if not target.startswith(('http://', 'https://')):
                target = f"http://{target}"
            
            cmd = [
                'wpscan',
                '--url', target,
                '--enumerate', 'vp,vt,u',  # Vulnerable plugins, themes, users
                '--format', 'json',
                '--no-banner'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900  # 15 minute timeout
            )
            
            return {
                'status': 'success' if result.returncode == 0 else 'completed_with_findings',
                'output': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': 'WPScan timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def run_web_scan(self, url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """Run web-specific scanning tools"""
        results = {
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'scans_run': [],
            'findings': []
        }
        
        try:
            # Directory/file enumeration
            if self.available_tools.get('gobuster'):
                self.logger.info("Running directory enumeration...")
                dir_scan = self._run_directory_scan(url, wordlist)
                results['scans_run'].append({
                    'tool': 'gobuster',
                    'type': 'directory_enumeration',
                    'result': dir_scan
                })
            
            # Web vulnerability scanning
            if self.available_tools.get('nikto'):
                self.logger.info("Running web vulnerability scan...")
                nikto_scan = self._run_nikto_scan(url)
                results['scans_run'].append({
                    'tool': 'nikto',
                    'type': 'web_vulnerability',
                    'result': nikto_scan
                })
            
            # Extract findings
            for scan in results['scans_run']:
                findings = self._extract_web_findings(scan['tool'], scan['result'])
                results['findings'].extend(findings)
            
            self.logger.info(f"Web scanning completed. Found {len(results['findings'])} findings.")
            
        except Exception as e:
            self.logger.error(f"Web scanning failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def _run_directory_scan(self, url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """Run directory/file enumeration"""
        try:
            if not wordlist:
                # Use a basic wordlist
                wordlist = self._create_basic_wordlist()
            
            cmd = [
                'gobuster',
                'dir',
                '-u', url,
                '-w', wordlist,
                '-x', 'php,html,txt,js,css',  # File extensions
                '--timeout', '10s',
                '-q'  # Quiet mode
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            return {
                'status': 'success' if result.returncode == 0 else 'completed',
                'output': result.stdout,
                'stderr': result.stderr,
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'error': 'Directory scan timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _create_basic_wordlist(self) -> str:
        """Create a basic wordlist for directory enumeration"""
        wordlist_content = """
admin
administrator
login
panel
dashboard
config
backup
test
dev
api
uploads
images
js
css
includes
wp-admin
wp-content
phpmyadmin
""".strip()
        
        wordlist_path = os.path.join(tempfile.gettempdir(), 'basic_wordlist.txt')
        with open(wordlist_path, 'w') as f:
            f.write(wordlist_content)
        
        return wordlist_path
    
    def _extract_vulnerabilities(self, tool: str, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerability information from scan results"""
        vulnerabilities = []
        
        if scan_result.get('status') in ['error', 'timeout']:
            return vulnerabilities
        
        try:
            output = scan_result.get('output', '')
            
            if tool == 'nmap':
                vulnerabilities.extend(self._parse_nmap_vulns(output))
            elif tool == 'nikto':
                vulnerabilities.extend(self._parse_nikto_vulns(output))
            elif tool == 'sqlmap':
                vulnerabilities.extend(self._parse_sqlmap_vulns(output))
            elif tool == 'wpscan':
                vulnerabilities.extend(self._parse_wpscan_vulns(output))
            
        except Exception as e:
            self.logger.error(f"Failed to extract vulnerabilities from {tool}: {str(e)}")
        
        return vulnerabilities
    
    def _parse_nmap_vulns(self, output: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from nmap output"""
        vulns = []
        
        # Look for vulnerability script results
        if 'VULNERABLE' in output:
            # Basic parsing - in a real implementation, you'd parse XML properly
            lines = output.split('\\n')
            for line in lines:
                if 'VULNERABLE' in line:
                    vulns.append({
                        'type': 'network_vulnerability',
                        'severity': 'medium',
                        'description': line.strip(),
                        'source': 'nmap'
                    })
        
        return vulns
    
    def _parse_nikto_vulns(self, output: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from nikto output"""
        vulns = []
        
        # Basic parsing of nikto output
        lines = output.split('\\n')
        for line in lines:
            if '+' in line and any(keyword in line.lower() for keyword in ['vuln', 'risk', 'issue', 'warning']):
                vulns.append({
                    'type': 'web_vulnerability',
                    'severity': 'medium',
                    'description': line.strip(),
                    'source': 'nikto'
                })
        
        return vulns
    
    def _parse_sqlmap_vulns(self, output: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from sqlmap output"""
        vulns = []
        
        if 'vulnerable' in output.lower() or 'injectable' in output.lower():
            vulns.append({
                'type': 'sql_injection',
                'severity': 'high',
                'description': 'SQL injection vulnerability detected',
                'source': 'sqlmap',
                'details': output[:500]  # Include first 500 chars
            })
        
        return vulns
    
    def _parse_wpscan_vulns(self, output: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from wpscan output"""
        vulns = []
        
        try:
            # Try to parse JSON output
            data = json.loads(output)
            
            # Parse different vulnerability types
            for vuln_type in ['vulnerabilities', 'plugins', 'themes']:
                if vuln_type in data:
                    for item in data[vuln_type]:
                        if isinstance(item, dict) and 'vulnerabilities' in item:
                            for vuln in item['vulnerabilities']:
                                vulns.append({
                                    'type': 'wordpress_vulnerability',
                                    'severity': 'medium',
                                    'description': vuln.get('title', 'WordPress vulnerability'),
                                    'source': 'wpscan'
                                })
        except json.JSONDecodeError:
            # Fallback to text parsing
            if 'vulnerabilit' in output.lower():
                vulns.append({
                    'type': 'wordpress_vulnerability',
                    'severity': 'medium',
                    'description': 'WordPress vulnerability detected',
                    'source': 'wpscan'
                })
        
        return vulns
    
    def _extract_web_findings(self, tool: str, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from web scanning tools"""
        findings = []
        
        if scan_result.get('status') in ['error', 'timeout']:
            return findings
        
        try:
            output = scan_result.get('output', '')
            
            if tool == 'gobuster':
                # Parse gobuster directory findings
                lines = output.split('\\n')
                for line in lines:
                    if 'Status:' in line and ('200' in line or '301' in line or '302' in line):
                        findings.append({
                            'type': 'directory_found',
                            'severity': 'info',
                            'description': line.strip(),
                            'source': 'gobuster'
                        })
            
        except Exception as e:
            self.logger.error(f"Failed to extract web findings from {tool}: {str(e)}")
        
        return findings
