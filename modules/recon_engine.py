"""
Reconnaissance Engine Module
Handles passive and active information gathering about targets.
"""

import subprocess
import socket
import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import requests
import dns.resolver
from datetime import datetime

class ReconEngine:
    """Reconnaissance and information gathering engine"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def run_reconnaissance(self, target: str, level: str = 'standard') -> Dict[str, Any]:
        """Run comprehensive reconnaissance based on target and level (verbose logging)"""
        self.logger.info(f"[ReconEngine] Starting reconnaissance for target: {target} (level: {level})")
        results = {
            'target': target,
            'target_type': self._identify_target_type(target),
            'timestamp': datetime.now().isoformat(),
            'recon_level': level,
            'findings': {}
        }
        try:
            self.logger.info("[ReconEngine] Gathering basic info...")
            results['findings']['basic_info'] = self._gather_basic_info(target)
            self.logger.info("[ReconEngine] Performing DNS reconnaissance...")
            results['findings']['dns_info'] = self._dns_reconnaissance(target)
            self.logger.info("[ReconEngine] Performing basic port scan...")
            results['findings']['port_scan'] = self._basic_port_scan(target)
            if level in ['standard', 'deep']:
                self.logger.info("[ReconEngine] Detecting services...")
                results['findings']['service_detection'] = self._service_detection(target)
                self.logger.info("[ReconEngine] Performing web reconnaissance...")
                results['findings']['web_info'] = self._web_reconnaissance(target)
            if level == 'deep':
                self.logger.info("[ReconEngine] Enumerating subdomains...")
                results['findings']['subdomain_enum'] = self._subdomain_enumeration(target)
                self.logger.info("[ReconEngine] Attempting OS detection...")
                results['findings']['os_detection'] = self._os_detection(target)
                self.logger.info("[ReconEngine] Looking for vulnerability hints...")
                results['findings']['vulnerability_hints'] = self._vulnerability_reconnaissance(target)
            self.logger.info("[ReconEngine] Reconnaissance completed successfully")
        except Exception as e:
            self.logger.error(f"[ReconEngine] Reconnaissance failed: {str(e)}")
            results['error'] = str(e)
        return results
    
    def _identify_target_type(self, target: str) -> str:
        """Identify if target is URL, IP, or domain"""
        if target.startswith(('http://', 'https://')):
            return 'url'
        elif self._is_ip_address(target):
            return 'ip'
        else:
            return 'domain'
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is a valid IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _gather_basic_info(self, target: str) -> Dict[str, Any]:
        """Gather basic information about the target"""
        info = {}
        
        try:
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                
                info['hostname'] = hostname
                info['port'] = port
                info['scheme'] = parsed.scheme
                info['path'] = parsed.path
                
                # Resolve IP
                if hostname is not None:
                    ip = socket.gethostbyname(hostname)
                    info['ip_address'] = ip
                else:
                    info['ip_address'] = None
                
            else:
                # Direct IP or domain
                hostname = target
                if not self._is_ip_address(target):
                    ip = socket.gethostbyname(hostname)
                    info['ip_address'] = ip
                    info['hostname'] = hostname
                else:
                    info['ip_address'] = target
                    # Try reverse DNS
                    try:
                        hostname = socket.gethostbyaddr(target)[0]
                        info['hostname'] = hostname
                    except:
                        info['hostname'] = target
            
            self.logger.debug(f"Basic info gathered: {info}")
            
        except Exception as e:
            self.logger.error(f"Failed to gather basic info: {str(e)}")
            info['error'] = str(e)
        
        return info
    
    def _dns_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Perform DNS reconnaissance"""
        dns_info = {}
        
        try:
            # Extract hostname from URL if needed
            if target.startswith(('http://', 'https://')):
                hostname = urlparse(target).hostname
            else:
                hostname = target if not self._is_ip_address(target) else None
            
            if not hostname:
                return {'error': 'No hostname to resolve'}
            
            # DNS record types to query
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    dns_info[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    dns_info[record_type] = []
            
            # Try to get WHOIS info (basic)
            dns_info['whois'] = self._basic_whois(hostname)
            
            self.logger.debug(f"DNS reconnaissance completed for {hostname}")
            
        except Exception as e:
            self.logger.error(f"DNS reconnaissance failed: {str(e)}")
            dns_info['error'] = str(e)
        
        return dns_info
    
    def _basic_whois(self, hostname: str) -> Dict[str, Any]:
        """Basic WHOIS information gathering"""
        # Placeholder for WHOIS implementation
        # In a real implementation, you would use a WHOIS library
        return {
            'registrar': 'Unknown',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'note': 'WHOIS implementation placeholder'
        }
    
    def _basic_port_scan(self, target: str) -> Dict[str, Any]:
        """Perform basic port scanning"""
        port_info = {
            'open_ports': [],
            'closed_ports': [],
            'scan_type': 'basic'
        }
        
        try:
            # Extract IP/hostname
            if target.startswith(('http://', 'https://')):
                hostname = urlparse(target).hostname or target
            else:
                hostname = target
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
            
            for port in common_ports:
                if self._is_port_open(hostname, port):
                    port_info['open_ports'].append(port)
                else:
                    port_info['closed_ports'].append(port)
            
            self.logger.debug(f"Port scan completed. Open ports: {port_info['open_ports']}")
            
        except Exception as e:
            self.logger.error(f"Port scanning failed: {str(e)}")
            port_info['error'] = str(e)
        
        return port_info
    
    def _is_port_open(self, hostname: str, port: int, timeout: int = 3) -> bool:
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((hostname, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _service_detection(self, target: str) -> Dict[str, Any]:
        """Detect services running on open ports"""
        services = {}
        
        try:
            # This would typically use nmap or similar tools
            # For now, we'll implement basic service detection
            
            # Extract hostname
            if target.startswith(('http://', 'https://')):
                hostname = urlparse(target).hostname
            else:
                hostname = target
            
            # Common service mappings
            service_map = {
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S',
                3306: 'MySQL',
                3389: 'RDP',
                5432: 'PostgreSQL'
            }
            
            # Check common ports and identify services
            if hostname is None:
                self.logger.warning("Hostname is None, skipping service detection.")
                return services

            for port, service in service_map.items():
                # Only call _is_port_open if hostname is not None
                if hostname is not None and self._is_port_open(hostname, port):
                    services[port] = {
                        'service': service,
                        'version': 'Unknown',
                        'banner': self._grab_banner(hostname, port)
                    }
            
            self.logger.debug(f"Service detection completed: {list(services.keys())}")
            
        except Exception as e:
            self.logger.error(f"Service detection failed: {str(e)}")
            services['error'] = str(e)
        
        return services
    
    def _grab_banner(self, hostname: str, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((hostname, port))
            
            # For HTTP/HTTPS, send a basic request
            if port in [80, 443, 8080]:
                request = b"HEAD / HTTP/1.1\\r\\nHost: " + hostname.encode() + b"\\r\\n\\r\\n"
                sock.send(request)
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner[:200]  # Limit banner length
            
        except:
            return "No banner available"
    
    def _web_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Perform web-specific reconnaissance"""
        web_info = {}
        
        try:
            if not target.startswith(('http://', 'https://')):
                # Try both HTTP and HTTPS
                test_urls = [f"http://{target}", f"https://{target}"]
            else:
                test_urls = [target]
            
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=10, verify=False)
                    
                    web_info[url] = {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'server': response.headers.get('Server', 'Unknown'),
                        'title': self._extract_title(response.text),
                        'technologies': self._detect_technologies(response)
                    }
                    
                    # Only check one successful URL
                    break
                    
                except requests.RequestException:
                    continue
            
            self.logger.debug("Web reconnaissance completed")
            
        except Exception as e:
            self.logger.error(f"Web reconnaissance failed: {str(e)}")
            web_info['error'] = str(e)
        
        return web_info
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return "No title found"
    
    def _detect_technologies(self, response) -> List[str]:
        """Detect web technologies from response"""
        technologies = []
        
        # Check headers for technology indicators
        headers = response.headers
        
        if 'X-Powered-By' in headers:
            technologies.append(f"Powered by: {headers['X-Powered-By']}")
        
        if 'Server' in headers:
            server = headers['Server']
            if 'Apache' in server:
                technologies.append('Apache')
            elif 'nginx' in server:
                technologies.append('nginx')
            elif 'IIS' in server:
                technologies.append('Microsoft IIS')
        
        # Check content for framework indicators
        content = response.text.lower()
        
        if 'wp-content' in content or 'wordpress' in content:
            technologies.append('WordPress')
        
        if 'joomla' in content:
            technologies.append('Joomla')
        
        if 'drupal' in content:
            technologies.append('Drupal')
        
        return technologies
    
    def _subdomain_enumeration(self, target: str) -> Dict[str, Any]:
        """Enumerate subdomains for the target"""
        subdomains = {
            'found_subdomains': [],
            'method': 'basic_wordlist'
        }
        
        try:
            # Extract base domain
            if target.startswith(('http://', 'https://')):
                base_domain = urlparse(target).hostname
            else:
                base_domain = target
            
            # Common subdomain prefixes
            common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop', 'secure']
            
            for sub in common_subs:
                subdomain = f"{sub}.{base_domain}"
                try:
                    socket.gethostbyname(subdomain)
                    subdomains['found_subdomains'].append(subdomain)
                except:
                    continue
            
            self.logger.debug(f"Subdomain enumeration found: {subdomains['found_subdomains']}")
            
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed: {str(e)}")
            subdomains['error'] = str(e)
        
        return subdomains
    
    def _os_detection(self, target: str) -> Dict[str, Any]:
        """Attempt basic OS detection"""
        os_info = {
            'detected_os': 'Unknown',
            'confidence': 'Low',
            'method': 'TTL analysis'
        }
        
        try:
            # Basic TTL-based OS detection
            # This is a simplified version - real tools use more sophisticated methods
            
            if target.startswith(('http://', 'https://')):
                hostname = urlparse(target).hostname
            else:
                hostname = target
            
            # Ping to get TTL (Windows implementation would differ)
            # This is a placeholder for OS detection logic
            os_info['note'] = 'OS detection requires more sophisticated tools like nmap'
            
        except Exception as e:
            self.logger.error(f"OS detection failed: {str(e)}")
            os_info['error'] = str(e)
        
        return os_info
    
    def _vulnerability_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Look for obvious vulnerability indicators during recon"""
        vuln_hints = {
            'potential_vulnerabilities': [],
            'security_headers': {},
            'certificate_info': {}
        }
        
        try:
            if target.startswith(('http://', 'https://')):
                url = target
            else:
                url = f"https://{target}"
            
            response = requests.get(url, timeout=10, verify=False)
            
            # Check security headers
            security_headers = [
                'X-Frame-Options',
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]
            
            for header in security_headers:
                vuln_hints['security_headers'][header] = response.headers.get(header, 'Missing')
            
            # Look for common vulnerability indicators
            if 'Missing' in vuln_hints['security_headers'].values():
                vuln_hints['potential_vulnerabilities'].append('Missing security headers')
            
            if response.headers.get('Server'):
                server = response.headers['Server']
                # Check for version disclosure
                if any(char.isdigit() for char in server):
                    vuln_hints['potential_vulnerabilities'].append('Server version disclosure')
            
            self.logger.debug("Vulnerability reconnaissance completed")
            
        except Exception as e:
            self.logger.error(f"Vulnerability reconnaissance failed: {str(e)}")
            vuln_hints['error'] = str(e)
        
        return vuln_hints
