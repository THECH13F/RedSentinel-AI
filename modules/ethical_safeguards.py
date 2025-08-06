"""
Ethical Safeguards Module
Implements safety measures including scope whitelisting, confirmation prompts, and reporting-only mode.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
import ipaddress
from urllib.parse import urlparse

class EthicalSafeguards:
    """Implements ethical hacking safeguards and constraints"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.whitelist_file = config.get('whitelist_file', 'config/authorized_targets.json')
        self.authorized_targets = self._load_authorized_targets()
    
    def _load_authorized_targets(self) -> Dict[str, Any]:
        """Load authorized targets from configuration"""
        targets = {
            'domains': [],
            'ip_ranges': [],
            'urls': [],
            'explicitly_authorized': []
        }
        
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    loaded_targets = json.load(f)
                    targets.update(loaded_targets)
                self.logger.info(f"Loaded {len(targets.get('domains', []))} authorized domains")
            else:
                self.logger.warning(f"Whitelist file not found: {self.whitelist_file}")
                # Create default whitelist file
                self._create_default_whitelist()
        
        except Exception as e:
            self.logger.error(f"Failed to load authorized targets: {str(e)}")
        
        return targets
    
    def _create_default_whitelist(self):
        """Create default authorized targets file"""
        try:
            os.makedirs(os.path.dirname(self.whitelist_file), exist_ok=True)
            
            default_targets = {
                "domains": [
                    "example.com",
                    "testphp.vulnweb.com",
                    "demo.testfire.net"
                ],
                "ip_ranges": [
                    "192.168.0.0/16",
                    "10.0.0.0/8",
                    "172.16.0.0/12"
                ],
                "urls": [
                    "http://testphp.vulnweb.com/",
                    "http://demo.testfire.net/"
                ],
                "explicitly_authorized": [],
                "_note": "Add your authorized targets here. Only test targets you own or have explicit permission to test."
            }
            
            with open(self.whitelist_file, 'w') as f:
                json.dump(default_targets, f, indent=2)
            
            self.logger.info(f"Created default whitelist at: {self.whitelist_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to create default whitelist: {str(e)}")
    
    def is_target_authorized(self, target: str) -> bool:
        """Check if target is authorized for testing"""
        if not target:
            return False
        
        try:
            # Check explicitly authorized targets first
            if target in self.authorized_targets.get('explicitly_authorized', []):
                self.logger.info(f"Target explicitly authorized: {target}")
                return True
            
            # Parse target to determine type
            if target.startswith(('http://', 'https://')):
                return self._is_url_authorized(target)
            elif self._is_ip_address(target):
                return self._is_ip_authorized(target)
            else:
                return self._is_domain_authorized(target)
        
        except Exception as e:
            self.logger.error(f"Error checking target authorization: {str(e)}")
            return False
    
    def _is_url_authorized(self, url: str) -> bool:
        """Check if URL is authorized"""
        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            
            # Check exact URL match
            if url in self.authorized_targets.get('urls', []):
                return True
            
            # Check domain authorization
            if domain:
                return self._is_domain_authorized(domain)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error parsing URL {url}: {str(e)}")
            return False
    
    def _is_domain_authorized(self, domain: str) -> bool:
        """Check if domain is authorized"""
        authorized_domains = self.authorized_targets.get('domains', [])
        
        # Exact match
        if domain in authorized_domains:
            return True
        
        # Subdomain match
        for auth_domain in authorized_domains:
            if domain.endswith(f".{auth_domain}"):
                return True
        
        # Check if it's a local/private domain
        if self._is_local_domain(domain):
            return True
        
        return False
    
    def _is_ip_authorized(self, ip: str) -> bool:
        """Check if IP address is authorized"""
        try:
            target_ip = ipaddress.ip_address(ip)
            
            # Check against authorized IP ranges
            for ip_range in self.authorized_targets.get('ip_ranges', []):
                if target_ip in ipaddress.ip_network(ip_range, strict=False):
                    return True
            
            # Check if it's a private IP
            if target_ip.is_private:
                return True
            
            return False
            
        except ValueError as e:
            self.logger.error(f"Invalid IP address {ip}: {str(e)}")
            return False
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _is_local_domain(self, domain: str) -> bool:
        """Check if domain is local/private"""
        local_domains = [
            'localhost',
            '127.0.0.1',
            '.local',
            '.test',
            '.example',
            '.invalid'
        ]
        
        return any(domain.endswith(local) or domain == local.lstrip('.') for local in local_domains)
    
    def display_ethical_warning(self):
        """Display ethical use warning"""
        warning = """
╔══════════════════════════════════════════════════════════════╗
║                     ⚠️  ETHICAL USE WARNING ⚠️                 ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  RedSentinel AI is designed for AUTHORIZED TESTING ONLY     ║
║                                                              ║
║  ✅ AUTHORIZED USE:                                          ║
║  • Your own systems and networks                            ║
║  • Systems with explicit written permission                 ║
║  • CTF (Capture The Flag) competitions                      ║
║  • Bug bounty programs with valid scope                     ║
║  • Authorized penetration testing engagements               ║
║                                                              ║
║  ❌ UNAUTHORIZED USE IS ILLEGAL AND UNETHICAL:              ║
║  • Testing systems without permission                       ║
║  • Malicious attacks or unauthorized access                 ║
║  • Any illegal or harmful activities                        ║
║                                                              ║
║  📋 RESPONSIBILITY:                                          ║
║  • User is responsible for ensuring proper authorization    ║
║  • User must comply with all applicable laws                ║
║  • User must respect system owners and operators            ║
║                                                              ║
║  🔒 SAFEGUARDS:                                              ║
║  • Target whitelist verification                            ║
║  • Rate limiting and respectful scanning                    ║
║  • Reporting-only mode available                            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(warning)
        
        # Prompt for confirmation
        response = input("Do you confirm you have authorization to test the specified target? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("❌ Testing aborted. Only test authorized targets.")
            exit(1)
        
        print("✅ Ethical use confirmed. Proceeding with authorized testing...")
        print("-" * 70)
    
    def add_authorized_target(self, target: str, target_type: str = 'auto') -> bool:
        """Add target to authorized list"""
        try:
            if target_type == 'auto':
                if target.startswith(('http://', 'https://')):
                    target_type = 'urls'
                elif self._is_ip_address(target):
                    target_type = 'ip_ranges'
                else:
                    target_type = 'domains'
            
            if target_type not in self.authorized_targets:
                self.authorized_targets[target_type] = []
            
            if target not in self.authorized_targets[target_type]:
                self.authorized_targets[target_type].append(target)
                self._save_authorized_targets()
                self.logger.info(f"Added authorized target: {target} ({target_type})")
                return True
            else:
                self.logger.info(f"Target already authorized: {target}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to add authorized target: {str(e)}")
            return False
    
    def remove_authorized_target(self, target: str) -> bool:
        """Remove target from authorized list"""
        try:
            removed = False
            
            for target_type in self.authorized_targets:
                if target in self.authorized_targets[target_type]:
                    self.authorized_targets[target_type].remove(target)
                    removed = True
                    break
            
            if removed:
                self._save_authorized_targets()
                self.logger.info(f"Removed authorized target: {target}")
                return True
            else:
                self.logger.warning(f"Target not found in authorized list: {target}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to remove authorized target: {str(e)}")
            return False
    
    def _save_authorized_targets(self):
        """Save authorized targets to file"""
        try:
            with open(self.whitelist_file, 'w') as f:
                json.dump(self.authorized_targets, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save authorized targets: {str(e)}")
    
    def list_authorized_targets(self) -> Dict[str, List[str]]:
        """Get list of all authorized targets"""
        return self.authorized_targets.copy()
    
    def validate_scan_parameters(self, target: str, level: str, modules: List[str]) -> Dict[str, Any]:
        """Validate scan parameters for ethical constraints"""
        validation = {
            'authorized': False,
            'warnings': [],
            'recommendations': []
        }
        
        # Check target authorization
        if not self.is_target_authorized(target):
            validation['warnings'].append(f"Target {target} is not in authorized list")
            validation['recommendations'].append("Add target to authorized list or verify permission")
        else:
            validation['authorized'] = True
        
        # Check scan intensity
        if level == 'deep':
            validation['warnings'].append("Deep scan level may generate significant traffic")
            validation['recommendations'].append("Ensure target can handle intensive scanning")
        
        # Check modules for potentially risky operations
        risky_modules = ['exploit', 'browser']
        for module in modules:
            if module in risky_modules:
                validation['warnings'].append(f"Module '{module}' performs active testing")
                validation['recommendations'].append(f"Ensure explicit permission for {module} testing")
        
        return validation
    
    def get_rate_limit_config(self, target: str) -> Dict[str, int]:
        """Get rate limiting configuration based on target"""
        # Default conservative rate limits
        config = {
            'requests_per_second': 2,
            'concurrent_requests': 1,
            'delay_between_tools': 5
        }
        
        # Adjust for local/private targets
        if self._is_local_target(target):
            config.update({
                'requests_per_second': 5,
                'concurrent_requests': 3,
                'delay_between_tools': 2
            })
        
        return config
    
    def _is_local_target(self, target: str) -> bool:
        """Check if target is local/private"""
        try:
            if target.startswith(('http://', 'https://')):
                hostname = urlparse(target).hostname
            else:
                hostname = target
            
            if hostname is not None and self._is_ip_address(hostname):
                ip = ipaddress.ip_address(hostname)
                return ip.is_private or ip.is_loopback
            else:
                return self._is_local_domain(hostname) if hostname is not None else False
                
        except Exception:
            return False
    
    def create_scan_consent_record(self, target: str, scan_config: Dict[str, Any]) -> str:
        """Create a record of scan consent and configuration"""
        record = {
            'target': target,
            'timestamp': f"{os.getpid()}_{int(os.urandom(4).hex(), 16)}",
            'scan_config': scan_config,
            'authorization_confirmed': True,
            'ethical_guidelines_acknowledged': True
        }
        
        # Save consent record
        consent_dir = 'logs/consent_records'
        os.makedirs(consent_dir, exist_ok=True)
        
        record_file = os.path.join(consent_dir, f"consent_{record['timestamp']}.json")
        
        try:
            with open(record_file, 'w') as f:
                json.dump(record, f, indent=2)
            
            self.logger.info(f"Scan consent record created: {record_file}")
            return record_file
            
        except Exception as e:
            self.logger.error(f"Failed to create consent record: {str(e)}")
            return ""
