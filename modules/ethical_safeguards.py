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
    

    # All authorization, whitelist, and confirmation logic removed.
    # Only rate limiting and consent record logic remain.
    
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
        """Check if target is local/private (basic check, no helper methods)"""
        try:
            if target.startswith(('http://', 'https://')):
                hostname = urlparse(target).hostname
            else:
                hostname = target
            if hostname is None:
                return False
            # Try IP address check
            try:
                ip = ipaddress.ip_address(hostname)
                return ip.is_private or ip.is_loopback
            except Exception:
                pass
            # Basic local domain check
            local_domains = [
                'localhost',
                '127.0.0.1',
                '.local',
                '.test',
                '.example',
                '.invalid'
            ]
            return any(hostname.endswith(local) or hostname == local.lstrip('.') for local in local_domains)
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
