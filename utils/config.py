"""
Configuration Management Module
Handles loading and managing configuration settings for RedSentinel AI.
"""

import json
import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path

class Config:
    """Configuration manager for RedSentinel AI"""
    
    def __init__(self, config_file: str = 'config/config.json'):
        self.config_file = config_file
        self.config_data = {}
        self.logger = logging.getLogger(__name__)
        self._load_default_config()
        
        # Try to load user config
        if os.path.exists(config_file):
            self.load_from_file(config_file)
        else:
            self._create_default_config_file()
    
    def _load_default_config(self):
        """Load default configuration values"""
        self.config_data = {
            'api': {
                'gemini_api_key': '',
                'timeout': 30,
                'max_retries': 3
            },
            'scanning': {
                'default_level': 'standard',
                'default_ai_mode': 'assist',
                'rate_limit': {
                    'requests_per_second': 2,
                    'concurrent_requests': 1
                },
                'timeouts': {
                    'nmap': 300,
                    'nikto': 600,
                    'sqlmap': 1800,
                    'browser_test': 120
                }
            },
            'output': {
                'default_format': 'html',
                'output_directory': './reports',
                'include_screenshots': False
            },
            'ethical': {
                'whitelist_file': 'config/authorized_targets.json',
                'require_confirmation': True,
                'auto_report_mode': False
            },
            'tools': {
                'nmap_path': 'nmap',
                'sqlmap_path': 'sqlmap',
                'nikto_path': 'nikto',
                'wpscan_path': 'wpscan',
                'gobuster_path': 'gobuster'
            },
            'browser': {
                'headless': True,
                'timeout': 30000,
                'viewport': {
                    'width': 1280,
                    'height': 720
                },
                'user_agent': 'RedSentinel-BrowserAgent/1.0'
            }
        }
    
    def _create_default_config_file(self):
        """Create default configuration file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config_data, f, indent=2)
            
            self.logger.info(f"Created default configuration file: {self.config_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to create config file: {str(e)}")
    
    def load_from_file(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
            
            # Merge with default config
            self._merge_config(self.config_data, user_config)
            self.logger.info(f"Configuration loaded from: {config_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to load config from {config_file}: {str(e)}")
    
    def _merge_config(self, default: Dict[str, Any], user: Dict[str, Any]):
        """Recursively merge user config with default config"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'api.timeout')"""
        keys = key_path.split('.')
        value = self.config_data
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config = self.config_data
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
    
    def get_api_key(self) -> Optional[str]:
        """Get Gemini API key"""
        # Check environment variable first
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            return api_key
        
        # Check config file
        return self.get('api.gemini_api_key')
    
    def set_api_key(self, api_key: str):
        """Set Gemini API key"""
        self.set('api.gemini_api_key', api_key)
    
    def get_tool_path(self, tool_name: str) -> str:
        """Get path for security tool"""
        return self.get(f'tools.{tool_name}_path', tool_name)
    
    def get_rate_limit_config(self) -> Dict[str, int]:
        """Get rate limiting configuration"""
        return self.get('scanning.rate_limit', {
            'requests_per_second': 2,
            'concurrent_requests': 1
        })
    
    def get_timeout(self, tool_name: str) -> int:
        """Get timeout for specific tool"""
        return self.get(f'scanning.timeouts.{tool_name}', 300)
    
    def is_headless_mode(self) -> bool:
        """Check if browser should run in headless mode"""
        return self.get('browser.headless', True)
    
    def get_browser_config(self) -> Dict[str, Any]:
        """Get browser configuration"""
        return self.get('browser', {
            'headless': True,
            'timeout': 30000,
            'viewport': {'width': 1280, 'height': 720},
            'user_agent': 'RedSentinel-BrowserAgent/1.0'
        })
    
    def should_require_confirmation(self) -> bool:
        """Check if confirmation prompts are required"""
        return self.get('ethical.require_confirmation', True)
    
    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration"""
        return self.get('output', {
            'default_format': 'html',
            'output_directory': './reports',
            'include_screenshots': False
        })
    
    def save_to_file(self, config_file: Optional[str] = None):
        """Save current configuration to file"""
        file_path = config_file or self.config_file
        
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                json.dump(self.config_data, f, indent=2)
            
            self.logger.info(f"Configuration saved to: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save config to {file_path}: {str(e)}")
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate configuration and return status"""
        validation = {
            'valid': True,
            'warnings': [],
            'errors': []
        }
        
        # Check API key
        if not self.get_api_key():
            validation['warnings'].append("No Gemini API key configured (AI features will be disabled)")
        
        # Check output directory
        output_dir = self.get('output.output_directory', './reports')
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            validation['errors'].append(f"Cannot create output directory: {str(e)}")
            validation['valid'] = False
        
        # Check tool paths
        tools = ['nmap', 'sqlmap', 'nikto', 'wpscan', 'gobuster']
        for tool in tools:
            tool_path = self.get_tool_path(tool)
            # Note: We won't check if tools exist here as they might not be installed
            # This is just for configuration validation
        
        return validation
    
    def get_all_config(self) -> Dict[str, Any]:
        """Get complete configuration (copy)"""
        return self.config_data.copy()
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self._load_default_config()
        self.logger.info("Configuration reset to defaults")
