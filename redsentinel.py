#!/usr/bin/env python3
"""
RedSentinel AI - Ethical Hacking Security Agent
Author: RedSentinel AI Team
Version: 1.0.2

AI-powered offensive security tool for ethical hacking and cybersecurity research.
"""

import argparse
import sys
import os
import json
from pathlib import Path
from typing import Dict, List, Optional
import logging
from datetime import datetime

# Import modules (will be created)
from modules.ai_planner import AIPlanner
from modules.recon_engine import ReconEngine
from modules.tool_runner import ToolRunner
from modules.browser_agent import BrowserAgent
from modules.report_generator import ReportGenerator
from modules.ethical_safeguards import EthicalSafeguards
from utils.logger import setup_logger
from utils.config import Config

class RedSentinelCLI:
    """Main CLI class for RedSentinel AI"""
    
    def __init__(self):
        self.config = Config()
        self.logger = setup_logger()
        self.ai_planner = AIPlanner(self.config)
        self.recon_engine = ReconEngine(self.config)
        self.tool_runner = ToolRunner(self.config)
        self.browser_agent = BrowserAgent(self.config)
        self.report_generator = ReportGenerator(self.config)
        self.ethical_safeguards = EthicalSafeguards(self.config)
        
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="RedSentinel AI - Ethical Hacking Security Agent",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  redsentinel --url https://example.com --level deep --ai-mode smart
  redsentinel --ip 192.168.1.1 --level basic --report-only
  redsentinel --config-file custom_config.json --wordlist custom.txt
  redsentinel --list-tools
            """
        )
        
        # Target specification
        target_group = parser.add_mutually_exclusive_group(required=False)
        target_group.add_argument(
            '--url', 
            type=str, 
            help='Target URL to scan (e.g., https://example.com)'
        )
        target_group.add_argument(
            '--ip', 
            type=str, 
            help='Target IP address to scan'
        )
        target_group.add_argument(
            '--target-file', 
            type=str, 
            help='File containing list of targets'
        )
        
        # Scan configuration
        parser.add_argument(
            '--level', 
            choices=['basic', 'standard', 'deep', 'custom'], 
            default='standard',
            help='Scan intensity level (default: standard)'
        )
        
        parser.add_argument(
            '--ai-mode', 
            choices=['off', 'assist', 'smart', 'autonomous'], 
            default='assist',
            help='AI assistance level (default: assist)'
        )
        
        # Module selection
        parser.add_argument(
            '--modules', 
            nargs='+', 
            choices=['recon', 'vuln-scan', 'web-scan', 'exploit', 'browser'], 
            help='Specific modules to run'
        )
        
        # Tool configuration
        parser.add_argument(
            '--tools', 
            nargs='+', 
            help='Specific tools to use (nmap, sqlmap, nikto, etc.)'
        )
        
        parser.add_argument(
            '--wordlist', 
            type=str, 
            help='Custom wordlist file for fuzzing/bruteforce'
        )
        
        # Output and reporting
        parser.add_argument(
            '--output-dir', 
            type=str, 
            default='./reports',
            help='Output directory for reports (default: ./reports)'
        )
        
        parser.add_argument(
            '--report-format', 
            choices=['json', 'html', 'pdf', 'all'], 
            default='html',
            help='Report format (default: html)'
        )
        
        # Ethical and safety options
        parser.add_argument(
            '--report-only', 
            action='store_true',
            help='Only perform reconnaissance and reporting (no exploitation)'
        )
        
        parser.add_argument(
            '--whitelist', 
            type=str, 
            help='File containing whitelisted targets'
        )
        
        parser.add_argument(
            '--confirm', 
            action='store_true',
            help='Require confirmation before running potentially dangerous tools'
        )
        
        # Configuration
        parser.add_argument(
            '--config-file', 
            type=str, 
            default='config/config.json',
            help='Configuration file path'
        )
        
        parser.add_argument(
            '--api-key', 
            type=str, 
            help='Gemini API key (overrides config file)'
        )
        
        # Utility options
        parser.add_argument(
            '--list-tools', 
            action='store_true',
            help='List all available tools and exit'
        )
        
        parser.add_argument(
            '--version', 
            action='version', 
            version='RedSentinel AI v1.0.2'
        )
        
        parser.add_argument(
            '--verbose', '-v', 
            action='count', 
            default=0,
            help='Increase verbosity (-v, -vv, -vvv)'
        )
        
        parser.add_argument(
            '--debug', 
            action='store_true',
            help='Enable debug mode'
        )
        
        return parser.parse_args()
    
    def validate_target(self, args: argparse.Namespace) -> bool:
        """Validate target specification (authorization checks removed)"""
        if not any([args.url, args.ip, args.target_file, args.list_tools]):
            self.logger.error("No target specified. Use --url, --ip, --target-file, or --list-tools")
            return False
        return True
    
    def setup_logging(self, args: argparse.Namespace):
        """Configure logging: always verbose by default"""
        logging.getLogger().setLevel(logging.INFO)
        if args.debug or args.verbose >= 3:
            logging.getLogger().setLevel(logging.DEBUG)
    
    def run_scan(self, args: argparse.Namespace) -> Dict:
        """Main scan execution logic (fully verbose, all actions and payloads shown)"""
        results = {
            'target': args.url or args.ip,
            'scan_level': args.level,
            'ai_mode': args.ai_mode,
            'timestamp': datetime.now().isoformat(),
            'modules_run': [],
            'findings': []
        }
        try:
            # Phase 1: AI Planning
            if args.ai_mode != 'off':
                self.logger.info("[RedSentinel] Starting AI-powered attack planning...")
                scan_plan = self.ai_planner.create_scan_plan(
                    target=args.url or args.ip,
                    level=args.level,
                    modules=args.modules,
                    tools=args.tools
                )
                self.logger.info(f"[RedSentinel] AI scan plan generated: {json.dumps(scan_plan, indent=2)}")
                results['scan_plan'] = scan_plan
            # Phase 2: Reconnaissance
            if not args.modules or 'recon' in args.modules:
                self.logger.info("[RedSentinel] Starting reconnaissance phase...")
                recon_results = self.recon_engine.run_reconnaissance(
                    target=args.url or args.ip,
                    level=args.level
                )
                self.logger.info(f"[RedSentinel] Reconnaissance results: {json.dumps(recon_results, indent=2)}")
                results['recon'] = recon_results
                results['modules_run'].append('recon')
            # Phase 3: Vulnerability Scanning
            if not args.modules or 'vuln-scan' in args.modules:
                if not args.report_only:
                    self.logger.info("[RedSentinel] Starting vulnerability scanning...")
                    vuln_results = self.tool_runner.run_vulnerability_scan(
                        target=args.url or args.ip,
                        tools=args.tools
                    )
                    self.logger.info(f"[RedSentinel] Vulnerability scan results: {json.dumps(vuln_results, indent=2)}")
                    results['vulnerabilities'] = vuln_results
                    results['modules_run'].append('vuln-scan')
            # Phase 4: Web Application Testing
            if not args.modules or 'web-scan' in args.modules:
                if args.url and not args.report_only:
                    self.logger.info("[RedSentinel] Starting web application testing...")
                    web_results = self.tool_runner.run_web_scan(
                        url=args.url,
                        wordlist=args.wordlist
                    )
                    self.logger.info(f"[RedSentinel] Web scan results: {json.dumps(web_results, indent=2)}")
                    results['web_testing'] = web_results
                    results['modules_run'].append('web-scan')
            # Phase 5: Browser-based Testing
            if not args.modules or 'browser' in args.modules:
                if args.url and not args.report_only:
                    self.logger.info("[RedSentinel] Starting browser-based testing...")
                    browser_results = self.browser_agent.run_browser_tests(
                        url=args.url
                    )
                    self.logger.info(f"[RedSentinel] Browser testing results: {json.dumps(browser_results, indent=2)}")
                    results['browser_testing'] = browser_results
                    results['modules_run'].append('browser')
            # Phase 6: AI-Guided Exploitation (if not report-only)
            if not args.modules or 'exploit' in args.modules:
                if not args.report_only and args.ai_mode in ['smart', 'autonomous']:
                    if args.confirm:
                        confirm = input("Proceed with exploitation phase? (y/N): ")
                        if confirm.lower() != 'y':
                            self.logger.info("[RedSentinel] Exploitation phase skipped by user")
                            return results
                    self.logger.info("[RedSentinel] Starting AI-guided exploitation...")
                    exploit_results = self.ai_planner.run_exploitation(
                        target=args.url or args.ip,
                        vulnerabilities=results.get('vulnerabilities', [])
                    )
                    self.logger.info(f"[RedSentinel] Exploitation results: {json.dumps(exploit_results, indent=2)}")
                    results['exploitation'] = exploit_results
                    results['modules_run'].append('exploit')
            return results
        except KeyboardInterrupt:
            self.logger.warning("[RedSentinel] Scan interrupted by user")
            return results
        except Exception as e:
            self.logger.error(f"[RedSentinel] Scan failed: {str(e)}")
            if args.debug:
                raise
            return results
    
    def main(self):
        """Main entry point (authorization checks and ethical warning removed)"""
        args = None
        try:
            # Parse arguments
            args = self.parse_arguments()
            # Setup logging (always verbose)
            self.setup_logging(args)
            # Handle utility commands
            if args.list_tools:
                self.tool_runner.list_available_tools()
                return 0
            # Validate target (authorization checks removed)
            if not self.validate_target(args):
                return 1
            # Load configuration
            if args.config_file and os.path.exists(args.config_file):
                self.config.load_from_file(args.config_file)
            # Override API key if provided
            if args.api_key:
                self.config.set_api_key(args.api_key)
            # Display banner
            self.display_banner()
            # Run scan
            self.logger.info("Starting RedSentinel AI scan...")
            results = self.run_scan(args)
            # Generate reports
            if results:
                self.logger.info("Generating reports...")
                self.report_generator.generate_report(
                    results=results,
                    output_dir=args.output_dir,
                    format=args.report_format
                )
            self.logger.info("Scan completed successfully!")
            return 0
        except Exception as e:
            self.logger.error(f"Fatal error: {str(e)}")
            if args is not None and hasattr(args, 'debug') and args.debug:
                raise
            return 1
    
    def display_banner(self):
        """Display ASCII art banner"""
        banner = """
╦═╗┌─┐┌┬┐╔═╗┌─┐┌┐┌┌┬┐┬┌┐┌┌─┐┬    ╔═╗╦
╠╦╝├┤  ││╚═╗├┤ │││ │ ││││├┤ │    ╠═╣║
╩╚═└─┘─┴┘╚═╝└─┘┘└┘ ┴ ┴┘└┘└─┘┴─┘  ╩ ╩╩
    AI-Powered Ethical Hacking Agent
        """
        print(banner)
        print("Version 1.0.2 | All actions and payloads are shown to the user.")
        print("-" * 50)

if __name__ == "__main__":
    cli = RedSentinelCLI()
    sys.exit(cli.main())
