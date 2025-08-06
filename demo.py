#!/usr/bin/env python3
"""
RedSentinel AI - Demo Script
Demonstrates basic functionality with safe targets.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.recon_engine import ReconEngine
from modules.ethical_safeguards import EthicalSafeguards
from utils.config import Config
from utils.logger import setup_logger

def run_demo():
    """Run a safe demonstration of RedSentinel AI"""
    
    print("""
╦═╗┌─┐┌┬┐╔═╗┌─┐┌┐┌┌┬┐┬┌┐┌┌─┐┬    ╔═╗╦
╠╦╝├┤  ││╚═╗├┤ │││ │ ││││├┤ │    ╠═╣║
╩╚═└─┘─┴┘╚═╝└─┘┘└┘ ┴ ┴┘└┘└─┘┴─┘  ╩ ╩╩
    AI-Powered Ethical Hacking Agent
           DEMO MODE
""")
    
    print("🔍 Running safe reconnaissance demo...")
    print("-" * 50)
    
    # Initialize components
    config = Config()
    logger = setup_logger()
    safeguards = EthicalSafeguards(config)
    recon_engine = ReconEngine(config)
    
    # Safe demo target
    demo_target = "example.com"
    
    print(f"Target: {demo_target}")
    print("Note: This is a safe demo using example.com")
    print()
    
    # Check if target is authorized
    if safeguards.is_target_authorized(demo_target):
        print("✅ Target authorized for testing")
    else:
        print("⚠️ Target not in whitelist (demo mode)")
    
    print()
    print("🔍 Starting basic reconnaissance...")
    
    try:
        # Run basic reconnaissance
        results = recon_engine.run_reconnaissance(demo_target, level='basic')
        
        print("📊 Reconnaissance Results:")
        print("-" * 30)
        
        # Display basic info
        if 'basic_info' in results['findings']:
            basic_info = results['findings']['basic_info']
            print(f"IP Address: {basic_info.get('ip_address', 'Unknown')}")
            print(f"Hostname: {basic_info.get('hostname', 'Unknown')}")
        
        # Display DNS info
        if 'dns_info' in results['findings']:
            dns_info = results['findings']['dns_info']
            if 'A' in dns_info and dns_info['A']:
                print(f"DNS A Records: {', '.join(dns_info['A'])}")
        
        # Display open ports
        if 'port_scan' in results['findings']:
            port_info = results['findings']['port_scan']
            open_ports = port_info.get('open_ports', [])
            if open_ports:
                print(f"Open Ports: {', '.join(map(str, open_ports))}")
            else:
                print("Open Ports: None detected (limited scan)")
        
        print()
        print("✅ Demo completed successfully!")
        print()
        print("💡 To run a full scan:")
        print("   python redsentinel.py --url https://yoursite.com --level standard")
        print()
        print("🛡️ Remember to only test authorized targets!")
        
    except Exception as e:
        print(f"❌ Demo failed: {str(e)}")
        print("This may be due to network connectivity or missing dependencies.")

if __name__ == "__main__":
    run_demo()
