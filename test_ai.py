#!/usr/bin/env python3
"""
Test script for AI Planner functionality
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_ai_planner():
    """Test AI planner import and basic functionality"""
    
    try:
        from modules.ai_planner import AIPlanner
        from utils.config import Config
        
        print("✅ AI Planner import successful")
        
        # Create config and planner
        config = Config()
        planner = AIPlanner(config)
        
        print("✅ AI Planner initialization successful")
        
        # Test default scan plan (doesn't require API key)
        plan = planner._create_default_scan_plan(
            target="example.com", 
            level="basic", 
            modules=None, 
            tools=None
        )
        
        print("✅ Default scan plan creation successful")
        print(f"Plan contains {len(plan)} elements")
        print(f"Reconnaissance steps: {len(plan.get('reconnaissance', []))}")
        print(f"Tool sequence: {len(plan.get('tool_sequence', []))}")
        
        # Test with API key if available
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            print(f"🔑 API key found, testing AI features...")
            config.set_api_key(api_key)
            planner_with_ai = AIPlanner(config)
            
            if planner_with_ai.model:
                print("✅ AI model initialized successfully")
                
                # Test AI scan plan
                ai_plan = planner_with_ai.create_scan_plan(
                    target="example.com",
                    level="basic",
                    modules=["recon"],
                    tools=["nmap"]
                )
                print("✅ AI scan plan created successfully")
            else:
                print("⚠️ AI model failed to initialize")
        else:
            print("ℹ️ No API key found (set GEMINI_API_KEY to test AI features)")
        
        print("\n🎉 All AI Planner tests passed!")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure google-genai is installed: pip install google-genai")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ai_planner()
