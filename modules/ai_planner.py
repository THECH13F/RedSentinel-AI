"""
AI Planner Module
Handles AI-powered attack planning, CVE searching, payload generation, and exploitation guidance.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from google import genai
from datetime import datetime

class AIPlanner:
    """AI-powered attack planning and assistance using Gemini API"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.model = None
        self._initialize_ai()
    
    def _initialize_ai(self):
        """Initialize Gemini AI model"""
        try:
            api_key = self.config.get_api_key()
            if not api_key:
                self.logger.warning("No Gemini API key configured. AI features will be disabled.")
                return
            
            # Configure the genai client
            client = genai.Client(api_key=api_key)
            
            # Test the connection with a simple request
            response = client.models.generate_content(
                model="gemini-2.0-flash-exp", 
                contents="Test connection"
            )
            
            self.logger.info("Gemini AI model initialized successfully")
            self.model = client

        except Exception as e:
            self.logger.error(f"Failed to initialize AI model: {str(e)}")
            self.model = None
    
    def create_scan_plan(self, target: str, level: str, modules: Optional[List[str]] = None, 
                        tools: Optional[List[str]] = None) -> Dict[str, Any]:
        """Create an AI-generated scan plan based on target and requirements"""
        if not self.model:
            self.logger.warning("AI model not available, using default scan plan")
            return self._create_default_scan_plan(target, level, modules, tools)
        
        try:
            prompt = self._build_scan_plan_prompt(target, level, modules, tools)
            response = self.model.models.generate_content(
                model="gemini-2.0-flash-exp",
                contents=prompt
            )
            
            # Parse AI response and create structured plan
            plan = self._parse_scan_plan_response(response.text or "")
            
            self.logger.info(f"AI scan plan created for target: {target}")
            return plan
            
        except Exception as e:
            self.logger.error(f"AI scan planning failed: {str(e)}")
            return self._create_default_scan_plan(target, level, modules, tools)
    
    def _build_scan_plan_prompt(self, target: str, level: str, modules: Optional[List[str]], 
                               tools: Optional[List[str]]) -> str:
        """Build prompt for AI scan planning"""
        prompt = f"""
You are a cybersecurity expert planning an ethical penetration test for authorized target: {target}

Requirements:
- Scan level: {level}
- Target type: {'URL' if target.startswith('http') else 'IP address'}
- Requested modules: {modules or 'all available'}
- Requested tools: {tools or 'auto-select'}

Please create a comprehensive scan plan including:
1. Reconnaissance strategy
2. Vulnerability assessment approach
3. Tool selection and order of execution
4. Potential attack vectors to investigate
5. Risk assessment and precautions

Return response in JSON format with the following structure:
{{
    "reconnaissance": ["step1", "step2", ...],
    "vulnerability_assessment": ["tool1", "tool2", ...],
    "attack_vectors": ["vector1", "vector2", ...],
    "tool_sequence": [
        {{"tool": "nmap", "purpose": "port scanning", "priority": 1}},
        ...
    ],
    "risk_level": "low|medium|high",
    "precautions": ["precaution1", "precaution2", ...],
    "estimated_duration": "X minutes"
}}

Focus on ethical testing practices and provide detailed reasoning for tool selection.
"""
        return prompt
    
    def _parse_scan_plan_response(self, response: str) -> Dict[str, Any]:
        """Parse AI response and extract scan plan"""
        try:
            # Try to extract JSON from the response
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)
            else:
                # Fallback: create structured plan from text
                return self._extract_plan_from_text(response)
                
        except json.JSONDecodeError:
            self.logger.warning("Failed to parse AI response as JSON, using text extraction")
            return self._extract_plan_from_text(response)
    
    def _extract_plan_from_text(self, text: str) -> Dict[str, Any]:
        """Extract scan plan from unstructured text response"""
        # Basic text parsing to create a structured plan
        return {
            "reconnaissance": ["DNS enumeration", "Port scanning", "Service detection"],
            "vulnerability_assessment": ["nmap", "nikto", "sqlmap"],
            "attack_vectors": ["Web application vulnerabilities", "Network services"],
            "tool_sequence": [
                {"tool": "nmap", "purpose": "port scanning", "priority": 1},
                {"tool": "nikto", "purpose": "web vulnerability scan", "priority": 2}
            ],
            "risk_level": "medium",
            "precautions": ["Ensure target authorization", "Rate limit requests"],
            "estimated_duration": "30-60 minutes",
            "ai_notes": text[:500]  # Include truncated AI response
        }
    
    def _create_default_scan_plan(self, target: str, level: str, modules: Optional[List[str]], 
                                 tools: Optional[List[str]]) -> Dict[str, Any]:
        """Create a default scan plan when AI is not available"""
        plans = {
            'basic': {
                "reconnaissance": ["DNS lookup", "Basic port scan"],
                "vulnerability_assessment": ["nmap"],
                "tool_sequence": [
                    {"tool": "nmap", "purpose": "port scanning", "priority": 1}
                ],
                "estimated_duration": "10-15 minutes"
            },
            'standard': {
                "reconnaissance": ["DNS enumeration", "Port scanning", "Service detection"],
                "vulnerability_assessment": ["nmap", "nikto"],
                "tool_sequence": [
                    {"tool": "nmap", "purpose": "comprehensive port scan", "priority": 1},
                    {"tool": "nikto", "purpose": "web vulnerability scan", "priority": 2}
                ],
                "estimated_duration": "20-30 minutes"
            },
            'deep': {
                "reconnaissance": ["Comprehensive DNS", "Full port scan", "Service enumeration", "OS detection"],
                "vulnerability_assessment": ["nmap", "nikto", "sqlmap", "wpscan"],
                "tool_sequence": [
                    {"tool": "nmap", "purpose": "aggressive scan", "priority": 1},
                    {"tool": "nikto", "purpose": "web vulnerability scan", "priority": 2},
                    {"tool": "sqlmap", "purpose": "SQL injection testing", "priority": 3},
                    {"tool": "wpscan", "purpose": "WordPress security scan", "priority": 4}
                ],
                "estimated_duration": "45-90 minutes"
            }
        }
        
        plan = plans.get(level, plans['standard'])
        plan.update({
            "target": target,
            "level": level,
            "risk_level": "medium",
            "precautions": ["Verify target authorization", "Monitor for rate limiting"],
            "attack_vectors": ["Web application vulnerabilities", "Network service exploits"]
        })
        
        return plan
    
    def search_cves(self, service: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search for CVEs related to a specific service/software"""
        if not self.model:
            self.logger.warning("AI model not available for CVE search")
            return []
        
        try:
            prompt = f"""
Search for known CVEs (Common Vulnerabilities and Exposures) for:
Service: {service}
Version: {version or 'any version'}

Please provide:
1. CVE IDs
2. Severity scores (CVSS)
3. Brief descriptions
4. Potential exploit availability
5. Mitigation recommendations

Format as JSON array of CVE objects.
"""
            
            response = self.model.models.generate_content(
                model="gemini-2.0-flash-exp",
                contents=prompt
            )
            # Parse and return CVE information
            return self._parse_cve_response(response.text or "")
            
        except Exception as e:
            self.logger.error(f"CVE search failed: {str(e)}")
            return []
    
    def generate_payload(self, vulnerability_type: str, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate custom payloads for specific vulnerabilities"""
        if not self.model:
            self.logger.warning("AI model not available for payload generation")
            return {}
        
        try:
            prompt = f"""
Generate a custom payload for:
Vulnerability Type: {vulnerability_type}
Target Information: {json.dumps(target_info, indent=2)}

Please provide:
1. Payload code/command
2. Explanation of how it works
3. Potential impact
4. Detection evasion techniques
5. Cleanup commands (if applicable)

IMPORTANT: This is for authorized ethical testing only. Include appropriate warnings.

Format as JSON with clear structure.
"""
            
            response = self.model.models.generate_content(
                model="gemini-2.0-flash-exp",
                contents=prompt
            )
            return self._parse_payload_response(response.text or "")
            
        except Exception as e:
            self.logger.error(f"Payload generation failed: {str(e)}")
            return {}
    
    def run_exploitation(self, target: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """AI-guided exploitation phase"""
        if not self.model:
            self.logger.warning("AI model not available for exploitation guidance")
            return {"status": "skipped", "reason": "AI not available"}
        
        if not vulnerabilities:
            return {"status": "skipped", "reason": "No vulnerabilities found"}
        
        try:
            prompt = f"""
You are an ethical hacking expert analyzing vulnerabilities for authorized target: {target}

Vulnerabilities found:
{json.dumps(vulnerabilities, indent=2)}

Please provide:
1. Exploitation priority ranking
2. Step-by-step exploitation approaches
3. Risk assessment for each exploit
4. Post-exploitation recommendations
5. Evidence collection strategies

Focus on safe, ethical testing practices. Include warnings about potential impact.

Format response as JSON with structured exploitation plan.
"""
            
            response = self.model.models.generate_content(
                model="gemini-2.0-flash-exp",
                contents=prompt
            )
            return self._parse_exploitation_response(response.text or "")
            
        except Exception as e:
            self.logger.error(f"AI exploitation guidance failed: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def _parse_cve_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse CVE search response"""
        try:
            # Extract JSON from response
            start_idx = response.find('[')
            end_idx = response.rfind(']') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)
        except:
            pass
        
        # Fallback to empty list
        return []
    
    def _parse_payload_response(self, response: str) -> Dict[str, Any]:
        """Parse payload generation response"""
        try:
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)
        except:
            pass
        
        return {"payload": "# AI payload generation failed", "warning": "Manual testing required"}
    
    def _parse_exploitation_response(self, response: str) -> Dict[str, Any]:
        """Parse exploitation guidance response"""
        try:
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)
        except:
            pass
        
        return {
            "status": "completed",
            "exploitation_plan": response[:1000],  # Include truncated response
            "timestamp": datetime.now().isoformat()
        }
