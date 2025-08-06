"""
Browser Agent Module
Handles browser-based testing using Puppeteer/Playwright for XSS, CSRF, and client-side testing.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import tempfile
import os

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class BrowserAgent:
    """Browser-based security testing agent"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.playwright_available = PLAYWRIGHT_AVAILABLE
        
        if not self.playwright_available:
            self.logger.warning("Playwright not available. Install with: pip install playwright")
    
    def run_browser_tests(self, url: str) -> Dict[str, Any]:
        """Run comprehensive browser-based security tests"""
        if not self.playwright_available:
            return {
                'error': 'Playwright not installed',
                'message': 'Install with: pip install playwright && playwright install'
            }
        
        results = {
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'tests_run': [],
            'vulnerabilities': []
        }
        
        try:
            # Run async browser tests
            asyncio.run(self._run_async_tests(url, results))
            
            self.logger.info(f"Browser testing completed. Found {len(results['vulnerabilities'])} issues.")
            
        except Exception as e:
            self.logger.error(f"Browser testing failed: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    async def _run_async_tests(self, url: str, results: Dict[str, Any]):
        """Run asynchronous browser tests"""
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            # Launch browser
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent='RedSentinel-BrowserAgent/1.0',
                viewport={'width': 1280, 'height': 720}
            )
            
            try:
                page = await context.new_page()
                
                # Test 1: Basic page analysis
                await self._analyze_page_security(page, url, results)
                
                # Test 2: XSS testing
                await self._test_xss_vulnerabilities(page, url, results)
                
                # Test 3: CSRF testing
                await self._test_csrf_vulnerabilities(page, url, results)
                
                # Test 4: JavaScript analysis
                await self._analyze_javascript_security(page, url, results)
                
                # Test 5: Cookie security
                await self._analyze_cookie_security(page, url, results)
                
                # Test 6: Content Security Policy
                await self._analyze_csp(page, url, results)
                
            finally:
                await browser.close()
    
    async def _analyze_page_security(self, page, url: str, results: Dict[str, Any]):
        """Analyze basic page security features"""
        test_name = "page_security_analysis"
        self.logger.info(f"Running {test_name}...")
        
        try:
            # Navigate to page
            response = await page.goto(url, wait_until='domcontentloaded')
            
            test_result = {
                'test': test_name,
                'status': 'completed',
                'findings': []
            }
            
            # Check response headers
            headers = response.headers
            
            # Security header analysis
            security_headers = {
                'x-frame-options': 'Clickjacking protection',
                'x-xss-protection': 'XSS protection',
                'x-content-type-options': 'MIME type sniffing protection',
                'strict-transport-security': 'HTTPS enforcement',
                'content-security-policy': 'Content security policy'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    test_result['findings'].append({
                        'type': 'missing_security_header',
                        'severity': 'medium',
                        'description': f"Missing {header} header - {description}",
                        'recommendation': f"Add {header} header for better security"
                    })
            
            # Check for HTTPS
            if not url.startswith('https://'):
                test_result['findings'].append({
                    'type': 'insecure_protocol',
                    'severity': 'high',
                    'description': 'Site not using HTTPS',
                    'recommendation': 'Implement HTTPS with valid SSL certificate'
                })
            
            # Check page title and meta tags for information disclosure
            title = await page.title()
            if any(keyword in title.lower() for keyword in ['test', 'dev', 'staging', 'debug']):
                test_result['findings'].append({
                    'type': 'information_disclosure',
                    'severity': 'low',
                    'description': f"Page title suggests development/test environment: {title}",
                    'recommendation': 'Use production-appropriate page titles'
                })
            
            results['tests_run'].append(test_result)
            results['vulnerabilities'].extend(test_result['findings'])
            
        except Exception as e:
            self.logger.error(f"Page security analysis failed: {str(e)}")
            results['tests_run'].append({
                'test': test_name,
                'status': 'error',
                'error': str(e)
            })
    
    async def _test_xss_vulnerabilities(self, page, url: str, results: Dict[str, Any]):
        """Test for XSS vulnerabilities"""
        test_name = "xss_vulnerability_test"
        self.logger.info(f"Running {test_name}...")
        
        try:
            test_result = {
                'test': test_name,
                'status': 'completed',
                'findings': []
            }
            
            # Common XSS payloads
            xss_payloads = [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '\';alert("XSS");//',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>'
            ]
            
            # Find input fields and test them
            await page.goto(url)
            
            # Find all input elements
            inputs = await page.query_selector_all('input[type="text"], input[type="search"], textarea')
            
            for i, input_elem in enumerate(inputs):
                for payload in xss_payloads[:2]:  # Test only first 2 payloads to avoid too many requests
                    try:
                        # Set up alert dialog handler
                        dialog_triggered = False
                        
                        async def handle_dialog(dialog):
                            nonlocal dialog_triggered
                            dialog_triggered = True
                            await dialog.dismiss()
                        
                        page.on('dialog', handle_dialog)
                        
                        # Fill input with XSS payload
                        await input_elem.fill(payload)
                        await input_elem.press('Enter')
                        
                        # Wait briefly for potential XSS execution
                        await page.wait_for_timeout(1000)
                        
                        if dialog_triggered:
                            test_result['findings'].append({
                                'type': 'xss_vulnerability',
                                'severity': 'high',
                                'description': f"XSS vulnerability in input field {i+1}",
                                'payload': payload,
                                'recommendation': 'Implement proper input validation and output encoding'
                            })
                            break  # Found XSS, no need to test more payloads on this input
                        
                        page.remove_listener('dialog', handle_dialog)
                        
                    except Exception as e:
                        self.logger.debug(f"XSS test error on input {i}: {str(e)}")
                        continue
            
            # Test URL parameters for reflected XSS
            try:
                test_url = f"{url}?test=<script>alert('XSS')</script>"
                response = await page.goto(test_url)
                content = await page.content()
                
                if '<script>alert(\'XSS\')</script>' in content:
                    test_result['findings'].append({
                        'type': 'reflected_xss',
                        'severity': 'high',
                        'description': 'Reflected XSS vulnerability in URL parameters',
                        'recommendation': 'Sanitize URL parameters before reflecting in page content'
                    })
            except Exception as e:
                self.logger.debug(f"Reflected XSS test error: {str(e)}")
            
            results['tests_run'].append(test_result)
            results['vulnerabilities'].extend(test_result['findings'])
            
        except Exception as e:
            self.logger.error(f"XSS testing failed: {str(e)}")
            results['tests_run'].append({
                'test': test_name,
                'status': 'error',
                'error': str(e)
            })
    
    async def _test_csrf_vulnerabilities(self, page, url: str, results: Dict[str, Any]):
        """Test for CSRF vulnerabilities"""
        test_name = "csrf_vulnerability_test"
        self.logger.info(f"Running {test_name}...")
        
        try:
            test_result = {
                'test': test_name,
                'status': 'completed',
                'findings': []
            }
            
            await page.goto(url)
            
            # Find forms that might be vulnerable to CSRF
            forms = await page.query_selector_all('form')
            
            for i, form in enumerate(forms):
                try:
                    # Check if form has CSRF token
                    csrf_inputs = await form.query_selector_all('input[name*="csrf"], input[name*="token"], input[type="hidden"]')
                    
                    if not csrf_inputs:
                        # Check form method and action
                        method = await form.get_attribute('method') or 'get'
                        action = await form.get_attribute('action') or ''
                        
                        if method.lower() in ['post', 'put', 'delete']:
                            test_result['findings'].append({
                                'type': 'csrf_vulnerability',
                                'severity': 'medium',
                                'description': f"Form {i+1} lacks CSRF protection (method: {method.upper()})",
                                'action': action,
                                'recommendation': 'Implement CSRF tokens for state-changing operations'
                            })
                
                except Exception as e:
                    self.logger.debug(f"CSRF test error on form {i}: {str(e)}")
                    continue
            
            results['tests_run'].append(test_result)
            results['vulnerabilities'].extend(test_result['findings'])
            
        except Exception as e:
            self.logger.error(f"CSRF testing failed: {str(e)}")
            results['tests_run'].append({
                'test': test_name,
                'status': 'error',
                'error': str(e)
            })
    
    async def _analyze_javascript_security(self, page, url: str, results: Dict[str, Any]):
        """Analyze JavaScript security issues"""
        test_name = "javascript_security_analysis"
        self.logger.info(f"Running {test_name}...")
        
        try:
            test_result = {
                'test': test_name,
                'status': 'completed',
                'findings': []
            }
            
            await page.goto(url)
            
            # Check for dangerous JavaScript functions
            dangerous_functions = await page.evaluate("""
                () => {
                    const dangerous = [];
                    const scripts = Array.from(document.scripts);
                    
                    scripts.forEach((script, index) => {
                        const content = script.innerHTML;
                        
                        // Check for eval usage
                        if (content.includes('eval(')) {
                            dangerous.push({
                                type: 'eval_usage',
                                script: index,
                                description: 'Use of eval() function detected'
                            });
                        }
                        
                        // Check for innerHTML usage
                        if (content.includes('innerHTML')) {
                            dangerous.push({
                                type: 'innerHTML_usage',
                                script: index,
                                description: 'Use of innerHTML detected (potential XSS risk)'
                            });
                        }
                        
                        // Check for document.write
                        if (content.includes('document.write')) {
                            dangerous.push({
                                type: 'document_write',
                                script: index,
                                description: 'Use of document.write detected'
                            });
                        }
                    });
                    
                    return dangerous;
                }
            """)
            
            for issue in dangerous_functions:
                test_result['findings'].append({
                    'type': f"javascript_{issue['type']}",
                    'severity': 'medium',
                    'description': issue['description'],
                    'recommendation': 'Use safer alternatives and validate/sanitize data'
                })
            
            # Check for external script sources
            external_scripts = await page.evaluate("""
                () => {
                    const scripts = Array.from(document.scripts);
                    return scripts
                        .filter(script => script.src && !script.src.startsWith(window.location.origin))
                        .map(script => script.src);
                }
            """)
            
            for script_src in external_scripts:
                test_result['findings'].append({
                    'type': 'external_script',
                    'severity': 'low',
                    'description': f"External script loaded: {script_src}",
                    'recommendation': 'Verify trust and implement Subresource Integrity (SRI)'
                })
            
            results['tests_run'].append(test_result)
            results['vulnerabilities'].extend(test_result['findings'])
            
        except Exception as e:
            self.logger.error(f"JavaScript security analysis failed: {str(e)}")
            results['tests_run'].append({
                'test': test_name,
                'status': 'error',
                'error': str(e)
            })
    
    async def _analyze_cookie_security(self, page, url: str, results: Dict[str, Any]):
        """Analyze cookie security settings"""
        test_name = "cookie_security_analysis"
        self.logger.info(f"Running {test_name}...")
        
        try:
            test_result = {
                'test': test_name,
                'status': 'completed',
                'findings': []
            }
            
            await page.goto(url)
            
            # Get all cookies
            cookies = await page.context.cookies()
            
            for cookie in cookies:
                cookie_name = cookie['name']
                
                # Check for missing Secure flag
                if not cookie.get('secure', False) and url.startswith('https://'):
                    test_result['findings'].append({
                        'type': 'insecure_cookie',
                        'severity': 'medium',
                        'description': f"Cookie '{cookie_name}' missing Secure flag",
                        'recommendation': 'Set Secure flag for cookies on HTTPS sites'
                    })
                
                # Check for missing HttpOnly flag
                if not cookie.get('httpOnly', False):
                    test_result['findings'].append({
                        'type': 'cookie_accessible_to_js',
                        'severity': 'medium',
                        'description': f"Cookie '{cookie_name}' missing HttpOnly flag",
                        'recommendation': 'Set HttpOnly flag to prevent JavaScript access'
                    })
                
                # Check for missing SameSite attribute
                if not cookie.get('sameSite'):
                    test_result['findings'].append({
                        'type': 'missing_samesite',
                        'severity': 'low',
                        'description': f"Cookie '{cookie_name}' missing SameSite attribute",
                        'recommendation': 'Set SameSite attribute to prevent CSRF attacks'
                    })
            
            results['tests_run'].append(test_result)
            results['vulnerabilities'].extend(test_result['findings'])
            
        except Exception as e:
            self.logger.error(f"Cookie security analysis failed: {str(e)}")
            results['tests_run'].append({
                'test': test_name,
                'status': 'error',
                'error': str(e)
            })
    
    async def _analyze_csp(self, page, url: str, results: Dict[str, Any]):
        """Analyze Content Security Policy"""
        test_name = "csp_analysis"
        self.logger.info(f"Running {test_name}...")
        
        try:
            test_result = {
                'test': test_name,
                'status': 'completed',
                'findings': []
            }
            
            response = await page.goto(url)
            headers = response.headers
            
            csp_header = headers.get('content-security-policy')
            
            if not csp_header:
                test_result['findings'].append({
                    'type': 'missing_csp',
                    'severity': 'medium',
                    'description': 'Content Security Policy header missing',
                    'recommendation': 'Implement CSP to prevent XSS and data injection attacks'
                })
            else:
                # Analyze CSP for common issues
                if 'unsafe-inline' in csp_header:
                    test_result['findings'].append({
                        'type': 'unsafe_csp',
                        'severity': 'medium',
                        'description': "CSP allows 'unsafe-inline'",
                        'recommendation': 'Remove unsafe-inline and use nonces or hashes'
                    })
                
                if 'unsafe-eval' in csp_header:
                    test_result['findings'].append({
                        'type': 'unsafe_csp',
                        'severity': 'high',
                        'description': "CSP allows 'unsafe-eval'",
                        'recommendation': 'Remove unsafe-eval to prevent code injection'
                    })
                
                if '*' in csp_header:
                    test_result['findings'].append({
                        'type': 'permissive_csp',
                        'severity': 'medium',
                        'description': 'CSP uses wildcard (*) directive',
                        'recommendation': 'Specify explicit source lists instead of wildcards'
                    })
            
            results['tests_run'].append(test_result)
            results['vulnerabilities'].extend(test_result['findings'])
            
        except Exception as e:
            self.logger.error(f"CSP analysis failed: {str(e)}")
            results['tests_run'].append({
                'test': test_name,
                'status': 'error',
                'error': str(e)
            })
    
    def test_with_custom_payloads(self, url: str, payloads: List[str]) -> Dict[str, Any]:
        """Test custom payloads (synchronous wrapper)"""
        if not self.playwright_available:
            return {'error': 'Playwright not available'}
        
        return asyncio.run(self._test_custom_payloads_async(url, payloads))
    async def _test_custom_payloads_async(self, url: str, payloads: List[str]) -> Dict[str, Any]:
        """Test custom payloads asynchronously"""
        from playwright.async_api import async_playwright
        results = {
            'target': url,
            'payloads_tested': len(payloads),
            'successful_payloads': [],
            'timestamp': datetime.now().isoformat()
        }
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            try:
                for payload in payloads:
                    try:
                        # Test payload in URL parameter
                        test_url = f"{url}?test={payload}"
                        await page.goto(test_url)
                        
                        # Check if payload appears unescaped
                        content = await page.content()
                        if payload in content:
                            results['successful_payloads'].append({
                                'payload': payload,
                                'method': 'url_parameter',
                                'description': 'Payload reflected without encoding'
                            })
                    
                    except Exception as e:
                        self.logger.debug(f"Custom payload test error: {str(e)}")
                        continue
                
            finally:
                await browser.close()
        
        return results
