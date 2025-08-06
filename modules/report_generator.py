"""
Report Generator Module
Creates human-readable security assessment reports in various formats.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import os

class ReportGenerator:
    """Generates comprehensive security assessment reports"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def generate_report(self, results: Dict[str, Any], output_dir: str = './reports', 
                       format: str = 'html') -> str:
        """Generate security assessment report in specified format"""
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_safe = self._sanitize_filename(results.get('target', 'unknown'))
        
        report_files = []
        
        try:
            if format in ['json', 'all']:
                json_file = self._generate_json_report(results, output_dir, timestamp, target_safe)
                report_files.append(json_file)
            
            if format in ['html', 'all']:
                html_file = self._generate_html_report(results, output_dir, timestamp, target_safe)
                report_files.append(html_file)
            
            if format in ['pdf', 'all']:
                pdf_file = self._generate_pdf_report(results, output_dir, timestamp, target_safe)
                if pdf_file:
                    report_files.append(pdf_file)
            
            self.logger.info(f"Reports generated: {', '.join(report_files)}")
            return report_files[0] if report_files else ""
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {str(e)}")
            return ""
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for cross-platform compatibility"""
        # Replace invalid characters with underscores
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Remove protocol prefixes
        filename = filename.replace('https_', '').replace('http_', '')
        
        return filename[:50]  # Limit length
    
    def _generate_json_report(self, results: Dict[str, Any], output_dir: str, 
                             timestamp: str, target_safe: str) -> str:
        """Generate JSON format report"""
        filename = f"redsentinel_report_{target_safe}_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        # Add metadata
        report_data = {
            'metadata': {
                'tool': 'RedSentinel AI',
                'version': '1.0.0',
                'generated_at': datetime.now().isoformat(),
                'target': results.get('target'),
                'scan_level': results.get('scan_level'),
                'ai_mode': results.get('ai_mode')
            },
            'summary': self._generate_summary(results),
            'detailed_results': results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"JSON report saved: {filepath}")
        return filepath
    
    def _generate_html_report(self, results: Dict[str, Any], output_dir: str, 
                             timestamp: str, target_safe: str) -> str:
        """Generate HTML format report"""
        filename = f"redsentinel_report_{target_safe}_{timestamp}.html"
        filepath = os.path.join(output_dir, filename)
        
        html_content = self._build_html_report(results)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report saved: {filepath}")
        return filepath
    
    def _generate_pdf_report(self, results: Dict[str, Any], output_dir: str, 
                            timestamp: str, target_safe: str) -> Optional[str]:
        """Generate PDF format report (requires additional dependencies)"""
        try:
            # This would require libraries like reportlab or weasyprint
            # For now, return None to indicate PDF generation is not available
            self.logger.warning("PDF generation not implemented. Install reportlab or weasyprint for PDF support.")
            return None
            
        except Exception as e:
            self.logger.error(f"PDF generation failed: {str(e)}")
            return None
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary from results"""
        summary = {
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'info_findings': 0,
            'modules_executed': [],
            'key_findings': []
        }
        
        # Count vulnerabilities by severity
        all_vulns = []
        
        # Collect vulnerabilities from all modules
        if 'vulnerabilities' in results:
            all_vulns.extend(results['vulnerabilities'])
        
        if 'browser_testing' in results and 'vulnerabilities' in results['browser_testing']:
            all_vulns.extend(results['browser_testing']['vulnerabilities'])
        
        if 'web_testing' in results and 'findings' in results['web_testing']:
            all_vulns.extend(results['web_testing']['findings'])
        
        # Count by severity
        for vuln in all_vulns:
            severity = vuln.get('severity', 'info').lower()
            summary['total_vulnerabilities'] += 1
            
            if severity == 'critical':
                summary['critical_vulnerabilities'] += 1
            elif severity == 'high':
                summary['high_vulnerabilities'] += 1
            elif severity == 'medium':
                summary['medium_vulnerabilities'] += 1
            elif severity == 'low':
                summary['low_vulnerabilities'] += 1
            else:
                summary['info_findings'] += 1
        
        # Identify key findings (high/critical vulnerabilities)
        key_findings = [v for v in all_vulns if v.get('severity', '').lower() in ['high', 'critical']]
        summary['key_findings'] = key_findings[:5]  # Top 5 key findings
        
        # List executed modules
        summary['modules_executed'] = results.get('modules_run', [])
        
        return summary
    
    def _build_html_report(self, results: Dict[str, Any]) -> str:
        """Build HTML report content"""
        summary = self._generate_summary(results)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedSentinel AI Security Assessment Report</title>
    <style>
        {self._get_html_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ RedSentinel AI Security Assessment Report</h1>
            <div class="target-info">
                <h2>Target: {results.get('target', 'Unknown')}</h2>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Scan Level: {results.get('scan_level', 'Unknown')}</p>
                <p>AI Mode: {results.get('ai_mode', 'Unknown')}</p>
            </div>
        </header>

        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-stats">
                <div class="stat-box critical">
                    <h3>{summary['critical_vulnerabilities']}</h3>
                    <p>Critical</p>
                </div>
                <div class="stat-box high">
                    <h3>{summary['high_vulnerabilities']}</h3>
                    <p>High</p>
                </div>
                <div class="stat-box medium">
                    <h3>{summary['medium_vulnerabilities']}</h3>
                    <p>Medium</p>
                </div>
                <div class="stat-box low">
                    <h3>{summary['low_vulnerabilities']}</h3>
                    <p>Low</p>
                </div>
                <div class="stat-box info">
                    <h3>{summary['info_findings']}</h3>
                    <p>Info</p>
                </div>
            </div>
            
            <div class="modules-run">
                <h3>Modules Executed</h3>
                <ul>
                    {self._format_modules_list(summary['modules_executed'])}
                </ul>
            </div>
        </section>

        <section class="key-findings">
            <h2>Key Findings</h2>
            {self._format_key_findings(summary['key_findings'])}
        </section>

        <section class="detailed-results">
            <h2>Detailed Results</h2>
            {self._format_detailed_results(results)}
        </section>

        <section class="recommendations">
            <h2>Recommendations</h2>
            {self._format_recommendations(summary)}
        </section>

        <footer>
            <p>Report generated by RedSentinel AI v1.0.0</p>
            <p>For authorized testing only - Ethical use required</p>
        </footer>
    </div>
</body>
</html>
"""
        return html
    
    def _get_html_styles(self) -> str:
        """Get CSS styles for HTML report"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
        }
        
        header h1 {
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        
        .target-info h2 {
            margin-bottom: 10px;
            font-size: 1.5em;
        }
        
        .summary-stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        
        .stat-box {
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            margin: 10px;
            min-width: 120px;
            color: white;
        }
        
        .stat-box.critical { background-color: #d32f2f; }
        .stat-box.high { background-color: #f57c00; }
        .stat-box.medium { background-color: #fbc02d; color: #333; }
        .stat-box.low { background-color: #388e3c; }
        .stat-box.info { background-color: #1976d2; }
        
        .stat-box h3 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        section {
            margin: 30px 0;
            padding: 20px;
            border-radius: 10px;
            background-color: #fafafa;
        }
        
        h2 {
            color: #333;
            margin-bottom: 15px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 5px;
        }
        
        .vulnerability {
            margin: 15px 0;
            padding: 15px;
            border-left: 5px solid;
            background-color: white;
            border-radius: 5px;
        }
        
        .vulnerability.critical { border-left-color: #d32f2f; }
        .vulnerability.high { border-left-color: #f57c00; }
        .vulnerability.medium { border-left-color: #fbc02d; }
        .vulnerability.low { border-left-color: #388e3c; }
        .vulnerability.info { border-left-color: #1976d2; }
        
        .vulnerability h4 {
            margin-bottom: 10px;
            color: #333;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .severity-badge.critical { background-color: #d32f2f; }
        .severity-badge.high { background-color: #f57c00; }
        .severity-badge.medium { background-color: #fbc02d; color: #333; }
        .severity-badge.low { background-color: #388e3c; }
        .severity-badge.info { background-color: #1976d2; }
        
        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
        
        ul {
            margin-left: 20px;
        }
        
        li {
            margin: 5px 0;
        }
        """
    
    def _format_modules_list(self, modules: List[str]) -> str:
        """Format modules list for HTML"""
        if not modules:
            return "<li>No modules executed</li>"
        
        return "\\n".join([f"<li>{module.replace('_', ' ').title()}</li>" for module in modules])
    
    def _format_key_findings(self, key_findings: List[Dict[str, Any]]) -> str:
        """Format key findings for HTML"""
        if not key_findings:
            return "<p>No critical or high severity vulnerabilities found.</p>"
        
        html = ""
        for finding in key_findings:
            severity = finding.get('severity', 'info').lower()
            description = finding.get('description', 'No description available')
            vuln_type = finding.get('type', 'unknown')
            
            html += f"""
            <div class="vulnerability {severity}">
                <h4>{vuln_type.replace('_', ' ').title()} 
                    <span class="severity-badge {severity}">{severity.upper()}</span>
                </h4>
                <p>{description}</p>
            </div>
            """
        
        return html
    
    def _format_detailed_results(self, results: Dict[str, Any]) -> str:
        """Format detailed results for HTML"""
        html = ""
        
        # Reconnaissance results
        if 'recon' in results:
            html += "<h3>Reconnaissance</h3>"
            html += f"<pre>{json.dumps(results['recon'], indent=2)}</pre>"
        
        # Vulnerability scan results
        if 'vulnerabilities' in results:
            html += "<h3>Vulnerability Scan Results</h3>"
            for vuln in results['vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                html += f"""
                <div class="vulnerability {severity}">
                    <h4>{vuln.get('type', 'Unknown').replace('_', ' ').title()}
                        <span class="severity-badge {severity}">{severity.upper()}</span>
                    </h4>
                    <p>{vuln.get('description', 'No description')}</p>
                    <p><strong>Source:</strong> {vuln.get('source', 'Unknown')}</p>
                </div>
                """
        
        # Browser testing results
        if 'browser_testing' in results:
            html += "<h3>Browser Security Testing</h3>"
            browser_results = results['browser_testing']
            if 'vulnerabilities' in browser_results:
                for vuln in browser_results['vulnerabilities']:
                    severity = vuln.get('severity', 'info').lower()
                    html += f"""
                    <div class="vulnerability {severity}">
                        <h4>{vuln.get('type', 'Unknown').replace('_', ' ').title()}
                            <span class="severity-badge {severity}">{severity.upper()}</span>
                        </h4>
                        <p>{vuln.get('description', 'No description')}</p>
                        {f"<p><strong>Recommendation:</strong> {vuln.get('recommendation', '')}</p>" if vuln.get('recommendation') else ''}
                    </div>
                    """
        
        return html or "<p>No detailed results available.</p>"
    
    def _format_recommendations(self, summary: Dict[str, Any]) -> str:
        """Format security recommendations for HTML"""
        recommendations = []
        
        # General recommendations based on findings
        if summary['critical_vulnerabilities'] > 0:
            recommendations.append("🚨 <strong>URGENT:</strong> Address critical vulnerabilities immediately before proceeding with other fixes.")
        
        if summary['high_vulnerabilities'] > 0:
            recommendations.append("⚠️ <strong>HIGH PRIORITY:</strong> Fix high-severity vulnerabilities as soon as possible.")
        
        if summary['medium_vulnerabilities'] > 0:
            recommendations.append("📋 Plan to address medium-severity vulnerabilities in the next maintenance cycle.")
        
        # Security best practices
        recommendations.extend([
            "🔒 Implement proper input validation and output encoding to prevent injection attacks.",
            "🛡️ Add security headers (CSP, X-Frame-Options, etc.) to protect against common attacks.",
            "🔐 Use HTTPS with strong TLS configuration for all sensitive communications.",
            "📝 Regularly update and patch all software components and dependencies.",
            "🔍 Implement proper logging and monitoring to detect security incidents.",
            "🚫 Follow the principle of least privilege for all system access."
        ])
        
        html = "<ul>"
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        html += "</ul>"
        
        return html
