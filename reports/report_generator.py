"""
HTML Report Generator for vulnerability scan results.
"""

import os
import html
from datetime import datetime
from typing import Optional
from jinja2 import Environment, BaseLoader

from core.models import ScanResult, Severity, OWASPCategory


class ReportGenerator:
    """Generates professional HTML reports from scan results."""
    
    def __init__(self):
        self.env = Environment(loader=BaseLoader())
    
    def generate_html_report(self, result: ScanResult, output_path: str) -> str:
        """Generate HTML report and save to file."""
        html_content = self._build_html(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _get_severity_color(self, severity: Severity) -> str:
        """Get color for severity level."""
        return {
            Severity.CRITICAL: '#DC2626',
            Severity.HIGH: '#EA580C',
            Severity.MEDIUM: '#CA8A04',
            Severity.LOW: '#2563EB',
            Severity.INFO: '#6B7280',
        }.get(severity, '#6B7280')
    
    def _build_html(self, result: ScanResult) -> str:
        """Build complete HTML report."""
        counts = result.get_severity_counts()
        owasp_counts = {}
        for finding in result.findings:
            cat = finding.owasp_category.value
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1
        
        findings_html = ""
        for finding in sorted(result.findings, key=lambda f: f.cvss_score, reverse=True):
            # Escape all user-supplied content to prevent XSS
            safe_title = html.escape(finding.title)
            safe_url = html.escape(finding.affected_url)
            safe_desc = html.escape(finding.description)
            safe_evidence = html.escape(finding.evidence) if finding.evidence else ""
            safe_payload = html.escape((finding.payload_used or "")[:100]) if finding.payload_used else ""
            safe_remediation = html.escape(finding.remediation) if finding.remediation else ""
            
            findings_html += f"""
            <div class="finding-card" style="border-left: 4px solid {self._get_severity_color(finding.severity)};">
                <div class="finding-header">
                    <span class="severity-badge" style="background: {self._get_severity_color(finding.severity)};">
                        {finding.severity.value.upper()}
                    </span>
                    <span class="cvss-score">CVSS: {finding.cvss_score}</span>
                    <span class="owasp-tag">{finding.owasp_category.value.split(' - ')[0]}</span>
                </div>
                <h3>{safe_title}</h3>
                <p class="affected-url">🔗 {safe_url}</p>
                <p class="description">{safe_desc}</p>
                {"<div class='evidence'><strong>Evidence:</strong> " + safe_evidence + "</div>" if safe_evidence else ""}
                {"<div class='payload'><strong>Payload:</strong> <code>" + safe_payload + "</code></div>" if safe_payload else ""}
                <div class="remediation">
                    <h4>📋 Remediation</h4>
                    <pre>{safe_remediation}</pre>
                </div>
            </div>
            """
        
        owasp_html = ""
        for cat, count in sorted(owasp_counts.items()):
            owasp_html += f"<tr><td>{cat}</td><td>{count}</td></tr>"
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {result.target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        
        header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px 20px;
            margin-bottom: 30px;
        }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header p {{ opacity: 0.8; }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }}
        .summary-card .count {{ font-size: 2.5em; font-weight: bold; }}
        .summary-card .label {{ font-size: 0.9em; opacity: 0.9; }}
        
        .section {{
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #1a1a2e;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }}
        .stat-item {{
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }}
        .stat-label {{ color: #666; }}
        .stat-value {{ font-weight: bold; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{ background: #f8f8f8; }}
        
        .finding-card {{
            background: #fafafa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }}
        .severity-badge {{
            padding: 5px 12px;
            border-radius: 4px;
            color: white;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .cvss-score {{
            font-weight: bold;
            color: #333;
        }}
        .owasp-tag {{
            background: #16213e;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8em;
        }}
        .finding-card h3 {{ color: #1a1a2e; margin-bottom: 10px; }}
        .affected-url {{
            color: #2563EB;
            font-family: monospace;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}
        .description {{ color: #555; margin-bottom: 15px; }}
        .evidence, .payload {{
            background: #f0f0f0;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
            font-size: 0.9em;
        }}
        .remediation {{
            background: #e8f5e9;
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
        }}
        .remediation h4 {{ color: #2e7d32; margin-bottom: 10px; }}
        .remediation pre {{
            white-space: pre-wrap;
            font-size: 0.85em;
            color: #333;
        }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }}
        
        @media print {{
            .finding-card {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>🛡️ Security Assessment Report</h1>
            <p>Target: {result.target_url}</p>
            <p>Scan Date: {result.started_at.strftime('%Y-%m-%d %H:%M:%S') if result.started_at else 'N/A'}</p>
        </div>
    </header>
    
    <div class="container">
        <div class="summary-cards">
            <div class="summary-card" style="background: #DC2626;">
                <div class="count">{counts.get('Critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card" style="background: #EA580C;">
                <div class="count">{counts.get('High', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card" style="background: #CA8A04;">
                <div class="count">{counts.get('Medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card" style="background: #2563EB;">
                <div class="count">{counts.get('Low', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card" style="background: #6B7280;">
                <div class="count">{counts.get('Informational', 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <section class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div>
                    <div class="stat-item">
                        <span class="stat-label">Target URL</span>
                        <span class="stat-value">{result.target_url}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Scan Duration</span>
                        <span class="stat-value">{result.scan_duration:.1f} seconds</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Total Findings</span>
                        <span class="stat-value">{len(result.findings)}</span>
                    </div>
                </div>
                <div>
                    <div class="stat-item">
                        <span class="stat-label">Modules Executed</span>
                        <span class="stat-value">{len(result.modules_run)}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Highest Severity</span>
                        <span class="stat-value">{result.get_highest_severity().value if result.get_highest_severity() else 'None'}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Report Generated</span>
                        <span class="stat-value">{datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
                    </div>
                </div>
            </div>
        </section>
        
        <section class="section">
            <h2>📋 OWASP Top 10 Mapping</h2>
            <table>
                <thead>
                    <tr>
                        <th>OWASP Category</th>
                        <th>Findings Count</th>
                    </tr>
                </thead>
                <tbody>
                    {owasp_html if owasp_html else '<tr><td colspan="2">No findings</td></tr>'}
                </tbody>
            </table>
        </section>
        
        <section class="section">
            <h2>🔍 Detailed Findings</h2>
            {findings_html if findings_html else '<p>No vulnerabilities detected.</p>'}
        </section>
    </div>
    
    <footer>
        <p>Generated by SOC Security Scanner | OWASP Top 10 Coverage</p>
        <p>This report is for authorized security testing purposes only.</p>
    </footer>
</body>
</html>
        """
        return html_content
