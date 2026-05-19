#!/usr/bin/env python3
"""
DRYBT by Dryex v.1 - Report Generator
Professional Reporting System with Multiple Formats (JSON, HTML, Markdown)
"""

import json
from datetime import datetime
from typing import List, Dict, Optional
import os

class ReportGenerator:
    def __init__(self, target: str):
        self.target = target
        self.timestamp = datetime.now().isoformat()
        self.findings: List[Dict] = []
        self.tool_name = "DRYBT by Dryex v.1"
        self.tool_version = "v.1"
    
    def add_finding(self, module: str, title: str, severity: str, 
                    details: Dict, poc: str = None, confidence: int = None):
        """
        Add a finding to the report
        
        Args:
            module: Module name that found the vulnerability
            title: Title of the finding
            severity: critical, high, medium, low, info
            details: Dictionary with detailed information
            poc: Proof of concept (optional)
            confidence: Confidence score 0-100 (optional)
        """
        finding = {
            "tool": self.tool_name,
            "version": self.tool_version,
            "module": module,
            "title": title,
            "severity": severity,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        
        if poc:
            finding["poc"] = poc
        if confidence:
            finding["confidence"] = confidence
        
        self.findings.append(finding)
    
    def to_json(self, filepath: str) -> str:
        """
        Save report as JSON format
        """
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        report = {
            "tool": self.tool_name,
            "version": self.tool_version,
            "target": self.target,
            "scan_start": self.timestamp,
            "scan_end": datetime.now().isoformat(),
            "total_findings": len(self.findings),
            "findings_by_severity": {
                "critical": len([f for f in self.findings if f.get("severity") == "critical"]),
                "high": len([f for f in self.findings if f.get("severity") == "high"]),
                "medium": len([f for f in self.findings if f.get("severity") == "medium"]),
                "low": len([f for f in self.findings if f.get("severity") == "low"]),
                "info": len([f for f in self.findings if f.get("severity") == "info"])
            },
            "findings": self.findings
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def to_html(self, filepath: str) -> str:
        """
        Save report as HTML format (professional looking)
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Count findings by severity
        critical_count = len([f for f in self.findings if f.get("severity") == "critical"])
        high_count = len([f for f in self.findings if f.get("severity") == "high"])
        medium_count = len([f for f in self.findings if f.get("severity") == "medium"])
        low_count = len([f for f in self.findings if f.get("severity") == "low"])
        info_count = len([f for f in self.findings if f.get("severity") == "info"])
        
        html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DRYBT Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #e0e0e0;
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        
        .tool-name {{
            font-size: 48px;
            font-weight: bold;
            letter-spacing: 2px;
            margin-bottom: 10px;
        }}
        
        .tool-version {{
            font-size: 18px;
            opacity: 0.9;
        }}
        
        .target-info {{
            margin-top: 20px;
            font-size: 16px;
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 10px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            backdrop-filter: blur(10px);
            transition: transform 0.3s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-number {{
            font-size: 36px;
            font-weight: bold;
        }}
        
        .stat-label {{
            font-size: 14px;
            margin-top: 10px;
            opacity: 0.8;
        }}
        
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff8844; }}
        .medium {{ color: #ffcc44; }}
        .low {{ color: #44aaff; }}
        .info {{ color: #44ffaa; }}
        
        .findings-section {{
            margin-top: 30px;
        }}
        
        .finding {{
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            transition: all 0.3s;
        }}
        
        .finding:hover {{
            transform: translateX(5px);
            background: rgba(255,255,255,0.08);
        }}
        
        .finding-header {{
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-left: 5px solid;
        }}
        
        .finding-header.critical {{ border-left-color: #ff4444; }}
        .finding-header.high {{ border-left-color: #ff8844; }}
        .finding-header.medium {{ border-left-color: #ffcc44; }}
        .finding-header.low {{ border-left-color: #44aaff; }}
        .finding-header.info {{ border-left-color: #44ffaa; }}
        
        .finding-title {{
            font-size: 18px;
            font-weight: bold;
        }}
        
        .finding-module {{
            font-size: 12px;
            opacity: 0.7;
            margin-top: 5px;
        }}
        
        .severity-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }}
        
        .severity-critical {{ background: #ff4444; color: white; }}
        .severity-high {{ background: #ff8844; color: white; }}
        .severity-medium {{ background: #ffcc44; color: #1a1a2e; }}
        .severity-low {{ background: #44aaff; color: white; }}
        .severity-info {{ background: #44ffaa; color: #1a1a2e; }}
        
        .finding-body {{
            padding: 0 20px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }}
        
        .finding-body.open {{
            max-height: 2000px;
            padding: 20px;
        }}
        
        .finding-details {{
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 15px;
            margin-top: 10px;
            overflow-x: auto;
        }}
        
        pre {{
            background: #0a0a0a;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 12px;
            font-family: 'Consolas', monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        
        .timestamp {{
            font-size: 11px;
            opacity: 0.5;
            text-align: right;
            margin-top: 10px;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid rgba(255,255,255,0.1);
            font-size: 12px;
            opacity: 0.6;
        }}
        
        @media (max-width: 768px) {{
            .tool-name {{ font-size: 32px; }}
            .stats {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="tool-name">🔍 DRYBT</div>
            <div class="tool-version">by Dryex | {version}</div>
            <div class="target-info">
                <strong>Target:</strong> {target}<br>
                <strong>Scan Date:</strong> {scan_date}
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{total_findings}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number critical">{critical_count}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">{high_count}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">{medium_count}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">{low_count}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <div class="findings-section">
            <h2>📋 Detailed Findings</h2>
'''
        
        # Add findings
        findings_html = ""
        for i, finding in enumerate(self.findings):
            severity = finding.get("severity", "info")
            severity_class = {
                "critical": "critical",
                "high": "high", 
                "medium": "medium",
                "low": "low",
                "info": "info"
            }.get(severity, "info")
            
            findings_html += f'''
            <div class="finding">
                <div class="finding-header {severity_class}" onclick="toggleFinding({i})">
                    <div>
                        <div class="finding-title">{finding.get('title', 'Unknown')}</div>
                        <div class="finding-module">Module: {finding.get('module', 'unknown')}</div>
                    </div>
                    <div>
                        <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                    </div>
                </div>
                <div class="finding-body" id="finding-{i}">
                    <div class="finding-details">
                        <pre>{json.dumps(finding.get('details', {}), indent=2, ensure_ascii=False)}</pre>
'''
            if finding.get('poc'):
                findings_html += f'''
                        <strong>📌 Proof of Concept:</strong>
                        <pre>{finding.get('poc')}</pre>
'''
            if finding.get('confidence'):
                findings_html += f'''
                        <strong>📊 Confidence:</strong> {finding.get('confidence')}%
'''
            findings_html += f'''
                    </div>
                    <div class="timestamp">Reported: {finding.get('timestamp', '')}</div>
                </div>
            </div>
'''
        
        html_footer = '''
        </div>
        
        <div class="footer">
            <p>DRYBT by Dryex v.1 - Ultimate Bug Bounty Tool</p>
            <p>Generated on {generated_date}</p>
        </div>
    </div>
    
    <script>
        function toggleFinding(id) {
            var element = document.getElementById('finding-' + id);
            element.classList.toggle('open');
        }
    </script>
</body>
</html>
'''
        
        # Format the HTML with proper values
        current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        html = html_template.format(
            target=self.target,
            version=self.tool_version,
            scan_date=current_date,
            generated_date=current_date,
            total_findings=len(self.findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count
        )
        
        # Insert findings into the HTML
        html = html.replace('<!-- findings will be inserted here -->', '')
        insertion_point = html.find('<div class="findings-section">')
        if insertion_point != -1:
            end_section = html.find('</div>', insertion_point)
            if end_section != -1:
                html = html[:end_section] + findings_html + html[end_section:]
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filepath
    
    def to_markdown(self, filepath: str) -> str:
        """
        Save report as Markdown format
        """
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        md = f"""# 🔍 DRYBT by Dryex v.1 - Bug Bounty Scan Report

## Scan Information

| Field | Value |
|-------|-------|
| **Target** | `{self.target}` |
| **Scan Start** | {self.timestamp} |
| **Scan End** | {datetime.now().isoformat()} |
| **Total Findings** | {len(self.findings)} |

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {len([f for f in self.findings if f.get('severity') == 'critical'])} |
| 🟠 High | {len([f for f in self.findings if f.get('severity') == 'high'])} |
| 🟡 Medium | {len([f for f in self.findings if f.get('severity') == 'medium'])} |
| 🔵 Low | {len([f for f in self.findings if f.get('severity') == 'low'])} |
| ⚪ Info | {len([f for f in self.findings if f.get('severity') == 'info'])} |

---

## Detailed Findings

"""
        for i, finding in enumerate(self.findings, 1):
            severity = finding.get('severity', 'info').upper()
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵',
                'INFO': '⚪'
            }.get(severity, '⚪')
            
            md += f"""
### {severity_icon} Finding #{i}: {finding.get('title', 'Unknown')}

| Property | Value |
|----------|-------|
| **Module** | `{finding.get('module', 'unknown')}` |
| **Severity** | {severity} |
| **Timestamp** | {finding.get('timestamp', '')} |

**Details:**

```json
{json.dumps(finding.get('details', {}), indent=2, ensure_ascii=False)}

"""