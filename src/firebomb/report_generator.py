"""
Report generation for security findings.
"""

import json
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

from firebomb.models import SecurityFinding, FirebaseConfig, EnumerationResult


class ReportGenerator:
    """Generates security reports in various formats."""

    def __init__(self, config: FirebaseConfig):
        """
        Initialize report generator.

        Args:
            config: FirebaseConfig for the tested project
        """
        self.config = config

    def generate_json(
        self,
        findings: List[SecurityFinding],
        summary: Dict[str, Any],
        enumeration: EnumerationResult,
        output_path: str,
    ) -> None:
        """
        Generate JSON report.

        Args:
            findings: List of SecurityFinding objects
            summary: Summary dictionary
            enumeration: EnumerationResult
            output_path: Path to save the report
        """
        report = {
            "metadata": {
                "tool": "Firebomb",
                "version": "1.0.0",
                "scan_date": datetime.now().isoformat(),
                "project_id": self.config.project_id,
            },
            "config": self.config.to_dict(),
            "summary": summary,
            "enumeration": enumeration.to_dict(),
            "findings": [finding.to_dict() for finding in findings],
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

    def generate_html(
        self,
        findings: List[SecurityFinding],
        summary: Dict[str, Any],
        enumeration: EnumerationResult,
        output_path: str,
    ) -> None:
        """
        Generate HTML report.

        Args:
            findings: List of SecurityFinding objects
            summary: Summary dictionary
            enumeration: EnumerationResult
            output_path: Path to save the report
        """
        html = self._create_html_report(findings, summary, enumeration)

        with open(output_path, "w") as f:
            f.write(html)

    def _create_html_report(
        self, findings: List[SecurityFinding], summary: Dict[str, Any], enumeration: EnumerationResult
    ) -> str:
        """
        Create HTML report content.

        Args:
            findings: List of SecurityFinding objects
            summary: Summary dictionary
            enumeration: EnumerationResult

        Returns:
            HTML string
        """
        # Generate findings HTML
        findings_html = ""
        for i, finding in enumerate(findings, 1):
            severity_class = finding.severity.value
            findings_html += f"""
            <div class="finding {severity_class}">
                <h3>#{i} [{finding.severity.value.upper()}] {finding.title}</h3>
                <div class="finding-content">
                    <h4>Description</h4>
                    <p>{self._escape_html(finding.description)}</p>

                    <h4>Affected Resource</h4>
                    <p>{self._escape_html(finding.affected_resource)}</p>

                    <h4>Recommendation</h4>
                    <pre>{self._escape_html(finding.recommendation)}</pre>

                    <div class="metadata">
                        {f'<span><strong>CWE:</strong> {finding.cwe}</span>' if finding.cwe else ''}
                        {f'<span><strong>OWASP:</strong> {finding.owasp}</span>' if finding.owasp else ''}
                    </div>
                </div>
            </div>
            """

        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firebomb Security Report - {self.config.project_id}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 30px;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}

        .section {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .section h2 {{
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}

        .summary-item {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: #f8f9fa;
        }}

        .summary-item .count {{
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }}

        .summary-item .label {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
        }}

        .summary-item.critical {{ background: #fee; }}
        .summary-item.critical .count {{ color: #d32f2f; }}
        .summary-item.high {{ background: #ffebee; }}
        .summary-item.high .count {{ color: #f44336; }}
        .summary-item.medium {{ background: #fff8e1; }}
        .summary-item.medium .count {{ color: #ff9800; }}
        .summary-item.low {{ background: #e3f2fd; }}
        .summary-item.low .count {{ color: #2196f3; }}
        .summary-item.info {{ background: #f5f5f5; }}
        .summary-item.info .count {{ color: #9e9e9e; }}

        .finding {{
            background: white;
            border-left: 4px solid;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .finding.critical {{ border-left-color: #d32f2f; background: #ffebee; }}
        .finding.high {{ border-left-color: #f44336; background: #fff3e0; }}
        .finding.medium {{ border-left-color: #ff9800; background: #fffde7; }}
        .finding.low {{ border-left-color: #2196f3; background: #e3f2fd; }}
        .finding.info {{ border-left-color: #9e9e9e; background: #fafafa; }}

        .finding h3 {{
            margin-bottom: 15px;
            color: #333;
        }}

        .finding-content h4 {{
            margin-top: 15px;
            margin-bottom: 8px;
            color: #667eea;
        }}

        .finding-content p {{
            white-space: pre-wrap;
            margin-bottom: 10px;
        }}

        .finding-content pre {{
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
            line-height: 1.4;
        }}

        .metadata {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #666;
        }}

        .metadata span {{
            margin-right: 20px;
        }}

        .config-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .config-table td {{
            padding: 10px;
            border-bottom: 1px solid #eee;
        }}

        .config-table td:first-child {{
            font-weight: bold;
            color: #667eea;
            width: 200px;
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔥 Firebomb Security Report</h1>
            <div class="subtitle">Firebase Security Assessment</div>
            <div style="margin-top: 15px; font-size: 0.9em;">
                Project: {self.config.project_id}<br>
                Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </header>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item critical">
                    <span class="count">{summary['critical']}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="summary-item high">
                    <span class="count">{summary['high']}</span>
                    <span class="label">High</span>
                </div>
                <div class="summary-item medium">
                    <span class="count">{summary['medium']}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="summary-item low">
                    <span class="count">{summary['low']}</span>
                    <span class="label">Low</span>
                </div>
                <div class="summary-item info">
                    <span class="count">{summary['info']}</span>
                    <span class="label">Info</span>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>⚙️ Configuration</h2>
            <table class="config-table">
                <tr>
                    <td>Project ID</td>
                    <td>{self.config.project_id}</td>
                </tr>
                <tr>
                    <td>API Key</td>
                    <td>{self.config.api_key[:20]}...</td>
                </tr>
                {f'<tr><td>Database URL</td><td>{self.config.database_url}</td></tr>' if self.config.database_url else ''}
                {f'<tr><td>Storage Bucket</td><td>{self.config.storage_bucket}</td></tr>' if self.config.storage_bucket else ''}
            </table>
        </div>

        <div class="section">
            <h2>🔍 Security Findings</h2>
            {findings_html if findings_html else '<p>No security findings detected.</p>'}
        </div>

        <footer>
            Generated by Firebomb v1.0.0 | Firebase Security Testing Tool<br>
            <a href="https://github.com/Victoratus/firebomb">github.com/Victoratus/firebomb</a>
        </footer>
    </div>
</body>
</html>
        """

        return html_template

    def _escape_html(self, text: str) -> str:
        """
        Escape HTML special characters.

        Args:
            text: Text to escape

        Returns:
            Escaped text
        """
        if not text:
            return ""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
