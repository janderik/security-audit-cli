"""Report generation for audit results."""

import json
from typing import Dict, List, Any
from datetime import datetime
from .engine import AuditResult, RiskLevel


class ReportGenerator:
    """Generate audit reports in various formats."""
    
    def __init__(self, result: AuditResult):
        self.result = result
    
    def to_console(self) -> str:
        """Generate console-friendly report."""
        lines = []
        lines.append("=" * 50)
        lines.append("  Security Audit Report")
        lines.append(f"  Target: {self.result.target}")
        lines.append(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 50)
        lines.append("")
        
        for finding in self.result.findings:
            icon = self._get_risk_icon(finding.risk_level)
            lines.append(f"[{finding.category}] {icon} {finding.title}")
            lines.append(f"  {finding.description}")
            if finding.recommendation:
                lines.append(f"  Recommendation: {finding.recommendation}")
            lines.append("")
        
        summary = self.result.get_summary()
        lines.append("=" * 50)
        lines.append(f"  Summary: {summary.get('high', 0)} High, "
                     f"{summary.get('medium', 0)} Medium, "
                     f"{summary.get('low', 0)} Low, "
                     f"{summary.get('info', 0)} Info")
        lines.append("=" * 50)
        
        return "\n".join(lines)
    
    def to_json(self) -> str:
        """Generate JSON report."""
        data = {
            "target": self.result.target,
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": self.result.end_time - self.result.start_time,
            "summary": self.result.get_summary(),
            "findings": [
                {
                    "category": f.category,
                    "risk_level": f.risk_level.value,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "details": f.details
                }
                for f in self.result.findings
            ]
        }
        return json.dumps(data, indent=2)
    
    def to_html(self) -> str:
        """Generate HTML report."""
        summary = self.result.get_summary()
        
        findings_html = ""
        for finding in self.result.findings:
            color = self._get_risk_color(finding.risk_level)
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 10px; margin: 10px 0;">
                <h3 style="color: {color};">{finding.risk_level.value.upper()}: {finding.title}</h3>
                <p><strong>Category:</strong> {finding.category}</p>
                <p>{finding.description}</p>
                {"<p><strong>Recommendation:</strong> " + finding.recommendation + "</p>" if finding.recommendation else ""}
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report - {self.result.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #333; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-item {{ padding: 15px; border-radius: 5px; color: white; }}
        .high {{ background: #dc3545; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; }}
        .info {{ background: #17a2b8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Audit Report</h1>
        <p>Target: {self.result.target}</p>
        <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <div class="summary-item high">High: {summary.get('high', 0)}</div>
        <div class="summary-item medium">Medium: {summary.get('medium', 0)}</div>
        <div class="summary-item low">Low: {summary.get('low', 0)}</div>
        <div class="summary-item info">Info: {summary.get('info', 0)}</div>
    </div>
    
    <h2>Findings</h2>
    {findings_html}
</body>
</html>"""
        return html
    
    def _get_risk_icon(self, level: RiskLevel) -> str:
        """Get icon for risk level."""
        icons = {
            RiskLevel.INFO: "[INFO]",
            RiskLevel.LOW: "[LOW]",
            RiskLevel.MEDIUM: "[MED]",
            RiskLevel.HIGH: "[HIGH]",
            RiskLevel.CRITICAL: "[CRIT]"
        }
        return icons.get(level, "[?]")
    
    def _get_risk_color(self, level: RiskLevel) -> str:
        """Get color for risk level."""
        colors = {
            RiskLevel.INFO: "#17a2b8",
            RiskLevel.LOW: "#28a745",
            RiskLevel.MEDIUM: "#ffc107",
            RiskLevel.HIGH: "#dc3545",
            RiskLevel.CRITICAL: "#721c24"
        }
        return colors.get(level, "#333")
