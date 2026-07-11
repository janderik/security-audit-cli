"""Core audit engine for security assessments."""

import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(Enum):
    """Risk levels for security findings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """Represents a single security finding."""
    category: str
    risk_level: RiskLevel
    title: str
    description: str
    recommendation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditResult:
    """Contains all findings from an audit."""
    target: str
    start_time: float = 0.0
    end_time: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    
    def add_finding(self, finding: Finding):
        """Add a finding to the result."""
        self.findings.append(finding)
    
    def get_findings_by_level(self, level: RiskLevel) -> List[Finding]:
        """Get findings filtered by risk level."""
        return [f for f in self.findings if f.risk_level == level]
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary count of findings by risk level."""
        summary = {}
        for level in RiskLevel:
            summary[level.value] = len(self.get_findings_by_level(level))
        return summary


class AuditEngine:
    """Main audit engine that orchestrates security checks."""
    
    def __init__(self, target: str, config: Optional[Dict] = None):
        self.target = target
        self.config = config or {}
        self.checks = []
        self.result = AuditResult(target=target)
    
    def register_check(self, check):
        """Register a security check module."""
        self.checks.append(check)
    
    def run_audit(self, check_categories: Optional[List[str]] = None) -> AuditResult:
        """Run the full audit or specific categories."""
        self.result.start_time = time.time()
        
        for check in self.checks:
            if check_categories is None or check.category in check_categories:
                findings = check.run(self.target, self.config)
                for finding in findings:
                    self.result.add_finding(finding)
        
        self.result.end_time = time.time()
        return self.result
    
    def get_duration(self) -> float:
        """Get audit duration in seconds."""
        if self.result.end_time and self.result.start_time:
            return self.result.end_time - self.result.start_time
        return 0.0
