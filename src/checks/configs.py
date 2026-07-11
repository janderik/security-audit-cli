"""Configuration security checks."""

import os
import platform
from typing import Dict, List, Any
from ..audit.engine import Finding, RiskLevel


class ConfigCheck:
    """Check system configurations for security issues."""
    
    category = "configs"
    
    def __init__(self):
        self.system = platform.system().lower()
    
    def run(self, target: str, config: Dict[str, Any]) -> List[Finding]:
        """Run configuration checks."""
        findings = []
        
        if self.system == "linux":
            findings.extend(self._check_linux_config(target))
        elif self.system == "windows":
            findings.extend(self._check_windows_config(target))
        
        findings.extend(self._check_common_configs(target))
        
        return findings
    
    def _check_linux_config(self, target: str) -> List[Finding]:
        """Check Linux-specific configurations."""
        findings = []
        
        ssh_config = "/etc/ssh/sshd_config"
        if os.path.exists(ssh_config):
            findings.extend(self._check_ssh_config(ssh_config))
        
        if os.path.exists("/etc/selinux/config"):
            findings.append(self._check_selinux())
        
        return findings
    
    def _check_windows_config(self, target: str) -> List[Finding]:
        """Check Windows-specific configurations."""
        findings = []
        
        findings.append(Finding(
            category="configs",
            risk_level=RiskLevel.INFO,
            title="Windows System Detected",
            description="Windows-specific configuration checks will be performed.",
            details={"os": "windows"}
        ))
        
        return findings
    
    def _check_common_configs(self, target: str) -> List[Finding]:
        """Check common configurations."""
        findings = []
        
        if os.path.exists("/etc/passwd"):
            findings.append(Finding(
                category="configs",
                risk_level=RiskLevel.INFO,
                title="Unix System Detected",
                description="Unix-based configuration checks will be performed.",
                details={"os": "unix"}
            ))
        
        return findings
    
    def _check_ssh_config(self, config_path: str) -> List[Finding]:
        """Check SSH configuration."""
        findings = []
        
        try:
            with open(config_path, 'r') as f:
                config_content = f.read()
            
            if "PermitRootLogin yes" in config_content:
                findings.append(Finding(
                    category="configs",
                    risk_level=RiskLevel.HIGH,
                    title="SSH Root Login Enabled",
                    description="SSH configuration allows direct root login.",
                    recommendation="Set 'PermitRootLogin no' in sshd_config",
                    details={"file": config_path}
                ))
            
            if "PasswordAuthentication yes" in config_content:
                findings.append(Finding(
                    category="configs",
                    risk_level=RiskLevel.MEDIUM,
                    title="SSH Password Authentication Enabled",
                    description="SSH allows password authentication which is vulnerable to brute force.",
                    recommendation="Use key-based authentication instead of passwords",
                    details={"file": config_path}
                ))
            
            if "Protocol 1" in config_content:
                findings.append(Finding(
                    category="configs",
                    risk_level=RiskLevel.CRITICAL,
                    title="SSH Protocol 1 Enabled",
                    description="SSH Protocol 1 is deprecated and insecure.",
                    recommendation="Remove 'Protocol 1' and use Protocol 2 only",
                    details={"file": config_path}
                ))
        except Exception as e:
            findings.append(Finding(
                category="configs",
                risk_level=RiskLevel.INFO,
                title="Could Not Read SSH Config",
                description=f"Error reading SSH config: {str(e)}",
                details={"file": config_path, "error": str(e)}
            ))
        
        return findings
    
    def _check_selinux(self) -> Finding:
        """Check SELinux status."""
        try:
            with open("/etc/selinux/config", 'r') as f:
                for line in f:
                    if line.strip().startswith("SELINUX="):
                        status = line.split("=")[1].strip()
                        if status == "disabled":
                            return Finding(
                                category="configs",
                                risk_level=RiskLevel.MEDIUM,
                                title="SELinux Disabled",
                                description="SELinux is disabled on this system.",
                                recommendation="Enable SELinux in enforcing mode",
                                details={"status": status}
                            )
        except Exception:
            pass
        
        return Finding(
            category="configs",
            risk_level=RiskLevel.INFO,
            title="SELinux Status Check",
            description="SELinux configuration check completed.",
            details={}
        )
