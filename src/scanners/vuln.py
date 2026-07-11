"""Vulnerability scanning module."""

import re
import subprocess
import platform
from typing import Dict, List, Any, Optional
from ..audit.engine import Finding, RiskLevel


class VulnerabilityScanner:
    """Scan for known vulnerabilities and misconfigurations."""
    
    category = "vulnerabilities"
    
    KNOWN_VULNS = {
        "openssl": {
            "versions": ["1.0.1", "1.0.2"],
            "cve": "CVE-2014-0160",
            "description": "Heartbleed vulnerability in OpenSSL",
            "severity": RiskLevel.CRITICAL
        },
        "openssh": {
            "versions": ["6.6", "6.7", "6.8"],
            "cve": "CVE-2016-0777",
            "description": "OpenSSH information leak vulnerability",
            "severity": RiskLevel.HIGH
        }
    }
    
    def __init__(self):
        self.system = platform.system().lower()
    
    def run(self, target: str, config: Dict[str, Any]) -> List[Finding]:
        """Run vulnerability scans."""
        findings = []
        
        findings.extend(self._check_outdated_software())
        findings.extend(self._check_insecure_services())
        findings.extend(self._check_weak_crypto())
        
        return findings
    
    def _check_outdated_software(self) -> List[Finding]:
        """Check for outdated software with known vulnerabilities."""
        findings = []
        
        if self.system == "linux":
            findings.extend(self._check_linux_packages())
        
        return findings
    
    def _check_linux_packages(self) -> List[Finding]:
        """Check Linux packages for vulnerabilities."""
        findings = []
        
        try:
            result = subprocess.run(
                ["dpkg", "-l"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            for package, vuln_info in self.KNOWN_VULNS.items():
                for line in result.stdout.split('\n'):
                    if package in line.lower():
                        for version in vuln_info["versions"]:
                            if version in line:
                                findings.append(Finding(
                                    category="vulnerabilities",
                                    risk_level=vuln_info["severity"],
                                    title=f"Vulnerable Package: {package}",
                                    description=vuln_info["description"],
                                    recommendation=f"Update {package} to the latest version",
                                    details={
                                        "package": package,
                                        "cve": vuln_info["cve"],
                                        "affected_versions": vuln_info["versions"]
                                    }
                                ))
                                break
        
        except Exception:
            pass
        
        return findings
    
    def _check_insecure_services(self) -> List[Finding]:
        """Check for insecure services running."""
        findings = []
        
        insecure_services = {
            "telnet": RiskLevel.HIGH,
            "ftp": RiskLevel.MEDIUM,
            "rsh": RiskLevel.HIGH,
            "rlogin": RiskLevel.HIGH,
            "rexec": RiskLevel.HIGH
        }
        
        for service, risk in insecure_services.items():
            if self._is_service_running(service):
                findings.append(Finding(
                    category="vulnerabilities",
                    risk_level=risk,
                    title=f"Insecure Service Running: {service}",
                    description=f"The {service} service is running and may pose security risks.",
                    recommendation=f"Disable {service} service if not required",
                    details={"service": service}
                ))
        
        return findings
    
    def _is_service_running(self, service_name: str) -> bool:
        """Check if a service is running."""
        try:
            if self.system == "linux":
                result = subprocess.run(
                    ["systemctl", "is-active", service_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.stdout.strip() == "active"
            elif self.system == "windows":
                result = subprocess.run(
                    ["sc", "query", service_name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return "RUNNING" in result.stdout
        except Exception:
            pass
        
        return False
    
    def _check_weak_crypto(self) -> List[Finding]:
        """Check for weak cryptographic configurations."""
        findings = []
        
        ssh_config = "/etc/ssh/sshd_config"
        try:
            if __import__('os').path.exists(ssh_config):
                with open(ssh_config, 'r') as f:
                    content = f.read()
                
                weak_ciphers = ["des", "3des", "rc4", "arcfour"]
                for cipher in weak_ciphers:
                    if cipher in content.lower():
                        findings.append(Finding(
                            category="vulnerabilities",
                            risk_level=RiskLevel.MEDIUM,
                            title=f"Weak Cipher Enabled: {cipher}",
                            description=f"Weak cipher {cipher} is enabled in SSH configuration.",
                            recommendation=f"Disable {cipher} cipher and use stronger alternatives",
                            details={"cipher": cipher, "file": ssh_config}
                        ))
        except Exception:
            pass
        
        return findings
