"""Port scanning security checks."""

import socket
from typing import Dict, List, Any, Optional
from ..audit.engine import Finding, RiskLevel


class PortCheck:
    """Check for open ports and running services."""
    
    category = "ports"
    
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    
    RISK_PORTS = {
        21: RiskLevel.MEDIUM,
        23: RiskLevel.HIGH,
        135: RiskLevel.MEDIUM,
        139: RiskLevel.MEDIUM,
        445: RiskLevel.MEDIUM,
        3389: RiskLevel.MEDIUM,
        5900: RiskLevel.HIGH
    }
    
    def __init__(self, timeout: float = 1.0, common_only: bool = True):
        self.timeout = timeout
        self.common_only = common_only
    
    def run(self, target: str, config: Dict[str, Any]) -> List[Finding]:
        """Run port scan on target."""
        findings = []
        
        ports_to_scan = list(self.COMMON_PORTS.keys()) if self.common_only else range(1, 1024)
        
        for port in ports_to_scan:
            if self._is_port_open(target, port):
                service = self.COMMON_PORTS.get(port, "Unknown")
                risk = self.RISK_PORTS.get(port, RiskLevel.INFO)
                
                finding = Finding(
                    category="ports",
                    risk_level=risk,
                    title=f"Port {port} ({service}) - Open",
                    description=f"Port {port} is open and running {service} service.",
                    recommendation=self._get_recommendation(port, service),
                    details={"port": port, "service": service}
                )
                findings.append(finding)
        
        return findings
    
    def _is_port_open(self, host: str, port: int) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, socket.gaierror):
            return False
    
    def _get_recommendation(self, port: int, service: str) -> str:
        """Get security recommendation for open port."""
        recommendations = {
            21: "Consider using SFTP instead of FTP. FTP transmits credentials in plaintext.",
            23: "Telnet is insecure. Disable Telnet and use SSH instead.",
            135: "MSRPC should be blocked by firewall unless specifically needed.",
            139: "NetBIOS should be disabled if not required for file sharing.",
            445: "SMB should be restricted to internal network only.",
            3389: "RDP should be accessed via VPN or restricted by IP.",
            5900: "VNC should be tunneled through SSH or VPN."
        }
        return recommendations.get(port, f"Review if {service} service is required.")
