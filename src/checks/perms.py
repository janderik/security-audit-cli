"""File permission security checks."""

import os
import stat
from typing import Dict, List, Any
from ..audit.engine import Finding, RiskLevel


class PermissionCheck:
    """Check file and directory permissions."""
    
    category = "perms"
    
    SENSITIVE_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/root/.ssh/authorized_keys"
    ]
    
    def __init__(self, check_world_writable: bool = True, check_suid: bool = True):
        self.check_world_writable = check_world_writable
        self.check_suid = check_suid
    
    def run(self, target: str, config: Dict[str, Any]) -> List[Finding]:
        """Run permission checks."""
        findings = []
        
        for filepath in self.SENSITIVE_FILES:
            if os.path.exists(filepath):
                findings.extend(self._check_file_permissions(filepath))
        
        if self.check_world_writable:
            findings.extend(self._check_world_writable_dirs(target))
        
        if self.check_suid:
            findings.extend(self._check_suid_files(target))
        
        return findings
    
    def _check_file_permissions(self, filepath: str) -> List[Finding]:
        """Check permissions on a specific file."""
        findings = []
        
        try:
            file_stat = os.stat(filepath)
            mode = file_stat.st_mode
            
            if mode & stat.S_IROTH:
                findings.append(Finding(
                    category="perms",
                    risk_level=RiskLevel.HIGH,
                    title=f"World Readable: {filepath}",
                    description=f"File {filepath} is readable by all users.",
                    recommendation=f"Set permissions to 640 or stricter: chmod 640 {filepath}",
                    details={"file": filepath, "mode": oct(mode)}
                ))
            
            if mode & stat.S_IWOTH:
                findings.append(Finding(
                    category="perms",
                    risk_level=RiskLevel.CRITICAL,
                    title=f"World Writable: {filepath}",
                    description=f"File {filepath} is writable by all users.",
                    recommendation=f"Remove world write permission: chmod o-w {filepath}",
                    details={"file": filepath, "mode": oct(mode)}
                ))
            
            if mode & stat.S_IXOTH:
                if not stat.S_ISDIR(mode):
                    findings.append(Finding(
                        category="perms",
                        risk_level=RiskLevel.MEDIUM,
                        title=f"World Executable: {filepath}",
                        description=f"File {filepath} is executable by all users.",
                        recommendation=f"Remove world execute permission: chmod o-x {filepath}",
                        details={"file": filepath, "mode": oct(mode)}
                    ))
            
            if filepath == "/etc/shadow":
                if mode & stat.S_IROTH or mode & stat.S_IRGRP:
                    findings.append(Finding(
                        category="perms",
                        risk_level=RiskLevel.CRITICAL,
                        title="Shadow File Readable",
                        description="/etc/shadow contains password hashes and should only be readable by root.",
                        recommendation="Set permissions to 640: chmod 640 /etc/shadow",
                        details={"file": filepath, "mode": oct(mode)}
                    ))
        
        except Exception as e:
            findings.append(Finding(
                category="perms",
                risk_level=RiskLevel.INFO,
                title=f"Permission Check Failed: {filepath}",
                description=f"Could not check permissions: {str(e)}",
                details={"file": filepath, "error": str(e)}
            ))
        
        return findings
    
    def _check_world_writable_dirs(self, path: str) -> List[Finding]:
        """Check for world-writable directories."""
        findings = []
        
        if not os.path.isdir(path):
            return findings
        
        try:
            for root, dirs, files in os.walk(path):
                if len(findings) > 10:
                    break
                
                for d in dirs:
                    dirpath = os.path.join(root, d)
                    try:
                        if os.path.islink(dirpath):
                            continue
                        
                        mode = os.stat(dirpath).st_mode
                        if mode & stat.S_IWOTH:
                            findings.append(Finding(
                                category="perms",
                                risk_level=RiskLevel.MEDIUM,
                                title=f"World Writable Directory: {dirpath}",
                                description=f"Directory {dirpath} is writable by all users.",
                                recommendation=f"Remove world write permission: chmod o-w {dirpath}",
                                details={"directory": dirpath, "mode": oct(mode)}
                            ))
                    except PermissionError:
                        continue
        except Exception:
            pass
        
        return findings
    
    def _check_suid_files(self, path: str) -> List[Finding]:
        """Check for SUID/SGID files."""
        findings = []
        
        if not os.path.isdir(path):
            return findings
        
        try:
            for root, dirs, files in os.walk(path):
                if len(findings) > 10:
                    break
                
                for f in files:
                    filepath = os.path.join(root, f)
                    try:
                        if os.path.islink(filepath):
                            continue
                        
                        mode = os.stat(filepath).st_mode
                        
                        if mode & stat.S_ISUID:
                            findings.append(Finding(
                                category="perms",
                                risk_level=RiskLevel.MEDIUM,
                                title=f"SUID File: {filepath}",
                                description=f"File {filepath} has SUID bit set.",
                                recommendation="Review if SUID bit is necessary",
                                details={"file": filepath, "mode": oct(mode)}
                            ))
                        
                        if mode & stat.S_ISGID:
                            findings.append(Finding(
                                category="perms",
                                risk_level=RiskLevel.LOW,
                                title=f"SGID File: {filepath}",
                                description=f"File {filepath} has SGID bit set.",
                                recommendation="Review if SGID bit is necessary",
                                details={"file": filepath, "mode": oct(mode)}
                            ))
                    except PermissionError:
                        continue
        except Exception:
            pass
        
        return findings
