#!/usr/bin/env python3
"""Security Audit CLI - Command line interface for security auditing."""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.audit.engine import AuditEngine
from src.audit.report import ReportGenerator
from src.checks import PortCheck, ConfigCheck, PermissionCheck
from src.scanners import VulnerabilityScanner


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Security Audit CLI - Automated security assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.1
  %(prog)s --target localhost --checks ports,configs
  %(prog)s --target 192.168.1.1 --output json --report audit.json
  %(prog)s --target /path/to/dir --checks perms --verbose
        """
    )
    
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP address, hostname, or directory path"
    )
    
    parser.add_argument(
        "--checks", "-c",
        help="Comma-separated list of checks to run (ports,configs,perms,vulns)"
    )
    
    parser.add_argument(
        "--output", "-o",
        choices=["console", "json", "html"],
        default="console",
        help="Output format (default: console)"
    )
    
    parser.add_argument(
        "--report", "-r",
        help="Output file path for report"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )
    
    parser.add_argument(
        "--ports",
        default="common",
        help="Port range to scan: 'common', 'top100', or '1-1024' (default: common)"
    )
    
    return parser.parse_args()


def setup_checks(args):
    """Initialize and configure check modules."""
    checks = []
    
    check_types = args.checks.split(",") if args.checks else ["ports", "configs", "perms", "vulns"]
    
    if "ports" in check_types:
        common_only = args.ports == "common"
        checks.append(PortCheck(timeout=args.timeout, common_only=common_only))
    
    if "configs" in check_types:
        checks.append(ConfigCheck())
    
    if "perms" in check_types:
        checks.append(PermissionCheck())
    
    if "vulns" in check_types:
        checks.append(VulnerabilityScanner())
    
    return checks


def main():
    """Main entry point."""
    args = parse_args()
    
    print(f"\nSecurity Audit CLI v1.0.0")
    print(f"Target: {args.target}")
    print(f"Checks: {args.checks or 'all'}")
    print("-" * 50)
    
    engine = AuditEngine(target=args.target)
    
    checks = setup_checks(args)
    for check in checks:
        engine.register_check(check)
    
    print("Running audit...")
    result = engine.run_audit()
    
    generator = ReportGenerator(result)
    
    if args.output == "console":
        report = generator.to_console()
        print(report)
    elif args.output == "json":
        report = generator.to_json()
        if args.report:
            with open(args.report, 'w') as f:
                f.write(report)
            print(f"Report saved to {args.report}")
        else:
            print(report)
    elif args.output == "html":
        report = generator.to_html()
        if args.report:
            with open(args.report, 'w') as f:
                f.write(report)
            print(f"Report saved to {args.report}")
        else:
            print("HTML output requires --report flag to specify output file")
    
    print(f"\nAudit completed in {engine.get_duration():.2f} seconds")
    
    summary = result.get_summary()
    if summary.get("critical", 0) > 0 or summary.get("high", 0) > 0:
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
