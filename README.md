# Security Audit CLI

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-orange.svg)](CONTRIBUTING.md)

A comprehensive command-line security auditing tool that performs automated security assessments across multiple categories including port scanning, configuration analysis, and permission checks.

## Features

- **Port Scanning**: Detect open ports and running services
- **Configuration Audit**: Check system configurations against security baselines
- **Permission Analysis**: Identify insecure file and directory permissions
- **Service Detection**: Identify running services and their versions
- **Vulnerability Reporting**: Generate detailed security reports in multiple formats
- **Extensible Architecture**: Add custom security checks via plugins

## Architecture

```
security-audit-cli/
├── src/
│   ├── audit/           # Core audit engine
│   │   ├── __init__.py
│   │   ├── engine.py    # Main audit orchestrator
│   │   └── report.py    # Report generation
│   ├── checks/          # Security check modules
│   │   ├── __init__.py
│   │   ├── ports.py     # Port scanning checks
│   │   ├── configs.py   # Configuration checks
│   │   └── perms.py     # Permission checks
│   └── scanners/        # Vulnerability scanners
│       ├── __init__.py
│       └── vuln.py      # Vulnerability detection
├── cli.py               # CLI entry point
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .gitignore
```

## Installation

### From Source

```bash
git clone https://github.com/janderik/security-audit-cli.git
cd security-audit-cli
pip install -r requirements.txt
```

### Using Docker

```bash
docker build -t security-audit-cli .
docker run -it security-audit-cli --target 192.168.1.1
```

## Usage

### Basic Audit

```bash
python cli.py --target 192.168.1.1
```

### Specific Checks

```bash
# Port scanning only
python cli.py --target 192.168.1.1 --checks ports

# Configuration audit
python cli.py --target localhost --checks configs

# Permission analysis
python cli.py --target /path/to/directory --checks perms
```

### Output Formats

```bash
# JSON output
python cli.py --target 192.168.1.1 --output json --report results.json

# HTML report
python cli.py --target 192.168.1.1 --output html --report audit.html

# Console output (default)
python cli.py --target 192.168.1.1 --output console
```

### Verbose Mode

```bash
python cli.py --target 192.168.1.1 --verbose
```

## Audit Categories

| Category | Description | Risk Levels |
|----------|-------------|-------------|
| Ports | Open port detection | Low, Medium, High |
| Configs | Configuration analysis | Info, Warning, Critical |
| Perms | Permission checks | Low, Medium, High |
| Services | Service enumeration | Info |
| Vulnerabilities | CVE detection | Medium, High, Critical |

## Output Example

```
==============================================
  Security Audit Report
  Target: 192.168.1.1
  Date: 2024-01-15 10:30:00
==============================================

[PORTS] Scanning ports 1-1024...
  [HIGH] Port 22 (SSH) - Open
  [MEDIUM] Port 80 (HTTP) - Open
  [MEDIUM] Port 443 (HTTPS) - Open
  [INFO] Port 3306 (MySQL) - Open

[CONFIGS] Checking configurations...
  [WARNING] SSH root login enabled
  [CRITICAL] Firewall disabled
  [INFO] SELinux status: disabled

[PERMS] Analyzing permissions...
  [HIGH] /etc/passwd - World readable
  [MEDIUM] /etc/shadow - Group readable

==============================================
  Summary: 4 High, 3 Medium, 2 Low, 2 Info
==============================================
```

## Configuration

Create a `config.yaml` file to customize audit behavior:

```yaml
scan:
  ports: "1-65535"
  timeout: 5
  threads: 10

checks:
  ports: true
  configs: true
  perms: true
  services: true

output:
  format: console
  verbose: false
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before performing security audits on any system.
