# ML Security Lab - Static Analysis Pipeline

**Coursera Assignment: Secure AI Code & Libraries with Static Analysis**

This lab demonstrates building a comprehensive security scanning pipeline for an ML/AI codebase using industry-standard static analysis tools.

## Overview

VulnAI is a fictional ML startup with an intentionally vulnerable codebase used to demonstrate security scanning capabilities. The lab includes:

- **4 Python files** with 50+ intentional security vulnerabilities
- **4 security scanners** (Bandit, Semgrep, PyLint, Safety)
- **GitHub Actions CI/CD workflow** for automated scanning
- **Comprehensive security report** with remediation guidance

## Project Structure

```
ml-security-lab/
├── train_model.py           # ML training pipeline (vulnerable)
├── data_loader.py           # Data loading utilities (vulnerable)
├── model_server.py          # Flask API server (vulnerable)
├── utils.py                 # Utility functions (vulnerable)
├── requirements.txt         # Dependencies with known CVEs
├── SECURITY_REPORT.md       # Detailed vulnerability analysis
├── .github/
│   └── workflows/
│       └── security-scan.yml  # CI/CD security pipeline
└── security-reports/        # Generated scan outputs
    ├── bandit_report.json
    ├── semgrep_report.json
    ├── pylint_report.json
    └── safety_report.json
```

## Vulnerabilities Demonstrated

| Category | CWE | Count | Example |
|----------|-----|-------|---------|
| Hardcoded Credentials | CWE-259 | 15+ | AWS keys, API tokens |
| Command Injection | CWE-78 | 12 | subprocess with shell=True |
| Code Injection | CWE-94 | 6 | eval(), exec() |
| Unsafe Deserialization | CWE-502 | 8 | pickle.load() |
| SQL Injection | CWE-89 | 6 | f-string in queries |
| XML External Entity | CWE-611 | 3 | ElementTree.parse() |
| Path Traversal | CWE-22 | 4 | tarfile.extractall() |
| Weak Cryptography | CWE-327 | 8 | MD5, SHA1, DES |
| Insecure SSL | CWE-295 | 5 | verify=False |
| Vulnerable Dependencies | - | 486 | Outdated packages |

## Security Scanners Used

### 1. Bandit (Python Security Linter)
```bash
bandit -r . -f json -o bandit_report.json
```
**Detects:** Hardcoded passwords, unsafe deserialization, command injection, weak crypto

### 2. Semgrep (SAST)
```bash
semgrep --config=auto . --json -o semgrep_report.json
```
**Detects:** Injection vulnerabilities, security misconfigurations, unsafe patterns

### 3. PyLint (Code Quality)
```bash
pylint *.py --output-format=json > pylint_report.json
```
**Detects:** Code quality issues, potential bugs, security anti-patterns

### 4. Safety (Dependency Scanner)
```bash
safety check -r requirements.txt --output json > safety_report.json
```
**Detects:** Known CVEs in dependencies

## Scan Results Summary

| Scanner | High | Medium | Low | Total |
|---------|------|--------|-----|-------|
| Bandit | 28 | 28 | 33 | 89 |
| Semgrep | 18 | 16 | 12 | 46 |
| PyLint | 8 | 15 | 20 | 43 |
| Safety | 486 | - | - | 486 |

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/security-scan.yml`) provides:

- **Automatic scanning** on push/PR to main
- **Weekly scheduled scans** for dependency updates
- **Artifact retention** of reports for 30 days
- **Job summary** with key findings
- **Secrets detection** with TruffleHog
- **Dependency review** on pull requests

## Running Locally

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install security tools
pip install bandit semgrep pylint safety

# Run all scans
bandit -r . -f txt --exclude ./venv
semgrep --config=auto . --exclude venv
pylint *.py
safety check -r requirements.txt
```

## Key Learnings

1. **Defense in Depth**: Multiple scanners catch different vulnerability types
2. **Shift Left**: Scanning early in CI/CD prevents production issues
3. **Dependency Management**: Most vulnerabilities come from dependencies
4. **False Positives**: Triage findings; not all are exploitable
5. **Remediation Priority**: Focus on high-severity + easy-to-fix first

## OWASP Top 10 Coverage

| OWASP 2021 | Covered |
|------------|---------|
| A01: Broken Access Control | Yes |
| A02: Cryptographic Failures | Yes |
| A03: Injection | Yes |
| A04: Insecure Design | Yes |
| A05: Security Misconfiguration | Yes |
| A06: Vulnerable Components | Yes |
| A07: Auth Failures | Yes |
| A08: Data Integrity Failures | Yes |

## Author

**Jose Ruiz-Vazquez**
AI Governance & Security Professional
ISO 42001:2023 Lead Auditor
