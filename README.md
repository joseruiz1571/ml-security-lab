# ML Security Lab

**Coursera Course:** Secure AI Code & Libraries with Static Analysis
**Author:** Jose Ruiz-Vazquez
**Date:** January 2026

---

## Overview

This repository contains hands-on security lab exercises for the Coursera course "Secure AI Code & Libraries with Static Analysis." The labs demonstrate common security vulnerabilities in machine learning applications and their remediation.

## Course Modules

| Module | Topic | Scenario |
|--------|-------|----------|
| [Module 1](module1/) | Introduction to ML Security Scanning | VulnAI Startup - AI-powered chatbot |
| [Module 2](module2/) | Advanced Static Analysis & Custom Rules | CryptoTrade Pro - Cryptocurrency trading platform |
| [Module 3](module3/) | Secure ML Pipeline & Compliance | HealthTech Innovations - Healthcare risk assessment |

---

## Module 1: VulnAI Startup

**Scenario:** New employee security audit of an AI-powered customer service chatbot.

**Skills Practiced:**
- Running Bandit for Python security linting
- Using Semgrep with community rules
- Scanning dependencies with Safety
- Basic vulnerability triage

**Key Findings:**
- Hardcoded API credentials
- Unsafe pickle deserialization
- SQL injection vulnerabilities

---

## Module 2: CryptoTrade Pro

**Scenario:** Security assessment of a cryptocurrency trading platform with ML models.

**Skills Practiced:**
- Writing custom Semgrep rules (YAML)
- Scanning Jupyter notebooks for secrets
- TensorFlow/Keras model security
- Advanced pickle vulnerability detection

**Deliverables:**
- Custom Semgrep rule files (3 YAML files, 22 rules)
- AI Vulnerability Assessment Report
- Remediated secure code

**Custom Rules Developed:**
```
module2/rules/
├── pickle-vulnerabilities.yaml     # 6 rules for deserialization
├── tensorflow-vulnerabilities.yaml # 6 rules for ML frameworks
└── hardcoded-secrets.yaml          # 10 rules for credentials
```

---

## Module 3: HealthTech Innovations

**Scenario:** Building a secure healthcare ML pipeline with compliance requirements.

**Skills Practiced:**
- Before/after security comparison
- SBOM (Software Bill of Materials) generation
- License compliance analysis
- HIPAA-aligned security controls
- Comprehensive security documentation

**Deliverables:**
- Vulnerable baseline code for comparison
- Fully remediated secure code
- SBOM in CSV and JSON formats
- Security assessment report
- Compliance evidence package

**Compliance Standards:**
- HIPAA Security Rule
- OWASP Top 10 2021
- CWE/SANS Top 25

---

## Tools Used

| Tool | Purpose | Installation |
|------|---------|--------------|
| Bandit | Python security linter | `pip install bandit` |
| Semgrep | Static analysis with custom rules | `pip install semgrep` |
| Safety | Dependency vulnerability scanner | `pip install safety` |
| pip-licenses | SBOM and license generation | `pip install pip-licenses` |
| PyLint | Code quality and security | `pip install pylint` |

## Quick Start

```bash
# Clone the repository
cd grc-tools/ml-security-lab

# Install scanning tools
pip install bandit semgrep safety pip-licenses

# Scan Module 1 vulnerable code
bandit -r module1/vulnerable/ -f txt

# Scan Module 2 with custom rules
semgrep --config module2/rules/ module2/vulnerable/

# Check Module 3 dependencies
safety check -r module3/vulnerable/requirements.txt

# Generate SBOM
pip-licenses --format=csv --output-file=sbom.csv
```

---

## Directory Structure

```
ml-security-lab/
├── README.md                    # This file
├── module1/                     # VulnAI Startup
│   ├── vulnerable/              # Intentionally vulnerable code
│   ├── reports/                 # Scan results
│   └── .github/workflows/       # CI/CD security pipeline
├── module2/                     # CryptoTrade Pro
│   ├── vulnerable/              # Vulnerable code + notebook
│   ├── remediated/              # Secure code examples
│   ├── rules/                   # Custom Semgrep rules
│   └── reports/                 # Assessment reports
└── module3/                     # HealthTech Healthcare
    ├── vulnerable/              # Baseline vulnerable code
    ├── secure/                  # Fully remediated code
    ├── reports/                 # Scan results + SBOM
    └── docs/                    # Security documentation
```

---

## Key Learning Outcomes

### Security Concepts
- CWE-502: Deserialization of Untrusted Data
- CWE-798: Use of Hard-coded Credentials
- CWE-89: SQL Injection
- CWE-78: Command Injection
- CWE-327: Use of Broken Cryptographic Algorithm

### Secure Coding Practices
- Environment variables for credentials
- Parameterized SQL queries
- joblib/safetensors instead of pickle
- Input validation patterns
- SHA-256 for hashing
- secrets module for tokens

### Compliance & Documentation
- SBOM generation
- License compatibility analysis
- Security assessment reports
- Before/after remediation evidence

---

## Vulnerability Summary

| Category | Module 1 | Module 2 | Module 3 | Total |
|----------|----------|----------|----------|-------|
| Hardcoded Credentials | 3 | 8 | 6 | 17 |
| Pickle Deserialization | 1 | 5 | 3 | 9 |
| SQL Injection | 1 | 2 | 2 | 5 |
| Command Injection | 0 | 2 | 1 | 3 |
| Weak Crypto | 0 | 1 | 2 | 3 |
| Dependency CVEs | 12 | 15 | 18 | 45 |

---

## About the Author

**Jose Ruiz-Vazquez**
GRC Professional learning practical security skills to bridge the gap between compliance requirements and technical implementation.

**Learning Journey:**
- Started with non-technical GRC background
- Building hands-on security scanning skills
- Creating practical examples for other GRC professionals

---

## Disclaimer

This repository contains **intentionally vulnerable code** for educational purposes. The vulnerable code demonstrates security anti-patterns and should **NEVER** be used in production systems.

All credentials shown are fake and used only for demonstration.

---

## License

This project is for educational purposes as part of Coursera coursework.
