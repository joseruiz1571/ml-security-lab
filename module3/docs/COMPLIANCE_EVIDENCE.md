# Compliance Evidence Package: HealthTech Innovations

**Project:** Patient Cardiovascular Risk Assessment Model
**Version:** 1.0 (Secure)
**Date:** January 2026

---

## 1. License Compliance

### 1.1 License Summary

| License Type | Package Count | Compatibility |
|--------------|---------------|---------------|
| BSD-3-Clause | 18 | Permissive - Compatible |
| MIT | 10 | Permissive - Compatible |
| Apache-2.0 | 7 | Permissive - Compatible |
| LGPL-3.0 | 1 | Review Required |
| HPND | 1 | Permissive - Compatible |
| MPL-2.0 | 1 | Weak Copyleft - Compatible |

### 1.2 Compliance Status

**Overall Status:** COMPLIANT WITH EXCEPTIONS

**Exception:** `psycopg2-binary` uses LGPL-3.0 license
- **Risk Level:** LOW
- **Rationale:** Package is used dynamically, not statically linked
- **Alternative:** Consider `asyncpg` (Apache-2.0) for future versions
- **Decision:** Approved for use with documentation

### 1.3 Prohibited Licenses

The following licenses are prohibited in this project:

| License | Reason | Status |
|---------|--------|--------|
| GPL-2.0 | Strong copyleft | NOT PRESENT |
| GPL-3.0 | Strong copyleft | NOT PRESENT |
| AGPL-3.0 | Network copyleft | NOT PRESENT |
| SSPL | Non-OSI approved | NOT PRESENT |

### 1.4 SBOM Artifacts

| File | Format | Location |
|------|--------|----------|
| sbom.csv | CSV | reports/sbom.csv |
| licenses.json | JSON | reports/licenses.json |

---

## 2. Security Scan Evidence

### 2.1 Bandit Scan Results

**Scan Command:**
```bash
bandit -r module3/secure/ -f txt
```

**Result:** PASS - No issues identified

**Evidence File:** `reports/secure_scan_results.txt`

### 2.2 Safety Dependency Scan

**Scan Command:**
```bash
safety check -r module3/secure/requirements.txt
```

**Result:** PASS - 0 vulnerabilities found

**Evidence File:** `reports/secure_scan_results.txt`

### 2.3 Semgrep Custom Rules

**Scan Command:**
```bash
semgrep --config module2/rules/ module3/secure/
```

**Result:** PASS - No issues detected

**Rules Applied:**
- pickle-vulnerabilities.yaml (6 rules)
- tensorflow-vulnerabilities.yaml (6 rules)
- hardcoded-secrets.yaml (10 rules)

---

## 3. Remediation Evidence

### 3.1 Vulnerability Remediation Matrix

| Finding ID | CWE | Vulnerable Code | Secure Code | Verified |
|------------|-----|-----------------|-------------|----------|
| F001 | CWE-798 | Hardcoded DB_PASSWORD | os.getenv('DB_PASSWORD') | YES |
| F002 | CWE-798 | Hardcoded FHIR_API_KEY | os.getenv('FHIR_API_KEY') | YES |
| F003 | CWE-798 | Hardcoded AWS_ACCESS_KEY | os.getenv('AWS_ACCESS_KEY_ID') | YES |
| F004 | CWE-502 | pickle.load() | joblib.load() | YES |
| F005 | CWE-89 | f-string SQL | Parameterized query | YES |
| F006 | CWE-78 | eval() | Direct calculation | YES |
| F007 | CWE-327 | hashlib.md5() | hashlib.sha256() | YES |
| F008 | CWE-330 | random.choices() | secrets.token_urlsafe() | YES |
| F009 | CWE-703 | assert statements | if/raise validation | YES |
| F010 | CWE-78 | subprocess shell=True | Function removed | YES |

### 3.2 Code Diff Summary

```
Vulnerable Version: risk_model.py
Lines of Code: 264
Security Issues: 17

Secure Version: risk_model_secure.py
Lines of Code: 322
Security Issues: 0

Changes:
+ Added get_config() for environment variables
+ Added _validate_input() method
+ Added REQUIRED_FEATURES and FEATURE_CONSTRAINTS
+ Changed pickle to joblib
+ Changed MD5 to SHA-256
+ Changed random to secrets
+ Changed f-string SQL to parameterized
+ Removed eval() and subprocess shell=True
```

---

## 4. Dependency Update Evidence

### 4.1 Version Comparison

| Package | Vulnerable | Secure | CVEs Fixed |
|---------|------------|--------|------------|
| scikit-learn | 0.20.0 | 1.3.0+ | CVE-2019-20891 |
| flask | 0.12.2 | 2.3.0+ | CVE-2018-1000656 |
| werkzeug | 0.15.3 | 2.3.0+ | CVE-2019-14806 |
| jinja2 | 2.10 | 3.1.2+ | CVE-2019-10906 |
| requests | 2.19.1 | 2.31.0+ | CVE-2018-18074 |
| urllib3 | 1.24.1 | 2.0.0+ | CVE-2019-11236, CVE-2020-26137 |
| cryptography | 2.1.4 | 41.0.0+ | CVE-2018-10903, CVE-2023-23931, CVE-2023-38325 |
| pillow | 6.2.0 | 10.0.0+ | CVE-2020-5313, CVE-2020-10177, CVE-2021-25289, CVE-2022-22817, CVE-2023-44271 |
| pyjwt | 1.5.0 | 2.8.0+ | CVE-2017-11424 |
| pyyaml | 5.1 | 6.0.1+ | CVE-2020-14343 |

### 4.2 Dependency Update Commands

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install secure dependencies
pip install -r module3/secure/requirements.txt

# Verify no vulnerabilities
safety check

# Generate SBOM
pip-licenses --format=csv --output-file=reports/sbom.csv
pip-licenses --format=json --output-file=reports/licenses.json
```

---

## 5. Configuration Evidence

### 5.1 Environment Variables Required

```bash
# Database Configuration
DB_HOST=<database_host>
DB_USER=<database_user>
DB_PASSWORD=<database_password>
DB_NAME=<database_name>

# API Keys
FHIR_API_KEY=<fhir_api_key>

# AWS Configuration
AWS_REGION=us-east-1
S3_MODEL_BUCKET=<s3_bucket_name>

# AWS credentials should use IAM roles in production
# AWS_ACCESS_KEY_ID=<only_for_local_development>
# AWS_SECRET_ACCESS_KEY=<only_for_local_development>
```

### 5.2 .env.example Provided

Location: `module3/secure/.env.example`

---

## 6. Testing Evidence

### 6.1 Security Test Cases

| Test ID | Description | Expected Result | Actual Result |
|---------|-------------|-----------------|---------------|
| SEC-001 | SQL injection attempt | Query rejected | PASS |
| SEC-002 | Path traversal attempt | ValueError raised | PASS |
| SEC-003 | Invalid patient ID format | Validation error | PASS |
| SEC-004 | Out-of-range feature values | ValueError raised | PASS |
| SEC-005 | Load model without .joblib | Extension error | PASS |
| SEC-006 | Missing environment variable | None returned | PASS |

### 6.2 Functional Test Cases

| Test ID | Description | Expected Result | Actual Result |
|---------|-------------|-----------------|---------------|
| FUNC-001 | Train model with valid data | Model trained | PASS |
| FUNC-002 | Predict with valid input | Risk probability | PASS |
| FUNC-003 | Save model to file | .joblib created | PASS |
| FUNC-004 | Load model from file | Model loaded | PASS |
| FUNC-005 | Hash patient ID | SHA-256 hash | PASS |
| FUNC-006 | Generate session token | 32-byte token | PASS |

---

## 7. Approval Signatures

### 7.1 Security Review

| Role | Name | Date | Approval |
|------|------|------|----------|
| Security Engineer | [Reviewer Name] | January 2026 | APPROVED |
| Security Architect | [Reviewer Name] | January 2026 | APPROVED |

### 7.2 Compliance Review

| Role | Name | Date | Approval |
|------|------|------|----------|
| Compliance Officer | [Reviewer Name] | January 2026 | APPROVED |
| Privacy Officer | [Reviewer Name] | January 2026 | APPROVED |

### 7.3 Technical Review

| Role | Name | Date | Approval |
|------|------|------|----------|
| Tech Lead | [Reviewer Name] | January 2026 | APPROVED |
| ML Engineer | [Reviewer Name] | January 2026 | APPROVED |

---

## 8. Artifact Inventory

| Artifact | Location | Purpose |
|----------|----------|---------|
| Vulnerable Code | module3/vulnerable/risk_model.py | Baseline for comparison |
| Secure Code | module3/secure/risk_model_secure.py | Production-ready code |
| Vulnerable Deps | module3/vulnerable/requirements.txt | CVE demonstration |
| Secure Deps | module3/secure/requirements.txt | Updated dependencies |
| SBOM (CSV) | module3/reports/sbom.csv | Bill of materials |
| SBOM (JSON) | module3/reports/licenses.json | License details |
| Vuln Scan Report | module3/reports/vulnerable_scan_results.txt | Before remediation |
| Secure Scan Report | module3/reports/secure_scan_results.txt | After remediation |
| Security Report | module3/docs/SECURITY_REPORT.md | Full assessment |
| Compliance Evidence | module3/docs/COMPLIANCE_EVIDENCE.md | This document |

---

## 9. Attestation

I attest that the information contained in this compliance evidence package is accurate and complete to the best of my knowledge. The security remediation has been verified through automated scanning and manual review.

**Prepared By:** Security Engineering Team
**Date:** January 2026
**Version:** 1.0

---

*This document is part of the HealthTech Innovations security compliance package and should be retained for audit purposes.*
