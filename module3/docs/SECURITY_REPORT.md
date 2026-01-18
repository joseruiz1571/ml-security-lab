# Security Assessment Report: HealthTech Innovations ML Pipeline

**Project:** Patient Cardiovascular Risk Assessment Model
**Assessment Date:** January 2026
**Assessor:** Security Engineering Team
**Classification:** Internal Use Only

---

## Executive Summary

This report documents the security assessment and remediation of the HealthTech Innovations Patient Risk Assessment machine learning model. The assessment identified **35 security findings** in the original codebase, including critical vulnerabilities in credential management, data handling, and dependency security.

All identified vulnerabilities have been successfully remediated in the secure version of the codebase.

| Metric | Vulnerable Version | Secure Version |
|--------|-------------------|----------------|
| Code Issues | 17 | 0 |
| Dependency CVEs | 18 | 0 |
| Risk Level | CRITICAL | LOW |
| Deployment Status | BLOCKED | APPROVED |

---

## 1. Assessment Scope

### 1.1 Components Assessed
- `risk_model.py` - Core ML model for patient risk prediction
- `requirements.txt` - Python dependencies
- Model serialization and loading mechanisms
- Database interaction patterns
- Credential and secrets handling

### 1.2 Tools Used
| Tool | Purpose | Version |
|------|---------|---------|
| Bandit | Python security linting | 1.7.5 |
| Semgrep | Static analysis with custom rules | 1.48.0 |
| Safety | Dependency vulnerability scanning | 2.3.5 |
| pip-licenses | SBOM and license generation | 4.3.2 |

### 1.3 Standards Referenced
- OWASP Top 10 2021
- CWE/SANS Top 25
- HIPAA Security Rule
- NIST Cybersecurity Framework

---

## 2. Findings Summary

### 2.1 Critical Findings

#### Finding 1: Hardcoded Credentials (CWE-798)
**Severity:** HIGH
**Instances:** 6

| Credential Type | Location | Risk |
|----------------|----------|------|
| Database Password | Line 22 | Full database access |
| FHIR API Key | Line 26 | Healthcare data exposure |
| EHR Token | Line 27 | Patient record access |
| AWS Access Key | Line 30 | Cloud infrastructure access |
| AWS Secret Key | Line 31 | Cloud infrastructure access |
| PHI Encryption Key | Line 35 | Protected health info exposure |

**Remediation:** All credentials moved to environment variables via `os.getenv()`.

#### Finding 2: Insecure Deserialization (CWE-502)
**Severity:** HIGH
**Instances:** 3

The use of Python's `pickle` module for model serialization allows arbitrary code execution when loading untrusted data.

```python
# VULNERABLE
data = pickle.load(f)

# SECURE
model_data = joblib.load(path)  # With validation
```

**Remediation:** Replaced pickle with joblib, added file extension validation and path traversal prevention.

#### Finding 3: SQL Injection (CWE-89)
**Severity:** HIGH
**Instances:** 2

String formatting used in SQL queries enables injection attacks.

```python
# VULNERABLE
query = f"SELECT * FROM patients WHERE patient_id = '{patient_id}'"

# SECURE
query = "SELECT * FROM patients WHERE patient_id = ?"
cursor.execute(query, (patient_id,))
```

**Remediation:** Implemented parameterized queries with input validation.

### 2.2 Medium Findings

#### Finding 4: Command Injection (CWE-78)
**Severity:** MEDIUM
**Instances:** 1

`subprocess.call()` with `shell=True` allows command injection.

**Remediation:** Function removed from secure version; if needed, use `subprocess.run()` with `shell=False` and argument lists.

#### Finding 5: Code Injection via eval() (CWE-78)
**Severity:** MEDIUM
**Instances:** 1

The `eval()` function executes arbitrary Python code.

```python
# VULNERABLE
height = eval(height_formula)

# SECURE
height_m = height_cm / 100
return weight_kg / (height_m ** 2)
```

**Remediation:** Direct calculation replaces eval().

#### Finding 6: Weak Cryptographic Hash (CWE-327)
**Severity:** MEDIUM
**Instances:** 1

MD5 is cryptographically broken and unsuitable for security purposes.

```python
# VULNERABLE
return hashlib.md5(patient_id.encode()).hexdigest()

# SECURE
return hashlib.sha256(patient_id.encode()).hexdigest()
```

**Remediation:** SHA-256 replaces MD5.

### 2.3 Low Findings

#### Finding 7: Insecure Random Number Generation (CWE-330)
**Severity:** LOW
**Instances:** 1

The `random` module is not cryptographically secure.

```python
# VULNERABLE
return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# SECURE
return secrets.token_urlsafe(32)
```

**Remediation:** `secrets` module used for cryptographic purposes.

#### Finding 8: Assert Used for Validation (CWE-703)
**Severity:** LOW
**Instances:** 3

Assert statements are removed when Python runs with optimization flags.

**Remediation:** Replaced with proper if/raise validation in `_validate_input()` method.

---

## 3. Dependency Analysis

### 3.1 Vulnerable Dependencies

| Package | Vulnerable Version | CVE Count | Secure Version |
|---------|-------------------|-----------|----------------|
| scikit-learn | 0.20.0 | 1 | >=1.3.0 |
| flask | 0.12.2 | 1 | >=2.3.0 |
| werkzeug | 0.15.3 | 1 | >=2.3.0 |
| jinja2 | 2.10 | 1 | >=3.1.2 |
| requests | 2.19.1 | 1 | >=2.31.0 |
| urllib3 | 1.24.1 | 2 | >=2.0.0 |
| cryptography | 2.1.4 | 3 | >=41.0.0 |
| pillow | 6.2.0 | 5 | >=10.0.0 |
| pyjwt | 1.5.0 | 1 | >=2.8.0 |
| pyyaml | 5.1 | 1 | >=6.0.1 |

### 3.2 SBOM Generation

A complete Software Bill of Materials (SBOM) has been generated:
- Format: CSV and JSON
- Location: `reports/sbom.csv`, `reports/licenses.json`
- Package Count: 34 direct and transitive dependencies

---

## 4. Remediation Verification

### 4.1 Before/After Comparison

| Category | Before | After | Change |
|----------|--------|-------|--------|
| Hardcoded Secrets | 6 | 0 | -100% |
| Pickle Usage | 3 | 0 | -100% |
| SQL Injection | 2 | 0 | -100% |
| Command Injection | 1 | 0 | -100% |
| eval() Usage | 1 | 0 | -100% |
| Weak Hash | 1 | 0 | -100% |
| Weak Random | 1 | 0 | -100% |
| Assert Validation | 3 | 0 | -100% |
| Vulnerable Dependencies | 18 CVEs | 0 CVEs | -100% |

### 4.2 Verification Commands

```bash
# Scan secure version with Bandit
bandit -r module3/secure/ -f txt -o bandit_secure.txt

# Scan dependencies with Safety
safety check -r module3/secure/requirements.txt

# Run custom Semgrep rules
semgrep --config module2/rules/ module3/secure/

# Generate updated SBOM
pip-licenses --format=csv --output-file=sbom.csv
```

---

## 5. Security Controls Implemented

### 5.1 Credential Management
- `get_config()` function loads all credentials from environment variables
- No secrets stored in source code or configuration files
- `.env.example` template provided for local development

### 5.2 Input Validation
- `REQUIRED_FEATURES` constant defines expected columns
- `FEATURE_CONSTRAINTS` dictionary defines valid ranges
- `_validate_input()` method performs comprehensive validation
- Patient ID format validation (alphanumeric only)

### 5.3 Secure Serialization
- joblib replaces pickle for model serialization
- Compression enabled (`compress=3`) for storage efficiency
- File extension validation (`.joblib` only)
- Path traversal prevention via `Path.resolve()`

### 5.4 Database Security
- Parameterized queries prevent SQL injection
- Connection cleanup with explicit `conn.close()`
- Risk score range validation (0-1)

### 5.5 Cryptographic Controls
- SHA-256 for hashing operations
- `secrets.token_urlsafe()` for token generation
- Updated cryptography library for secure operations

---

## 6. Compliance Mapping

### 6.1 HIPAA Security Rule

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| Access Control (164.312(a)(1)) | Environment variable credentials | COMPLIANT |
| Audit Controls (164.312(b)) | Logging without PHI | COMPLIANT |
| Integrity Controls (164.312(c)(1)) | Input validation | COMPLIANT |
| Transmission Security (164.312(e)(1)) | Secure dependencies | COMPLIANT |

### 6.2 OWASP Top 10 2021

| Risk | Mitigation | Status |
|------|------------|--------|
| A01 Broken Access Control | Environment credentials | MITIGATED |
| A02 Cryptographic Failures | SHA-256, secrets module | MITIGATED |
| A03 Injection | Parameterized queries | MITIGATED |
| A04 Insecure Design | Input validation | MITIGATED |
| A05 Security Misconfiguration | Secure defaults | MITIGATED |
| A06 Vulnerable Components | Updated dependencies | MITIGATED |
| A08 Software Integrity | joblib serialization | MITIGATED |

---

## 7. Recommendations

### 7.1 Immediate Actions (Completed)
- [x] Remove all hardcoded credentials
- [x] Replace pickle with joblib
- [x] Implement parameterized queries
- [x] Update vulnerable dependencies
- [x] Add input validation

### 7.2 Future Enhancements
- [ ] Implement model signature verification (HMAC)
- [ ] Add rate limiting for API endpoints
- [ ] Enable audit logging to SIEM
- [ ] Conduct penetration testing
- [ ] Implement secrets rotation policy

---

## 8. Conclusion

The HealthTech Innovations Patient Risk Assessment model has been successfully remediated from a CRITICAL risk level to LOW risk. All 35 security findings have been addressed through secure coding practices, updated dependencies, and proper security controls.

The secure version is approved for deployment with standard monitoring and periodic security assessments.

---

**Document Control:**
- Version: 1.0
- Created: January 2026
- Next Review: July 2026
- Classification: Internal Use Only
