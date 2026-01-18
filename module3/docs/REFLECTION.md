# Module 3 Reflection: Secure Healthcare ML Pipeline

**Author:** Jose Ruiz-Vazquez
**Date:** January 2026

---

## What I Learned

### 1. The Gap Between Vulnerable and Secure Code

Building both the vulnerable baseline and secure version showed me how much intentional effort security requires. The vulnerable code was actually easier to write - just dump credentials, use pickle, concatenate SQL strings. Making code secure requires:

- Thinking about attack vectors before writing code
- Adding validation layers that feel like "extra work"
- Choosing secure libraries over convenient ones
- Writing more code to do the same functionality safely

**Key Insight:** Security is not the default. It must be deliberately designed in.

### 2. SBOM and License Compliance Matter

Before this exercise, I understood SBOMs conceptually from a GRC perspective. Now I see them as practical tools:

- 34 packages in my simple ML application
- 18 CVEs in the vulnerable dependencies
- 1 LGPL license requiring review (psycopg2-binary)

**Key Insight:** Every `pip install` brings risk. SBOMs make that risk visible.

### 3. Static Analysis Has Limits

Bandit and Semgrep caught many issues, but they:
- Can't detect business logic flaws
- Miss some context-dependent vulnerabilities
- Produce false positives that require human judgment
- Need custom rules for domain-specific patterns

**Key Insight:** Tools are aids, not replacements for security thinking.

### 4. Remediation Patterns Are Repeatable

The same fixes apply across different applications:

| Problem | Solution |
|---------|----------|
| Hardcoded secrets | Environment variables |
| pickle.load() | joblib.load() or safetensors |
| f-string SQL | Parameterized queries |
| eval() | Direct calculation |
| MD5 | SHA-256 |
| random | secrets |

**Key Insight:** Learn the secure patterns once, apply them everywhere.

---

## Challenges Faced

### 1. Version Pinning Balance

The vulnerable requirements.txt used old, specific versions (e.g., `flask==0.12.2`). The secure version uses minimum versions (e.g., `flask>=2.3.0`). In real environments, you need to balance:
- Security (latest versions)
- Stability (tested versions)
- Compatibility (working together)

### 2. LGPL License Decision

The psycopg2-binary package uses LGPL, which can be problematic for some organizations. I documented this as "review required" rather than removing it, because:
- It's dynamically linked (LGPL compliant)
- The alternative (asyncpg) would require code changes
- Real-world decisions involve trade-offs

### 3. Making Vulnerable Code "Realistic"

Writing intentionally vulnerable code that looks realistic was harder than expected. Real developers don't usually write `# VULNERABILITY: This is insecure`. The vulnerabilities had to be plausible mistakes.

---

## Application to GRC Role

### 1. Policy Development

Now I can write more specific security policies:
- "All credentials must be loaded from environment variables or secrets managers"
- "Model serialization must use joblib with signature verification"
- "All SQL queries must use parameterized statements"

These are actionable, testable requirements rather than vague guidance.

### 2. Vendor Assessment

When evaluating AI/ML vendors, I can ask:
- "How do you serialize and deserialize models?"
- "What static analysis tools are in your CI/CD pipeline?"
- "Can you provide an SBOM for your application?"

### 3. Audit Evidence

This lab created the kind of evidence auditors want:
- Before/after scan comparisons
- Documented remediation steps
- License compliance matrices
- Version-controlled security controls

---

## What I Would Do Differently

### 1. Start with the Secure Version

In a real project, I would write secure code from the beginning rather than building vulnerable code to fix. "Shift left" means designing security in, not bolting it on.

### 2. Add Automated Testing

The secure version has input validation but no unit tests. In practice, I would add:
- Tests that verify SQL injection attempts fail
- Tests that verify invalid inputs raise exceptions
- Integration tests with the security scanning tools

### 3. Implement Model Signing

The secure version validates file extensions and paths, but doesn't implement full HMAC signature verification. This would be the next security control to add.

---

## Key Takeaways

1. **Security is a practice, not a product.** Tools help, but security requires intentional design decisions.

2. **The vulnerable path is the easy path.** Secure code requires more effort upfront but prevents costly breaches later.

3. **GRC and technical security are connected.** Understanding both makes policies more effective and technical controls more aligned with business needs.

4. **Documentation is part of security.** Evidence packages, SBOMs, and remediation reports are as important as the code itself.

5. **Start somewhere, keep learning.** I still have much to learn about ML security, but this lab gave me practical skills I can use immediately.

---

## Next Steps

- [ ] Complete remaining Coursera course modules
- [ ] Set up these scans in my own development workflow
- [ ] Share learning with GRC team members
- [ ] Explore more advanced topics (model poisoning, adversarial attacks)
- [ ] Build additional custom Semgrep rules for our organization's patterns

---

*"Security is not about being perfect. It's about being better than yesterday."*
