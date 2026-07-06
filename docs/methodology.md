# 🔍 Ironwall Methodology — 7-Step Security Audit

## Overview

Ironwall follows a **7-step gated pipeline** inspired by professional security audit workflows. Each step builds on the previous, creating a layered defense-in-depth approach to code security.

## Why 7 Steps?

Most security scanners run a single tool (gitleaks, semgrep, or npm audit). Real security audits use multiple tools, cross-reference findings, and apply human judgment. Ironwall automates this workflow:

1. **Automated scanners** (Steps 1, 5) — deterministic, zero false negatives
2. **AI-assisted analysis** (Steps 2, 3, 4, 6, 7) — semantic understanding, pattern recognition
3. **Verification layer** (Attack Scenario Three Questions) — filters false positives

## The Pipeline

### Step 1: Secret Scanning (gitleaks)
**Tool:** gitleaks
**TIER:** 1 (failure = abort scan)

Scans for:
- API keys (AWS, GitHub, OpenAI, etc.)
- Passwords and credentials
- Private keys (RSA, EC, DSA, OpenSSH)
- JWT secrets and signing keys
- Database connection strings

**Why gitleaks first?** Credential leaks are the most impactful and most commonly missed vulnerability. If gitleaks can't run, nothing else should — it means the environment is broken.

### Step 2: SAST Analysis (semgrep + AI)
**Tool:** semgrep + AI review

Semgrep runs pattern-based static analysis. AI reviews findings to filter false positives:
- Is the vulnerable code reachable? (not dead code, not test fixtures)
- Is user input sanitized before reaching the sink?
- Is this in a test file?

**Why semgrep + AI?** Semgrep is fast and accurate but produces false positives. AI provides semantic understanding to distinguish real vulnerabilities from safe patterns.

### Step 3: Endpoint Audit
**Tool:** AI + regex route detection

Extracts API route definitions from 8 frameworks (Go-chi, Go-gin, Go-gorilla, Go-stdlib, Python-Flask/FastAPI, Node-Express) and checks:
- **Authentication:** Is auth middleware present?
- **Authorization:** Who can access this endpoint?
- **Sensitivity:** Does it handle admin/user/payment data?

Flags write operations (POST/PUT/DELETE) and sensitive paths without auth.

### Step 4: Hardcoded Secrets (Deep Scan)
**Tool:** Regex + AI

Catches secrets that gitleaks missed:
- Database connection strings with embedded credentials
- OAuth client secrets in code
- Hex-encoded secrets (32+ chars)
- FTP/email credentials
- Encryption keys inline
- Internal URLs with auth tokens
- AWS account IDs in strings

**Why after gitleaks?** These patterns are higher-noise — more false positives. Running after Step 1 means gitleaks already caught the obvious ones.

### Step 5: Dependency CVE
**Tool:** govulncheck / npm audit / pip-audit

Checks known vulnerabilities in:
- Go dependencies (via govulncheck)
- Node.js dependencies (via npm audit)
- Python dependencies (via pip-audit)

Auto-detects project ecosystem from lockfiles.

### Step 6: Server Configuration
**Tool:** Regex rules

Analyzes configuration files:
- **TLS/SSL:** InsecureSkipVerify, verify_ssl=false
- **Debug mode:** DEBUG=true in production
- **CORS:** Wildcard origins
- **Docker:** Running as root, socket exposure, unsafe COPY
- **Ports:** Database ports exposed publicly

### Step 7: Database Audit
**Tool:** Regex rules

Analyzes SQL migration files:
- **Dangerous operations:** DROP TABLE, TRUNCATE
- **SQL injection:** Dynamic SQL (EXECUTE IMMEDIATE, sp_executesql)
- **Weak crypto:** MD5/SHA1 for passwords
- **Permissions:** GRANT ALL, excessive privileges
- **Schema:** Missing foreign key constraints, plaintext password columns

## Attack Scenario Verification

The core IP of Ironwall. Every finding above MEDIUM severity must pass **three questions:**

### Q1: Actor — Who can exploit this?

Must name a specific role or access level:
- ✅ "Unauthenticated remote attacker"
- ✅ "Logged-in user with viewer role"
- ❌ "Anyone" (too vague)

### Q2: Path — What are the exact steps?

Must trace a concrete attack path:
- ✅ "1. Send POST to /api/login with crafted JSON. 2. SQL injection in username field. 3. Extract JWT secret from database."
- ❌ "Exploit the vulnerability to gain access" (no steps)

### Q3: Impact — What does the attacker gain?

Must state specific, measurable impact:
- ✅ "Full database dump including 50K user records with password hashes"
- ❌ "Information disclosure" (too vague)

### Verdict

| Q1 | Q2 | Q3 | Verdict |
|----|----|----|---------|
| ✅ Concrete | ✅ Concrete | ✅ Concrete | **REAL vulnerability** |
| ✅ Concrete | ✅ Concrete | ❌ Vague | **Likely real, downgrade confidence** |
| ✅ Concrete | ❌ No path | ❌ Vague | **Probable false positive** |
| ❌ Vague | ❌ No path | ❌ Vague | **False positive — filter out** |

## Gotchas Library

Patterns that scanners miss — see [gotchas.md](gotchas.md).

## Signal Attenuation Management

The 7-step pipeline is designed to minimize signal loss:

1. **TIER1 gating** — Step 1 failure aborts the scan. No partial results.
2. **Tool diversity** — Different tools catch different things. No single point of failure.
3. **AI as filter, not detector** — AI reviews scanner output; scanners do the detection.
4. **Heuristic fallback** — When AI is unavailable, rule-based attack scenarios provide reasonable assessments.
5. **Severity downgrade chain** — Test files → -1 severity. Low AI confidence → -1 severity. Comment context → skip.

## Comparison to Other Approaches

| | Typical Scanner | Pentest Tool | Ironwall |
|---|---|---|---|
| **Approach** | Run 1 tool | Exploit simulation | **7-step pipeline** |
| **False positives** | High | Low (PoC verified) | **Filtered by 3 questions** |
| **Coverage** | Narrow (1 tool) | Wide (exploit all) | **Layered (7 perspectives)** |
| **Speed** | Seconds | Hours | **~30s (quick) / ~5min (full)** |
| **Cost** | Free | $50-500/scan | **Free (MIT)** |

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [semgrep](https://semgrep.dev)
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln)
