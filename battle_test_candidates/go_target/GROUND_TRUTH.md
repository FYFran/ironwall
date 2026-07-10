# Ground Truth — go_target

Deliberately vulnerable Go web application for Ironwall Phase B battle testing.
12 vulnerabilities, 8 CWE categories, 2 safe control endpoints.

## Vulnerability Inventory

| GT-ID | CWE | Severity | Handler | File:Line | Description |
|-------|-----|----------|---------|-----------|-------------|
| GT-001 | CWE-798 | CRITICAL | — | main.go:33 | Hardcoded database password `admin123!@#Secret` |
| GT-002 | CWE-798 | CRITICAL | — | main.go:36 | Hardcoded API key `sk-abc123def...` |
| GT-003 | CWE-89 | CRITICAL | handleLogin | main.go:78 | SQL injection — username concatenated into query |
| GT-004 | CWE-79 | HIGH | handleSearch | main.go:97 | XSS — user input reflected without escaping |
| GT-005 | CWE-78 | CRITICAL | handleExec | main.go:115 | Command injection — `bash -c` with user input |
| GT-006 | CWE-22 | HIGH | handleFiles | main.go:131 | Path traversal — user filename joined to path |
| GT-007 | CWE-918 | HIGH | handleProxy | main.go:148 | SSRF — user URL passed to http.Get |
| GT-008 | CWE-306 | HIGH | handleAdminUsers | main.go:166 | Missing authentication on admin endpoint |
| GT-009 | CWE-328 | MEDIUM | handleHash | main.go:191 | MD5 used for hashing (should be bcrypt/argon2) |
| GT-010 | CWE-798 | CRITICAL | handleLogin | main.go:78 | Password checked in SQL query (no hashing) |
| GT-011 | CWE-200 | MEDIUM | handleLogin | main.go:81 | User enumeration via different error responses |
| GT-012 | CWE-209 | LOW | handleExec | main.go:118 | Error message leaks command output detail |

## Safe Endpoints (Controls)

| Endpoint | Handler | Expected |
|----------|---------|----------|
| GET /api/health | handleHealth | No findings |
| GET / | handleIndex | No findings (or INFO only) |

## API Endpoints Summary

| Method | Path | Vulnerability | Handler |
|--------|------|--------------|---------|
| POST | /api/login | SQLi (GT-003), no password hashing (GT-010), user enum (GT-011) | handleLogin |
| GET | /api/search?query= | XSS (GT-004) | handleSearch |
| GET | /api/exec?cmd= | Command Injection (GT-005) | handleExec |
| GET | /api/files?filename= | Path Traversal (GT-006) | handleFiles |
| GET | /api/proxy?url= | SSRF (GT-007) | handleProxy |
| GET | /api/admin/users | Missing Auth (GT-008) | handleAdminUsers |
| GET | /api/hash?input= | Weak Crypto MD5 (GT-009) | handleHash |
| GET | /api/health | — (safe) | handleHealth |
| GET | / | — (safe) | handleIndex |

## What We're Testing

### SAST tools (semgrep + gosec) should find:
- GT-001, GT-002: Hardcoded secrets (gitleaks, gosec G101)
- GT-003: SQL injection (semgrep, gosec G201)
- GT-005: Command injection (semgrep, gosec G204)
- GT-006: Path traversal (gosec G304)
- GT-007: SSRF (gosec G107)
- GT-009: Weak crypto MD5 (gosec G401)

### SAST tools will likely MISS:
- GT-004: XSS in raw Write() — no Go scanner detects this pattern well
- GT-008: Missing auth — semantic understanding required
- GT-010: Password not hashed — semantic understanding required
- GT-011: User enumeration — business logic
- GT-012: Error info leak — context-dependent

### Phase B (OBSERVE→TRACE→VERIFY) SHOULD find:
- OBSERVE catches all handlers (SQL, command, file, HTTP, crypto, input, SSRF concerns)
- TRACE should identify data flow: input→sink for GT-003, GT-004, GT-005, GT-006, GT-007
- VERIFY should confirm these are real vulnerabilities

### Success Criteria for Phase B:
- **Recall ≥ 0.50**: At least 6/12 ground truth vulns found
- **New discoveries**: At least 2 vulns that SAST missed (GT-004 XSS, GT-008 missing auth, GT-010 no hashing, GT-011 user enum)
- **Precision ≥ 0.50**: At most 1 false positive per real vuln
