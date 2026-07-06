# 🔍 Ironwall Security Audit Report

**Target:** `.`  
**Date:** 2026-07-07 01:27:12  
**Duration:** 948ms  
**Tool Version:** ironwall v0.4.0  

## 📊 Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 5 |
| 🟠 HIGH | 4 |
| 🟡 MEDIUM | 9 |
| 🟢 LOW | 3 |
| ℹ️ INFO | 3 |
| **Total** | **24** |

## 🔴 CRITICAL Findings

### IRON-001: Unauthenticated ANY endpoint: /admin/users

**File:** `testdata\go-vuln\hardcoded_secret.go:64`  
**Category:** missing-auth  
**CWE:** CWE-306  
**CVSS:** 9.8  

**Code:**
```
64 | http.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
```

---

### IRON-004: Potential DB connection string with credentials

**File:** `testdata\go-vuln\hardcoded_secret.go:82`  
**Category:** hardcoded-credentials  
**CWE:** CWE-798  
**CVSS:** 9.8  

**Code:**
```
82 | _ = "mysql://admin:SuperSecret123!@localhost:3306/mydb"
```

---

### IRON-007: Potential Internal URL with credentials

**File:** `testdata\go-vuln\hardcoded_secret.go:91`  
**Category:** hardcoded-credentials  
**CWE:** CWE-798  
**CVSS:** 9.8  

**Code:**
```
91 | _ = "https://admin:password123@internal-api.company.com/v1"
```

---

### IRON-012: TLS verification disabled in .env

**File:** `testdata\go-vuln\.env:9`  
**Category:** insecure-configuration  
**CWE:** CWE-16  
**CVSS:** 9.8  

**Code:**
```
9 | NODE_TLS_REJECT_UNAUTHORIZED=0
```

**Fix:**
Enable TLS verification. Remove InsecureSkipVerify or set verify_ssl to true.

---

### IRON-016: Exposed Docker daemon socket in docker-compose.yml

**File:** `testdata\go-vuln\docker-compose.yml:10`  
**Category:** insecure-configuration  
**CWE:** CWE-16  
**CVSS:** 9.8  

**Code:**
```
10 | - /var/run/docker.sock:/var/run/docker.sock
```

**Fix:**
Remove Docker socket mount unless absolutely necessary. Use docker-api-proxy instead.

---

## 🟠 HIGH Findings

### IRON-002: Unauthenticated ANY endpoint: /api/delete-user

**File:** `testdata\go-vuln\hardcoded_secret.go:69`  
**Category:** missing-auth  
**CWE:** CWE-306  
**CVSS:** 7.5  

**Code:**
```
69 | http.HandleFunc("/api/delete-user", func(w http.ResponseWriter, r *http.Request) {
```

---

### IRON-003: Potential Generic API key in config

**File:** `testdata\go-vuln\hardcoded_secret.go:14`  
**Category:** hardcoded-secret  
**CWE:** CWE-798  
**CVSS:** 7.5  

**Code:**
```
14 | var apiKey = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
```

---

### IRON-006: Potential OAuth client secret pattern

**File:** `testdata\go-vuln\hardcoded_secret.go:88`  
**Category:** hardcoded-secret  
**CWE:** CWE-798  
**CVSS:** 7.5  

**Code:**
```
88 | _ = `{"client_secret": "GOCSPX-abcdefghijklmnopqrstuvwxyz"}`
```

---

### IRON-020: Excessive GRANT permissions in 001_init.sql

**File:** `testdata\go-vuln\migrations\001_init.sql:20`  
**Category:** privilege-escalation  
**CWE:** CWE-250  
**CVSS:** 7.5  

**Code:**
```
20 | GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user;
```

**Fix:**
Grant only the specific permissions needed (SELECT, INSERT, UPDATE, DELETE).

---

## 🟡 MEDIUM Findings

### IRON-005: Potential Hex-encoded secret (32+ hex chars as string)

**File:** `testdata\go-vuln\hardcoded_secret.go:85`  
**Category:** hardcoded-secret  
**CWE:** CWE-798  
**CVSS:** 5.0  

**Code:**
```
85 | _ = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
```

**Attack Scenario:**
- **Actor:** Anyone with access to the source code
- **Path:** Read the file, extract the credential, use it to access the target service
- **Impact:** Unauthorized access to the protected service

---

### IRON-009: Debug mode enabled in .env

**File:** `testdata\go-vuln\.env:2`  
**Category:** debug-mode-enabled  
**CWE:** CWE-489  
**CVSS:** 5.0  

**Code:**
```
2 | DEBUG=true
```

**Fix:**
Set DEBUG=false or APP_DEBUG=false in production.

---

### IRON-010: Debug mode enabled in .env

**File:** `testdata\go-vuln\.env:3`  
**Category:** debug-mode-enabled  
**CWE:** CWE-489  
**CVSS:** 5.0  

**Code:**
```
3 | APP_DEBUG=true
```

**Fix:**
Set DEBUG=false or APP_DEBUG=false in production.

---

### IRON-011: CORS wildcard origin in .env

**File:** `testdata\go-vuln\.env:6`  
**Category:** cors-misconfiguration  
**CWE:** CWE-942  
**CVSS:** 5.0  

**Code:**
```
6 | CORS_ORIGIN=*
```

**Fix:**
Specify explicit allowed origins instead of wildcard.

---

### IRON-014: Debug mode enabled in Dockerfile

**File:** `testdata\go-vuln\Dockerfile:10`  
**Category:** debug-mode-enabled  
**CWE:** CWE-489  
**CVSS:** 5.0  

**Code:**
```
10 | ENV DEBUG=true
```

**Fix:**
Set DEBUG=false or APP_DEBUG=false in production.

---

### IRON-015: Debug mode enabled in Dockerfile

**File:** `testdata\go-vuln\Dockerfile:11`  
**Category:** debug-mode-enabled  
**CWE:** CWE-489  
**CVSS:** 5.0  

**Code:**
```
11 | ENV APP_DEBUG=true
```

**Fix:**
Set DEBUG=false or APP_DEBUG=false in production.

---

### IRON-017: Debug mode enabled in docker-compose.yml

**File:** `testdata\go-vuln\docker-compose.yml:12`  
**Category:** debug-mode-enabled  
**CWE:** CWE-489  
**CVSS:** 5.0  

**Code:**
```
12 | - DEBUG=true
```

**Fix:**
Set DEBUG=false or APP_DEBUG=false in production.

---

### IRON-018: CORS wildcard origin in docker-compose.yml

**File:** `testdata\go-vuln\docker-compose.yml:13`  
**Category:** cors-misconfiguration  
**CWE:** CWE-942  
**CVSS:** 5.0  

**Code:**
```
13 | - CORS_ORIGIN=*
```

**Fix:**
Specify explicit allowed origins instead of wildcard.

---

### IRON-023: Unpinned GitHub Action in release.yml

**File:** `.github/workflows/release.yml:0`  
**Category:** supply-chain  
**CWE:** CWE-1104  
**CVSS:** 5.0  

**Fix:**
Pin actions to full commit SHA: uses: actions/checkout@a81bb... instead of @v4

**References:**
- https://github.com/stepsecurity/secure-workflows

---

## 🟢 LOW Findings

### IRON-013: Unsafe Docker COPY in Dockerfile

**File:** `testdata\go-vuln\Dockerfile:4`  
**Category:** insecure-configuration  
**CWE:** CWE-16  
**CVSS:** 2.5  

**Code:**
```
4 | COPY . .
```

**Fix:**
Use .dockerignore file to exclude sensitive files from Docker build context.

---

### IRON-019: AUTOINCREMENT without protection in 001_init.sql

**File:** `testdata\go-vuln\migrations\001_init.sql:4`  
**Category:** information-disclosure  
**CWE:** CWE-200  
**CVSS:** 2.5  

**Code:**
```
4 | id SERIAL PRIMARY KEY,           -- AUTOINCREMENT without UUID
```

**Fix:**
Consider using UUID or ULID for primary keys in user-facing tables.

---

### IRON-022: 10/10 recent commits are not GPG signed

**File:** `.git:0`  
**Category:** supply-chain  
**CWE:** CWE-1104  
**CVSS:** 2.0  

**Fix:**
Configure git GPG signing: git config --global commit.gpgsign true

**References:**
- https://docs.github.com/en/authentication/managing-commit-signature-verification

---

## ℹ️ INFO Findings

### IRON-008: SBOM generated: 38 components detected

**File:** `sbom.cdx.json:0`  
**Category:** sbom  

**References:**
- https://github.com/anchore/syft

---

### IRON-021: SBOM generation available via syft

**File:** `.:0`  
**Category:** sbom  

**Fix:**
syft scan . -o cyclonedx-json > sbom.cdx.json

**References:**
- https://github.com/anchore/syft

---

### IRON-024: OpenSSF Scorecard not installed

**File:** `.:0`  
**Category:** supply-chain  

**Fix:**
go install github.com/ossf/scorecard/v5@latest

**References:**
- https://securityscorecards.dev/

---


---

*Report generated by [Ironwall v0.4.0](https://github.com/FYFran/ironwall) — 8-Step Security Audit CLI*
