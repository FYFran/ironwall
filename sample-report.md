# 🔍 Ironwall Security Audit Report

**Target:** `./testdata/go-vuln`  
**Date:** 2026-07-07 00:24:00  
**Duration:** 159ms  
**Tool Version:** ironwall v0.2.0  

## 📊 Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 5 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 9 |
| 🟢 LOW | 2 |
| ℹ️ INFO | 0 |
| **Total** | **19** |

## 🔴 CRITICAL Findings

### IRON-002: Unauthenticated ANY endpoint: /admin/users

**File:** `hardcoded_secret.go:64`  
**Category:** missing-auth  
**CWE:** CWE-306  
**CVSS:** 9.8  

**Code:**
```
64 | http.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
```

---

### IRON-004: Potential DB connection string with credentials

**File:** `hardcoded_secret.go:82`  
**Category:** hardcoded-credentials  
**CWE:** CWE-798  
**CVSS:** 9.8  

**Code:**
```
82 | _ = "mysql://admin:SuperSecret123!@localhost:3306/mydb"
```

---

### IRON-007: Potential Internal URL with credentials

**File:** `hardcoded_secret.go:91`  
**Category:** hardcoded-credentials  
**CWE:** CWE-798  
**CVSS:** 9.8  

**Code:**
```
91 | _ = "https://admin:password123@internal-api.company.com/v1"
```

---

### IRON-011: TLS verification disabled in .env

**File:** `.env:9`  
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

### IRON-015: Exposed Docker daemon socket in docker-compose.yml

**File:** `docker-compose.yml:10`  
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

### IRON-003: Unauthenticated ANY endpoint: /api/delete-user

**File:** `hardcoded_secret.go:69`  
**Category:** missing-auth  
**CWE:** CWE-306  
**CVSS:** 7.5  

**Code:**
```
69 | http.HandleFunc("/api/delete-user", func(w http.ResponseWriter, r *http.Request) {
```

---

### IRON-006: Potential OAuth client secret pattern

**File:** `hardcoded_secret.go:88`  
**Category:** hardcoded-secret  
**CWE:** CWE-798  
**CVSS:** 7.5  

**Code:**
```
88 | _ = `{"client_secret": "GOCSPX-abcdefghijklmnopqrstuvwxyz"}`
```

---

### IRON-019: Excessive GRANT permissions in 001_init.sql

**File:** `migrations\001_init.sql:20`  
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

### IRON-GITLEAKS-001: Secret detected: Detected a Generic API Key, potentially exposing access to various services and sensitive operations.

**File:** `testdata/go-vuln/hardcoded_secret.go:14`  
**Category:** secret-detected  
**CWE:** CWE-312  
**CVSS:** 5.0  

**Code:**
```
14 | sk-a*******************************************x234
```

**References:**
- https://github.com/gitleaks/gitleaks

---

### IRON-005: Potential Hex-encoded secret (32+ hex chars as string)

**File:** `hardcoded_secret.go:85`  
**Category:** hardcoded-secret  
**CWE:** CWE-798  
**CVSS:** 5.0  

**Code:**
```
85 | _ = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
```

**Attack Scenario:**
- **Actor:** Anyone with access to the source code (public repo, leaked code, former employee)
- **Path:** 1. Read hardcoded_secret.go
2. Extract Potential Hex-encoded secret (32+ hex chars as string) from line 85
3. Use the credential to access the target service
- **Impact:** Unauthorized access to the service protected by this credential. Potential data breach, resource abuse, or lateral movement.

---

### IRON-008: Debug mode enabled in .env

**File:** `.env:2`  
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

### IRON-009: Debug mode enabled in .env

**File:** `.env:3`  
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

### IRON-010: CORS wildcard origin in .env

**File:** `.env:6`  
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

### IRON-013: Debug mode enabled in Dockerfile

**File:** `Dockerfile:10`  
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

### IRON-014: Debug mode enabled in Dockerfile

**File:** `Dockerfile:11`  
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

### IRON-016: Debug mode enabled in docker-compose.yml

**File:** `docker-compose.yml:12`  
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

### IRON-017: CORS wildcard origin in docker-compose.yml

**File:** `docker-compose.yml:13`  
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

## 🟢 LOW Findings

### IRON-012: Unsafe Docker COPY in Dockerfile

**File:** `Dockerfile:4`  
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

### IRON-018: AUTOINCREMENT without protection in 001_init.sql

**File:** `migrations\001_init.sql:4`  
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


---

*Report generated by [Ironwall v0.2.0](https://github.com/FYFran/ironwall) — 7-Step Security Audit CLI*
