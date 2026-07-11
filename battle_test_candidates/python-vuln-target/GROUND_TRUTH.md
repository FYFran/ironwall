# Ground Truth — python-vuln-target

> 10 planted vulnerabilities for Ironwall recall/precision measurement.
> Date: 2026-07-11

---

## Planted Vulnerabilities

### VULN-1: SQL Injection — LIKE search (line ~33)
- **Route**: GET /api/users?username=
- **CWE**: CWE-89
- **Code**: `f"SELECT ... WHERE username LIKE '%{username}%'"`
- **Exploit**: `?username=' UNION SELECT 1,2,3--`
- **Severity**: HIGH

### VULN-1b: SQL Injection — Login bypass (line ~47)
- **Route**: POST /api/login
- **CWE**: CWE-89
- **Code**: password interpolated into SQL after MD5
- **Exploit**: `{"username": "admin", "password": "' OR '1'='1"}`
- **Severity**: CRITICAL

### VULN-2: SSTI — render_template_string (line ~61)
- **Route**: GET /greet?name=
- **CWE**: CWE-1336
- **Code**: `render_template_string(f"<h1>Hello, {name}!</h1>")`
- **Exploit**: `?name={{config.items()}}`
- **Severity**: CRITICAL

### VULN-2b: SSTI — User-Agent reflection (line ~71)
- **Route**: GET /profile
- **CWE**: CWE-1336
- **Code**: User-Agent header interpolated into template string
- **Exploit**: Set User-Agent to `{{config}}`
- **Severity**: HIGH

### VULN-3: Auth Bypass — admin endpoints (lines ~82, ~91)
- **Route**: GET /api/admin/users, POST /api/admin/delete_user
- **CWE**: CWE-306
- **Code**: No session/auth check on admin endpoints
- **Exploit**: Direct curl to /api/admin/users
- **Severity**: CRITICAL

### VULN-4: Path Traversal — file download (line ~105)
- **Route**: GET /download?file=
- **CWE**: CWE-22
- **Code**: `os.path.join(base_dir, filename)` with unsanitized user input
- **Exploit**: `?file=../../etc/passwd`
- **Severity**: HIGH

### VULN-4b: Path Traversal — log viewer (line ~115)
- **Route**: GET /logs?name=
- **CWE**: CWE-22
- **Code**: `os.path.join(log_dir, log_name)` → `open(log_path)`
- **Exploit**: `?name=../../../etc/passwd`
- **Severity**: HIGH

### VULN-5: SSRF — URL fetch (line ~128)
- **Route**: GET /api/fetch?url=
- **CWE**: CWE-918
- **Code**: `requests.get(url)` with no validation
- **Exploit**: `?url=http://169.254.169.254/latest/meta-data/` (AWS IMDS)
- **Severity**: HIGH

### VULN-5b: SSRF — webhook (line ~140)
- **Route**: POST /api/webhook
- **CWE**: CWE-918
- **Code**: `requests.post(target_url, ...)` with attacker-controlled URL
- **Exploit**: `{"callback_url": "http://internal-admin:8080/delete-all"}`
- **Severity**: HIGH

### VULN-6: Command Injection (line ~153)
- **Route**: GET /api/ping?host=
- **CWE**: CWE-78
- **Code**: `subprocess.run(f"ping -c 1 {host}", shell=True)`
- **Exploit**: `?host=127.0.0.1; cat /etc/passwd`
- **Severity**: CRITICAL

### VULN-7: IDOR (line ~165)
- **Route**: GET /api/files/<file_id>
- **CWE**: CWE-639
- **Code**: No ownership check, SQLi in file_id
- **Exploit**: Enumerate file IDs
- **Severity**: MEDIUM

### VULN-8: Weak Crypto — MD5 (line ~178)
- **Route**: POST /api/hash
- **CWE**: CWE-328
- **Code**: `hashlib.md5(password.encode()).hexdigest()`
- **Severity**: MEDIUM

### VULN-9: Hardcoded Secret (line ~12)
- **Code**: `app.secret_key = "hardcoded-secret-do-not-use-in-production-12345"`
- **CWE**: CWE-798
- **Severity**: HIGH

### VULN-10: Debug Mode (line ~197)
- **Code**: `app.run(debug=True, host="0.0.0.0")`
- **CWE**: CWE-489
- **Severity**: CRITICAL

---

## Summary

| Severity | Count | IDs |
|----------|-------|-----|
| CRITICAL | 5 | VULN-1b, VULN-2, VULN-3, VULN-6, VULN-10 |
| HIGH | 7 | VULN-1, VULN-2b, VULN-4, VULN-4b, VULN-5, VULN-5b, VULN-9 |
| MEDIUM | 2 | VULN-7, VULN-8 |
| **Total** | **14** | |

## By Category

| Category | Count |
|----------|-------|
| Injection (SQLi+SSTI+CMD) | 5 |
| Broken Access Control | 3 |
| Path Traversal | 2 |
| SSRF | 2 |
| Crypto Failure | 1 |
| Security Misconfiguration | 2 |
