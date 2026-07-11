# Ground Truth — go-vuln-target

> 7 planted vulnerabilities across 5 files. Cross-package data flows for CG testing.
> Date: 2026-07-11

## Planted Vulnerabilities

### VULN-1: SQL Injection (CRITICAL)
- **Flow**: main.go:handleUserSearch → db.SearchUsers → fmt.Sprintf SQL
- **Code**: `fmt.Sprintf("SELECT ... WHERE username LIKE '%%%s%%'", username)`
- **Cross-package**: main → db
- **CWE**: CWE-89

### VULN-2: Auth Bypass / Missing Auth (HIGH)
- **Flow**: main.go:handleAdminStats → db.GetStats (no auth middleware)
- **Cross-package**: main → db
- **CWE**: CWE-306

### VULN-3: Path Traversal (HIGH)
- **Flow**: main.go:handleFileDownload → file.ReadFile → filepath.Join + os.ReadFile
- **Cross-package**: main → file
- **CWE**: CWE-22

### VULN-4: SSRF (HIGH)
- **Flow**: main.go:handleFetchURL → utils.FetchURL → http.Get
- **Cross-package**: main → utils
- **CWE**: CWE-918

### VULN-5: Command Injection (CRITICAL)
- **Flow**: main.go:handlePing → utils.Ping → exec.Command("sh", "-c", cmd)
- **Cross-package**: main → utils
- **CWE**: CWE-78

### VULN-6: Weak Crypto — MD5 (MEDIUM)
- **Flow**: main.go:handleLogin → auth.CheckLogin → md5.Sum + plain comparison
- **Cross-package**: main → auth → db
- **CWE**: CWE-328

### VULN-7: IDOR (MEDIUM)
- **Flow**: main.go:handleUserDetail → db.GetUserByID → raw SQL with int
- **Cross-package**: main → db
- **CWE**: CWE-639

## Cross-Package Call Chains

| Chain | Depth | Files |
|-------|-------|-------|
| handleLogin → auth.CheckLogin → db.SearchUsers | 3 | main→auth→db |
| handleUserSearch → db.SearchUsers | 2 | main→db |
| handlePing → utils.Ping → exec.Command | 2 | main→utils |
| handleFetchURL → utils.FetchURL → http.Get | 2 | main→utils |
| handleFileDownload → file.ReadFile → os.ReadFile | 2 | main→file |
| handleAdminStats → db.GetStats | 2 | main→db |
| handleUserDetail → db.GetUserByID | 2 | main→db |

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 (SQLi, CMDi) |
| HIGH | 3 (Auth, PathTraversal, SSRF) |
| MEDIUM | 2 (MD5, IDOR) |
| **Total** | **7** |
