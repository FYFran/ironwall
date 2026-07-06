# Example: Go Backend Security Audit

Real audit of a typical Go API server. Shows what ironwall finds and how to fix each issue.

## Target

```
my-go-api/
├── main.go
├── config/
│   └── config.go
├── handler/
│   ├── auth.go
│   └── user.go
├── middleware/
│   └── auth.go
├── db/
│   └── migrations/
│       └── 001_init.sql
├── Dockerfile
├── docker-compose.yml
└── go.mod
```

## Scan Command

```bash
ironwall scan ./my-go-api --format markdown
```

## Findings

### 🔴 CRITICAL: Hardcoded JWT Secret

**File:** `config/config.go:12`

```go
var JWTSecret = []byte("my-super-secret-key-2024")
```

**Attack Scenario:**
- Actor: Anyone with source code access
- Path: Read config.go → extract JWT secret → forge tokens for any user
- Impact: Full account takeover of all users

**Fix:**
```go
var JWTSecret = []byte(os.Getenv("JWT_SECRET"))
```

### 🔴 CRITICAL: Docker Socket Mounted

**File:** `docker-compose.yml:10`

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

**Attack Scenario:**
- Actor: Attacker who compromises the app container
- Path: Write to docker.sock → create privileged container → escape to host
- Impact: Full host compromise

**Fix:** Remove docker socket mount. Use docker-api-proxy for container management.

### 🟠 HIGH: SQL Injection in User Handler

**File:** `handler/user.go:28`

```go
query := "SELECT * FROM users WHERE name = '" + name + "'"
row := db.QueryRow(query)
```

**Attack Scenario:**
- Actor: Unauthenticated user calling /api/users?name=X
- Path: Send `' OR '1'='1` as name → SQL injection → extract all user records
- Impact: Full database dump of user table

**Fix:**
```go
row := db.QueryRow("SELECT * FROM users WHERE name = $1", name)
```

### 🟠 HIGH: Missing Auth on Admin Endpoint

**File:** `main.go:45`

```go
r.Get("/admin/users", listAllUsers)
```

**Attack Scenario:**
- Actor: Any visitor to the web application
- Path: Navigate to /admin/users → get full user list
- Impact: Unauthorized access to all user data

**Fix:**
```go
r.With(authMiddleware).Get("/admin/users", listAllUsers)
```

### 🟡 MEDIUM: Debug Mode Enabled

**File:** `.env:2`

```
DEBUG=true
```

**Fix:**
```
DEBUG=false
```

### 🟡 MEDIUM: CORS Wildcard

**File:** `main.go:20`

```go
w.Header().Set("Access-Control-Allow-Origin", "*")
```

**Fix:**
```go
w.Header().Set("Access-Control-Allow-Origin", "https://myapp.com")
```

### 🟢 LOW: Missing Index on Foreign Key

**File:** `db/migrations/001_init.sql:15`

```sql
CREATE TABLE posts (
    user_id INTEGER REFERENCES users(id)
);
```

**Fix:**
```sql
CREATE TABLE posts (
    user_id INTEGER REFERENCES users(id)
);
CREATE INDEX idx_posts_user_id ON posts(user_id);
```

## Summary

| Severity | Count | Action |
|----------|-------|--------|
| 🔴 CRITICAL | 2 | Fix before production |
| 🟠 HIGH | 2 | Fix before next deploy |
| 🟡 MEDIUM | 2 | Track in backlog |
| 🟢 LOW | 1 | Nice to have |

## Post-Fix Verification

```bash
# After fixing all issues, rescan
ironwall scan ./my-go-api --format markdown
# Should show 0 CRITICAL, 0 HIGH
```
