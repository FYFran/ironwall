# Example: Python API Security Audit

Real audit of a FastAPI backend. Shows Python-specific vulnerability patterns.

## Target

```
my-fastapi/
├── main.py
├── config.py
├── routes/
│   ├── users.py
│   └── auth.py
├── models/
│   └── user.py
├── requirements.txt
└── Dockerfile
```

## Scan Command

```bash
ironwall scan ./my-fastapi --format markdown --ai
```

## Findings

### 🔴 CRITICAL: Hardcoded Database Password

**File:** `config.py:5`

```python
DATABASE_URL = "postgresql://admin:MySecretPass123@localhost:5432/mydb"
```

**Attack Scenario:**
- Actor: Anyone with source code access
- Path: Read config.py → extract credentials → connect to database directly
- Impact: Full database access bypassing application controls

**Fix:**
```python
DATABASE_URL = os.environ["DATABASE_URL"]
```

### 🔴 CRITICAL: pickle.loads() on User Input

**File:** `routes/users.py:34`

```python
@app.post("/api/users/import")
async def import_users(request: Request):
    data = await request.body()
    users = pickle.loads(data)  # RCE!
```

**Attack Scenario:**
- Actor: Authenticated user with import permission
- Path: Craft malicious pickle payload → POST to /api/users/import → arbitrary code execution
- Impact: Remote code execution on server

**Fix:**
```python
import json
users = json.loads(data)  # Safe deserialization
```

### 🟠 HIGH: Command Injection via os.system

**File:** `routes/users.py:56`

```python
@app.get("/api/export")
async def export_data(format: str = "csv"):
    os.system(f"python export.py --format={format}")
```

**Attack Scenario:**
- Actor: Authenticated user
- Path: GET /api/export?format=csv;cat /etc/passwd → command injection
- Impact: Arbitrary command execution as the app user

**Fix:**
```python
import subprocess
subprocess.run(["python", "export.py", "--format", format], check=True)
```

### 🟠 HIGH: Insecure Password Storage

**File:** `models/user.py:20`

```python
import hashlib

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
```

**Attack Scenario:**
- Actor: Attacker who obtains database dump
- Path: MD5 hashes are crackable at billions/second → reverse to plaintext
- Impact: All user passwords recoverable

**Fix:**
```python
import bcrypt

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### 🟡 MEDIUM: Unauthenticated Health Endpoint Exposes Internals

**File:** `main.py:15`

```python
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "db_version": db.execute("SELECT version()").scalar(),
        "connections": len(db.pool),
        "env": os.environ.get("APP_ENV"),
    }
```

**Fix:**
```python
@app.get("/health")
async def health():
    return {"status": "ok"}  # Minimal — no internals
```

### 🟡 MEDIUM: npm audit Finding in Dependencies

**File:** `requirements.txt`

```
flask==2.0.1  # CVE-2023-30861: Information disclosure
```

**Fix:**
```
flask>=2.0.3
```

### 🟢 LOW: Debug Mode Enabled

**File:** `Dockerfile:8`

```dockerfile
ENV FLASK_DEBUG=1
```

**Fix:**
```dockerfile
ENV FLASK_DEBUG=0
```

## Summary

| Severity | Count | Action |
|----------|-------|--------|
| 🔴 CRITICAL | 2 | Fix immediately (DB creds, pickle RCE) |
| 🟠 HIGH | 2 | Fix before next deploy |
| 🟡 MEDIUM | 2 | Track in backlog |
| 🟢 LOW | 1 | Production hardening |

## AI-Assisted Findings

With `--ai` flag, ironwall additionally detected:

- **Rate limiting missing on /api/auth/login** — brute force risk. Add slowapi or similar.
- **JWT token stored in localStorage pattern** — recommend httpOnly cookies.
