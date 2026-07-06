# 🔍 Ironwall Gotchas Library

Curated patterns that automated scanners typically miss. Each entry includes the pattern, why scanners miss it, and how Ironwall catches it.

## Go Gotchas

### G1: SQL Injection via fmt.Sprintf

```go
// ❌ scanners often miss this because the SQL is built across multiple lines
query := fmt.Sprintf(
    "SELECT * FROM users WHERE id = %s AND status = '%s'",
    userID, status,
)
db.Query(query)
```

**Why missed:** Semgrep matches single-line string concatenation. Multi-line fmt.Sprintf with multiple variables creates too many false positives for simple rules.
**Ironwall detection:** Step 2 (semgrep + AI review of db.Query calls).

### G2: Environment Variable Fallback as Secret

```go
// ❌ looks safe — uses env var — but has a hardcoded fallback
apiKey := os.Getenv("API_KEY")
if apiKey == "" {
    apiKey = "dev-key-12345"  // HARDCODED FALLBACK
}
```

**Why missed:** Gitleaks sees `os.Getenv` and trusts it. Doesn't check the fallback path.
**Ironwall detection:** Step 4 regex catches string assignments inside conditional blocks.

### G3: Context Deadline Bypass

```go
// ❌ creates new context without parent's deadline
func handleRequest(ctx context.Context) {
    newCtx := context.Background()  // LOSES ORIGINAL DEADLINE
    result, _ := slowOperation(newCtx)
}
```

**Why missed:** Not a traditional "vulnerability." But in practice, this defeats timeout protections and enables DoS.
**Ironwall detection:** Step 3 (endpoint analysis flags handlers without proper context propagation).

### G4: Error Swallowing with Information Leak

```go
// ❌ error message leaks internal path structure
if err != nil {
    http.Error(w, fmt.Sprintf("failed to read %s: %v", filename, err), 500)
}
```

**Why missed:** Semgrep sees error handling (good!) but doesn't check error message content.
**Ironwall detection:** Step 3 (endpoint audit flags fmt.Sprintf in error responses).

## JavaScript/TypeScript Gotchas

### J1: eval() with Template Literals

```javascript
// ❌ not caught by semgrep's eval() rule — uses template literal
const query = `SELECT * FROM ${table} WHERE ${column} = '${value}'`
eval(`process(${query})`)  // template literal eval often missed
```

**Why missed:** Semgrep eval rule matches `eval(variable)` but template literals inside eval are less common and rules are conservative.
**Ironwall detection:** Step 2 (semgrep + AI review of eval patterns).

### J2: Prototype Pollution via Object.assign

```javascript
// ❌ deep merge without prototype check
function mergeConfig(defaults, userInput) {
    return Object.assign({}, defaults, JSON.parse(userInput))
}
```

**Why missed:** Object.assign is used safely 95% of the time. Scanners can't distinguish safe from unsafe without context.
**Ironwall detection:** Step 2 (AI review flags Object.assign with user-controlled input).

### J3: JWT Decode Without Verify

```javascript
// ❌ decodes JWT without verifying signature
const payload = JSON.parse(atob(token.split('.')[1]))
// uses payload.userId without verification
```

**Why missed:** No standard semgrep rule for "decode without verify" pattern.
**Ironwall detection:** Step 4 (hardcoded patterns + AI review of JWT handling).

## Python Gotchas

### P1: pickle.loads() on User Input

```python
# ❌ deserialization without safe loader
data = pickle.loads(request.data)  # RCE if attacker crafts payload
```

**Why missed:** Semgrep catches `pickle.load` but not when wrapped in a larger function.
**Ironwall detection:** Step 2 (semgrep + AI review of deserialization contexts).

### P2: os.system() with f-string

```python
# ❌ command injection via f-string
filename = request.GET.get('file')
os.system(f'convert {filename} output.pdf')
```

**Why missed:** f-string injection is harder to detect than string concatenation.
**Ironwall detection:** Step 2 (semgrep + Step 4 regex for `os.system` with format strings).

### P3: Django Raw SQL with .format()

```python
# ❌ raw SQL with format — bypasses Django ORM protection
table = request.GET.get('table')
User.objects.raw(f'SELECT * FROM {table} WHERE active = 1')
```

**Why missed:** Django `raw()` is flagged by some rules, but `f'...{table}...` inside `raw()` is a complex pattern.
**Ironwall detection:** Step 2 (semgrep + AI review of ORM raw queries).

## Docker Gotchas

### D1: Healthcheck as RCE Vector

```dockerfile
# ❌ curl in healthcheck can be used for SSRF
HEALTHCHECK CMD curl -f http://${API_HOST}/health || exit 1
```

**Why missed:** Scanners don't analyze healthcheck commands for security.
**Ironwall detection:** Step 6 (flags curl/wget in Dockerfile).

### D2: BuildKit Mount Leaks

```dockerfile
# ❌ RUN --mount=type=secret doesn't protect from layer caching
RUN --mount=type=secret,id=aws_key cat /run/secrets/aws_key > /app/.aws_key
```

**Why missed:** Secret mount usage looks secure but the file copy defeats it.
**Ironwall detection:** Step 6 (AI review of Dockerfile RUN commands).

## Database Gotchas

### DB1: Index on Expression with Side Channel

```sql
-- ❌ functional index leaks data through timing
CREATE INDEX ON users ((pgp_sym_decrypt(encrypted_email, 'key')));
```

**Why missed:** Encryption in indexes is an advanced pattern that basic scanners miss.
**Ironwall detection:** Step 7 (flags pgcrypto functions in index definitions).

### DB2: Trigger with External Command

```sql
-- ❌ trigger runs external command — RCE if table is writable
CREATE TRIGGER after_insert AFTER INSERT ON uploads
FOR EACH ROW EXECUTE FUNCTION pg_read_file('/tmp/' || NEW.filename);
```

**Why missed:** Trigger-based RCE is rare and not covered by standard rules.
**Ironwall detection:** Step 7 (AI review of trigger definitions with dynamic paths).

## API Design Gotchas

### A1: Bulk Endpoint Without Limit

```go
// ❌ no pagination — client can request all records
r.Get("/api/users", listAllUsers)  // returns ALL users, no LIMIT
```

**Why missed:** Route scanning doesn't check handler implementation.
**Ironwall detection:** Step 3 flags list endpoints without query parameters for pagination.

### A2: IDOR via Predictable IDs

```go
// ❌ autoincrement IDs enable enumeration
r.Get("/api/users/{id}", getUser)  // id=1,2,3,... enumerable
```

**Why missed:** IDOR detection requires understanding data model relationships.
**Ironwall detection:** Step 3 + Step 7 (endpoint audit flags autoincrement PKs, cross-references with GET by ID routes).

## Rust Gotchas

### R1: unsafe block wrapping safe operations

```rust
// ❌ unsafe block hides the actual safe operation — reviewers get fatigued
unsafe {
    let slice = std::slice::from_raw_parts(ptr, len); // actually safe here
    do_something_dangerous(ptr); // but THIS is dangerous — buried in noise
}
```

**Why missed:** Scanners flag all `unsafe` blocks equally. The real danger is when dangerous ops are hidden among safe ones.
**Ironwall detection:** Step 2 (AI review of unsafe block content, flagging multiple operations in one block).

### R2: cargo-audit blind spot — git dependencies

```toml
# ❌ cargo-audit only checks crates.io — git deps skip verification
[dependencies]
my-internal-lib = { git = "https://github.com/org/repo", branch = "legacy" }
```

**Why missed:** `cargo audit` only checks published crate versions. Git dependencies bypass the advisory database entirely.
**Ironwall detection:** Step 5 (flags git dependencies in Cargo.toml for manual review).

## Infrastructure as Code Gotchas

### I1: Terraform state with hardcoded secrets

```hcl
# ❌ secrets in terraform state are stored in plaintext
resource "aws_db_instance" "main" {
  password = "MySecretPass123"  # ends up in tfstate!
}
```

**Why missed:** IaC scanners check for best practices, not embedded secrets within resource definitions.
**Ironwall detection:** Step 4 (regex picks up `password = "..."` in .tf files).

### I2: Kubernetes secret in deployment YAML

```yaml
# ❌ secret defined directly in deployment instead of using Secret resource
env:
  - name: DATABASE_URL
    value: "postgres://user:pass123@db:5432/mydb"
```

**Why missed:** kube-linter checks for pod security, not credential hygiene.
**Ironwall detection:** Step 6 (scans .yaml/.yml for embedded credentials in env values).

## CI/CD Gotchas

### C1: GitHub Actions workflow injection

```yaml
# ❌ user-controlled PR title used in shell command — command injection
- name: Process PR
  run: |
    echo "PR title: ${{ github.event.pull_request.title }}"
    ./scripts/process.sh "${{ github.event.pull_request.title }}"
```

**Why missed:** Standard SAST doesn't scan workflow YAML. But this is RCE on your CI runners.
**Ironwall detection:** Step 6 (AI review of workflow YAML for shell injection patterns).

### C2: Artifact poisoning via unverified upload

```yaml
# ❌ uploads artifact without verifying source
- uses: actions/upload-artifact@v4
  with:
    name: build-output
    path: ./dist  # what if a prior step was compromised?
```

**Why missed:** CI scanning tools focus on secrets, not artifact provenance.
**Ironwall detection:** Step 6 (flags `upload-artifact` without prior verification step).

## API Security Gotchas

### A3: GraphQL introspection enabled in production

```go
// ❌ introspection leaks entire API schema to attackers
h := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{
    Resolvers: &resolver{},
}))
// Default enables introspection + playground
```

**Why missed:** GraphQL security is niche — most SAST tools focus on REST.
**Ironwall detection:** Step 3 (flags GraphQL handler setup without explicit introspection disable).

### A4: WebSocket upgrade without origin check

```go
// ❌ any website can open a WebSocket to your server
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
}
```

**Why missed:** WebSocket security is not covered by standard SAST rules.
**Ironwall detection:** Step 3 (flags `CheckOrigin: return true` patterns).

## Crypto Gotchas

### CR1: Using math/rand for security tokens

```go
// ❌ math/rand is NOT cryptographically secure
import "math/rand"
token := fmt.Sprintf("%x", rand.Int63())
```

**Why missed:** Scanners flag `math/rand` usage but don't trace to token generation context.
**Ironwall detection:** Step 2 (gosec G404: use of math/rand + AI context review for token generation).

### CR2: AES in ECB mode

```go
// ❌ ECB mode leaks plaintext patterns in ciphertext
block, _ := aes.NewCipher(key)
cipher.NewECBEncrypter(block).CryptBlocks(ciphertext, plaintext)
```

**Why missed:** AES usage looks correct at first glance. Only crypto experts catch ECB mode issues.
**Ironwall detection:** Step 2 (gosec catches weak cipher modes + Step 7 AI review).

## Logging Gotchas

### L1: PII in error messages

```go
// ❌ error message leaks user email and internal paths
if err != nil {
    log.Printf("user %s failed to read %s: %v", user.Email, filePath, err)
    http.Error(w, err.Error(), 500)
}
```

**Why missed:** Error handling checks exist (good!) but don't catch information leakage in messages.
**Ironwall detection:** Step 3 (flags fmt.Sprintf in error responses with user-controlled variables).

### L2: Token in URL query parameters

```go
// ❌ tokens in URLs are logged by proxies, caches, and browsers
resp, _ := http.Get("https://api.example.com/data?token=" + apiKey)
```

**Why missed:** `http.Get` with query params looks normal. Token leakage via URL is subtle.
**Ironwall detection:** Step 4 (flags URL query params containing "token", "key", "auth", "secret").

## Contributing Gotchas

Found a pattern that scanners miss? Add it here!

**Format:**
```markdown
### X1: Title
**Code:** (vulnerable example)
**Why missed:** (why scanners miss it)
**Ironwall detection:** (how ironwall catches it)
```

Submit a PR to `docs/gotchas.md`.
