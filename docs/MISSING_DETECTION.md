# Ironwall MISSING Detection — Architecture & Differentiation

> **Status:** v0.5.0-design | Brain B adversarial review: PASSED (3 attacks resolved)
> **Core insight:** SAST finds "what's written wrong." MISSING finds "what's not written at all."
> **Competitive moat:** No other tool (Semgrep, Snyk, CodeQL, SonarQube) does absence detection.

## 1. Why MISSING Detection Exists

### The SAST Blind Spot

Every SAST tool works the same way: **pattern match against known bad code.**

```
Semgrep:  if (user_input is used in SQL) → "SQL Injection"
Gosec:    if (TLS InsecureSkipVerify == true) → "Insecure TLS"
CodeQL:   if (data flows from source→sink without sanitizer) → "Taint"
```

This means SAST can ONLY find vulnerabilities that are **already present in the code.** It cannot find what's **absent.**

### What SAST Cannot Find

| Missing Control | Why SAST Misses It | Real-World Impact |
|----------------|-------------------|-------------------|
| No rate limiting on /api/login | Nothing to pattern-match — there's no code at all | Credential stuffing, DDoS |
| No auth on /admin/export | Route exists, handler exists, but no @login_required | Data breach |
| No CSRF token on POST /transfer | Form works correctly, no csrf_token in template | CSRF attack |
| No input validation on user_id | Parameter used directly, no validation middleware | IDOR, injection |
| No Content-Security-Policy | No CSP header = nothing to grep for | XSS amplification |
| No file upload size limit | Handler accepts files, no MaxBytesReader | Disk exhaustion |
| JWT secret in frontend code | Not a "secret leak" in traditional sense — it's in the wrong place | Token forgery |

**Ironwall's SAST steps (1-8) find the first category. MISSING detection (step 9) finds the second.**

## 2. Architecture

### Pipeline Position

```
Step 1: Secrets (gitleaks)
Step 2: SAST (gosec/semgrep/bandit/CodeQL)
Step 3: Endpoints (route extraction + analysis)    ← INPUT to Step 9
Step 4: Hardcoded Secrets
Step 5: Dependencies (CVE)
Step 6: Server/IaC Config
Step 7: Database Audit
Step 8: Supply Chain
Step 9: MISSING Detection          ← NEW: Absence analysis
Step 10: VERIFY (Bull vs Bear)     ← NEW: Adversarial verification
```

### Step 9: MISSING Detection — Three-Phase Pipeline

#### Phase A: Framework-Aware Control Catalog

Not a hardcoded `ShouldHave` list. Dynamic detection based on actual project state.

```go
type SecurityControl struct {
    Name           string   // e.g., "rate_limiting"
    Category       string   // e.g., "traffic", "auth", "data", "injection"
    Severity       Severity // Severity if missing
    DetectionMode  string   // "ast" | "grep" | "config" | "composite"
    PresencePatterns  []string // Patterns that indicate existence
    AbsencePatterns   []string // Patterns that confirm absence
    EffectivenessCheck EffectivenessValidator
}
```

**Framework profiles are generated from `go.mod`/`requirements.txt`/`pom.xml`, not hardcoded:**

| Framework | Built-in Controls | Recommended Third-Party | Explicitly NOT Built-in |
|-----------|------------------|------------------------|------------------------|
| Gin v1.9+ | binding validation | gin-contrib/limit, gin-contrib/csrf, gin-contrib/secure | rate limiting, CSRF, CSP headers |
| Flask 2.0+ | — | Flask-Limiter, Flask-Talisman, Flask-SeaSurf | ALL security controls are third-party |
| Spring Boot 3.x | CSRF (default on), auth (Spring Security) | — | rate limiting |
| Echo v4 | binding validation, middleware pattern | echo-contrib/limiter, echo-contrib/session | CSRF, rate limiting |

#### Phase B: Presence + Effectiveness Check (Brain B Fix #1)

Two-tier check — presence alone is NOT sufficient:

**B1: Presence Detection**
```
For each endpoint × each required control:
  1. grep/AST: Is there code that claims to implement this control?
  2. Config check: Is the control configured in framework config files?
  3. Dependency check: Is a known security library imported?
```

**B2: Effectiveness Validation (CRITICAL — Brain B attack #1 fix)**
```
For each "present" control, verify it's NOT:
  - Commented out (#, //, /* */, <!-- -->)
  - Behind a DEBUG/test condition (if DEBUG, if os.Getenv("ENV") == "dev")
  - An empty/stub implementation (func auth(f) { return f })
  - Explicitly disabled (.disable(), = False, = "off", SkipVerify=true)
  - In wrong middleware order (logger before auth → bypass potential)
  - In test files only (real handlers lack it)

For auth specifically:
  - Does the auth function contain a rejection path? (return 401/403, abort(), panic())
  - If no rejection path → "auth" is decorative → MISSING confirmed

For rate limiting specifically:
  - Does the limiter have a concrete threshold? (req/s, req/min)
  - If no threshold → "rate limit" is decorative → MISSING confirmed
```

#### Phase C: Missing Report

```go
type MissingFinding struct {
    Endpoint       string   // e.g., "POST /api/transfer"
    MissingControl string   // e.g., "rate_limiting"
    Category       string   // e.g., "traffic"
    Severity       Severity // Critical if auth/authz, High for rate_limit/CSRF
    Evidence       string   // "Scanned 3 handler files, 0 references to rate limiting found"
    Effectiveness  string   // "" | "present_but_decorative" | "present_but_disabled"
    FixTemplate    string   // Language-specific fix code
    CWE            string   // CWE mapping
}
```

### Step 10: VERIFY — Bull vs Bear Adversarial Verification

#### Architecture (Brain B Fix #2 incorporated)

```
Input: MissingFinding from Step 9

Phase 10a: Architecture Context Scan (NEW — Brain B attack #2 fix)
  Scan project for infrastructure-as-code:
    - docker-compose.yml, docker-compose.*.yml
    - nginx.conf, nginx/, nginx-*/
    - kubernetes/, k8s/, helm/
    - terraform/, *.tf
    - serverless.yml, app.yaml, fly.toml
    - .github/workflows/, .gitlab-ci.yml
  Extract: ArchContext{
    HasNginx: bool,
    HasAPIGateway: bool,
    HasLoadBalancer: bool,
    HasWAF: bool, // Cloudflare, AWS WAF, etc.
    HasServiceMesh: bool, // Istio, Linkerd, etc.
  }

Phase 10b: Bull Agent (Confirmer)
  Role: Prove the control is ACTUALLY missing
  Input: Source code within repo scope + SAST results
  Task: Find ALL possible implementations of this control in the codebase
  Output: BullVerdict{MISSING|FOUND_INEFFECTIVE|PRESENT} + confidence + evidence

Phase 10c: Bear Agent (Denier)
  Role: Prove the control EXISTS (in code, config, or INFRASTRUCTURE)
  Input: Source code + SAST results + ArchContext (wider scope than Bull!)
  Task: Find evidence the control may exist outside source code
  Output: BearVerdict{
    Verdict: PRESENT_IN_CODE | PRESENT_IN_INFRA | MAYBE_IN_INFRA | NOT_FOUND,
    Evidence: "nginx.conf line 42: limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/s"
  }

Phase 10d: Consensus
  Matrix:
  | Bull | Bear | Result |
  |------|------|--------|
  | MISSING | NOT_FOUND | ✅ CONFIRMED MISSING — highest confidence |
  | MISSING | MAYBE_IN_INFRA | ⚠️ UNCERTAIN — downgrade to MEDIUM + scope_limited tag |
  | MISSING | PRESENT_IN_INFRA | ❌ NOT MISSING — control exists at infra level, close as info |
  | FOUND_INEFFECTIVE | NOT_FOUND | ⚠️ DECORATIVE — control exists but ineffective, report as HIGH |
  | FOUND_INEFFECTIVE | PRESENT_IN_CODE | ⚠️ PARTIAL — multiple controls, some weak, report individually |
  | PRESENT | ANY | ✅ Control exists and is effective — no finding reported |

Phase 10e: UNCERTAIN Handling
  UNCERTAIN findings are NOT dropped. They are reported with:
    - Severity downgraded by 1 level
    - Tag: "scope_limited"
    - Note: "Control may exist in infrastructure outside Ironwall's scan scope.
             Verify manually: check nginx/CDN/WAF configuration."
```

## 3. Competitive Differentiation

| Capability | Semgrep | Snyk | CodeQL | SonarQube | Ironwall |
|-----------|---------|------|--------|-----------|----------|
| Pattern-based SAST | ✅ | ✅ | ✅ | ✅ | ✅ |
| Dependency CVE | ❌ | ✅ | ❌ | ❌ | ✅ |
| Secret scanning | ❌ | ❌ | ❌ | ❌ | ✅ |
| IaC scanning | ❌ | ✅ | ❌ | ✅ | ✅ |
| Supply chain (SLSA, SBOM) | ❌ | ❌ | ❌ | ❌ | ✅ |
| **MISSING detection** | ❌ | ❌ | ❌ | ❌ | **✅ Unique** |
| **Effectiveness validation** | ❌ | ❌ | ❌ | ❌ | **✅ Unique** |
| **Bull vs Bear verification** | ❌ | ❌ | ❌ | ❌ | **✅ Unique** |
| Endpoint-aware analysis | ❌ | ❌ | ❌ | ❌ | ✅ |
| Framework-aware catalog | ❌ | ❌ | ❌ | ❌ | ✅ |

## 4. Implementation Plan

### Phase 2a: Core MISSING Engine (#40)
- [ ] `step9_missing.go` — Complete pipeline step
- [ ] `internal/missing/catalog.go` — Framework-aware control catalog
- [ ] `internal/missing/effectiveness.go` — B2 effectiveness validation
- [ ] `internal/missing/presence.go` — B1 presence detection
- [ ] Unit tests: catalog generation, effectiveness checks, false positive scenarios

### Phase 2b: VERIFY Bull vs Bear (#42)
- [ ] `step10_verify.go` — Complete pipeline step
- [ ] `internal/verify/bull.go` — Bull agent (confirmer)
- [ ] `internal/verify/bear.go` — Bear agent (denier, with ArchContext)
- [ ] `internal/verify/arch_context.go` — Infrastructure scanning
- [ ] Unit tests: consensus matrix, UNCERTAIN handling, effectiveness scenarios

### Phase 2c: Semgrep Rules + Non-Code Scanning (#31)
- [ ] `.semgrep/token-leak.yaml` — Token混淆 rules
- [ ] `internal/scanner/noncode.go` — Non-code file scanner
- [ ] Integration with Step 1 (secrets) for non-code coverage

## 5. Signature

```
Architecture designed by: Brain A (皮特)
Adversarial review by: Brain B (DeepSeek V4 Pro @ localhost:4000)
3 attacks identified → 3 fixes incorporated → PASSED
Date: 2026-07-14
```
