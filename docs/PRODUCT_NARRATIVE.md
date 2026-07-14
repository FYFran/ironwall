# Ironwall — Product Narrative

> **What if your security scanner found the vulnerabilities that aren't there yet?**

## The Story (60 seconds)

You're about to deploy. You ran Semgrep, CodeQL, Snyk — all green. You ship.

48 hours later, your `/api/admin/export` endpoint gets hit 100,000 times in 10 minutes. No rate limiting. Semgrep didn't flag it — there was nothing to flag. The code that should have been there... wasn't.

**SAST tools find what's written wrong. Ironwall finds what's not written at all.**

That's the difference between "no known vulnerabilities" and "actually secure."

## The Problem

Software security is asymmetric. Attackers only need one missing check. Defenders need all of them.

| Tool | Finds |
|------|-------|
| Semgrep | Pattern: `user_input → SQL` → "SQL Injection" |
| CodeQL | Flow: `source → sink without sanitizer` → "Taint" |
| Snyk | Version: `lodash@4.17.20` → "CVE-2021-23337" |
| **Ironwall** | **Absence: `POST /api/transfer` has no rate limiting, no CSRF token, no auth check** |

Every tool checks the code that exists. Only Ironwall checks for the code that doesn't.

## How It Works

```
Your Code
    │
    ├── Step 1-8: Standard SAST pipeline
    │   (gitleaks → gosec/semgrep/CodeQL → endpoints → secrets → deps → infra → DB → supply chain)
    │
    ├── Step 9: MISSING Detection ← THE MOAT
    │   For every endpoint:
    │   "Does this have: auth? rate limiting? CSRF? input validation? security headers?"
    │   Not just pattern matching — effectiveness validation.
    │   A stub auth function that always returns true? That's a MISSING finding.
    │
    └── Step 10: VERIFY (Bull vs Bear)
        Bull agent: "Prove it's missing."
        Bear agent: "Prove it exists somewhere — even in nginx/WAF/infra."
        Consensus → confirmed finding. Disagreement → UNCERTAIN, downgraded.
```

## The Moat

| Capability | Semgrep | Snyk | CodeQL | SonarQube | **Ironwall** |
|-----------|---------|------|--------|-----------|----------|
| SAST pattern matching | ✅ | ✅ | ✅ | ✅ | ✅ |
| Dependency CVE | ❌ | ✅ | ❌ | ❌ | ✅ |
| Secret scanning | ❌ | ❌ | ❌ | ❌ | ✅ |
| IaC scanning | ❌ | ✅ | ❌ | ✅ | ✅ |
| Supply chain (SLSA/SBOM) | ❌ | ❌ | ❌ | ❌ | ✅ |
| **MISSING detection** | ❌ | ❌ | ❌ | ❌ | **✅** |
| **Effectiveness validation** | ❌ | ❌ | ❌ | ❌ | **✅** |
| **Adversarial verification** | ❌ | ❌ | ❌ | ❌ | **✅** |

## Real Examples

### Finding #1: No Rate Limiting on Login
```
Endpoint: POST /api/login
Semgrep: ✅ Clean
CodeQL:   ✅ Clean
Snyk:     ✅ Clean
Ironwall: 🔴 MISSING: rate_limiting — 0 references to limiter found in 3 handler files.
          Risk: Brute-forceable. 100 attempts/second = 3 days to crack 8-char password.
```

### Finding #2: Decorative Auth
```
Endpoint: GET /api/admin/users
Semgrep: ✅ Clean (auth middleware is imported!)
Ironwall: 🔴 MISSING: auth (ineffective: decorative)
          The auth function `checkAuth()` has NO rejection path.
          It sets `request.verified = True` unconditionally.
          This endpoint is effectively public while looking protected.
```

### Finding #3: Token in Frontend
```
File: frontend/src/api.js
Semgrep: ✅ Clean
Ironwall: 🔴 JWT token stored in localStorage.
          Any XSS vulnerability = complete account takeover.
          Fix: httpOnly cookie or BFF pattern.
```

## Target Users

1. **Indie developers** deploying their first SaaS — don't know what they don't know
2. **Startup CTOs** moving fast — need automated guardrails, not manual checklists
3. **Security-conscious teams** already using SAST — need the missing half of the puzzle

## Why Now

- **AI-generated code** has 1.7x more defects than human code (Addy Osmani, Google 2026)
- **45% of AI-generated code** contains OWASP Top 10 vulnerabilities
- Traditional SAST can't find missing controls — and AI is more likely to omit them
- The market needs a tool that answers: "What SHOULD be here that isn't?"

---

> Ironwall is not a replacement for Semgrep or CodeQL. It's the other half of the equation.
> **SAST finds what's broken. Ironwall finds what's missing.**
