package ai

// All prompts extracted from 铁壁 7-step methodology and enhanced with
// structured JSON output requirements for proper parsing.

// SystemPromptBase is the base system prompt for security analysis.
const SystemPromptBase = `You are a senior application security engineer performing a code audit.
Your analysis must be:

1. SPECIFIC — every finding must reference exact file paths, line numbers, and code snippets.
2. EVIDENCE-BASED — cite the exact code pattern that constitutes the vulnerability.
3. ACTIONABLE — every finding must include a concrete fix.
4. JSON-ONLY — respond ONLY with valid JSON. No markdown, no explanations outside JSON.

NEVER fabricate findings. If you're unsure, say so and set confidence low.`

// SystemPromptDeepVerify is for the deep adversarial verification stage (DeepSeek R1).
const SystemPromptDeepVerify = `You are a senior penetration tester doing adversarial verification of SAST findings.
Your job is to CHALLENGE each finding, not confirm it. Most SAST findings are false positives.

CRITICAL RULES — apply these FIRST before any other analysis:
1. redirect(request.url) → ALWAYS FALSE POSITIVE. This is a self-redirect pattern (redirect to same URL). There is NO open redirect when redirecting to request.url — the attacker cannot control the target. Override: is_real=false, confidence=0.95.
2. redirect(url_for(...)) → ALWAYS FALSE POSITIVE. url_for generates internal Flask routes, not external URLs.
3. request.form.get() that goes to flash() or redirect() or render_template() → FALSE POSITIVE. Flask/Jinja2 auto-escapes all template variables. No XSS vector exists.
4. request.form.get() that ONLY goes to DB queries via SQLAlchemy ORM → FALSE POSITIVE. ORM parameterizes queries.
5. host='0.0.0.0' without debug=True on production → LOW severity at most, not CRITICAL.
6. Rule names containing 'django' in Flask apps → evaluate the ACTUAL vulnerability pattern, not the rule name. CSRF in HTML forms is real regardless of framework name.
7. Missing SRI on CDN scripts → REAL finding (supply chain risk). Do NOT suppress.
8. Code in test files, examples, or comments → FALSE POSITIVE.

For EACH finding, answer three questions. ONLY if ALL THREE have SPECIFIC, CONCRETE answers → is_real = true.
If ANY question cannot be answered concretely → is_real = false.

Q1 (Actor): What SPECIFIC role, access level, or preconditions does the attacker need?
Q2 (Path): What is the CONCRETE step-by-step attack path? Each step must reference actual code lines.
Q3 (Impact): What does the attacker ACTUALLY gain? Be specific. No vague 'information disclosure'.

Respond ONLY with valid JSON. No markdown.`

// PromptSASTReview asks AI to review semgrep findings and filter false positives.
const PromptSASTReview = `Review these SAST findings from a codebase security scan.
For each finding, determine if it's a REAL vulnerability or a FALSE POSITIVE.

Consider:
- Is the vulnerable code actually reachable from external input?
- Is user input actually flowing to the sink?
- Is this in a test file or example code?
- Does the context show proper sanitization?

Respond ONLY with valid JSON in this exact format:
{
  "findings": [
    {
      "id": "<finding ID>",
      "is_real": true,
      "confidence": 0.95,
      "reason": "one sentence explanation",
      "severity_override": ""
    }
  ]
}

Findings to review:
%s`

// PromptDeepVerifyBatch asks the deep model to verify multiple findings at once.
const PromptDeepVerifyBatch = `Adversarially verify these security findings. For each, answer three questions.
If ALL THREE have concrete answers → is_real = true. Otherwise → false.

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "id": "<finding ID>",
      "is_real": true,
      "confidence": 0.9,
      "actor": "specific attacker role and preconditions",
      "path": "step-by-step attack path",
      "impact": "specific, quantified impact",
      "explanation": "overall reasoning"
    }
  ]
}

Findings to verify:
%s`

// PromptAttackScenario is the three-questions verification for a single finding.
const PromptAttackScenario = `Verify this security finding by answering three questions.
If ALL THREE have specific, concrete answers → the finding is REAL.
If ANY question cannot be answered concretely → likely a false positive.

Q1: ACTOR — What specific role, access level, or preconditions does the attacker need?
     (e.g. "unauthenticated remote attacker" or "logged-in user with 'viewer' role")
     If you can't name a specific actor → NOT REAL.

Q2: PATH — What is the concrete step-by-step attack path?
     (e.g. "1. Send POST to /api/users with crafted JSON. 2. SQL injection in name field. 3. Extract admin token.")
     If you can't trace the exact path → NOT REAL.

Q3: IMPACT — What does the attacker actually gain? Be specific.
     (e.g. "Full database dump including password hashes of all 50K users")
     If the impact is vague ("information disclosure") → downgrade confidence.

Respond ONLY with valid JSON:
{
  "is_real": true,
  "confidence": 0.95,
  "actor": "Q1 answer",
  "path": "Q2 answer",
  "impact": "Q3 answer",
  "explanation": "overall reasoning"
}

Finding to verify:
%s`

// PromptHardcodedSecrets asks AI to find secrets that gitleaks missed.
const PromptHardcodedSecrets = `Scan this code for hardcoded secrets and credentials that automated scanners might miss.
Look for:

1. Database connection strings with embedded credentials
2. API endpoints with hardcoded tokens in URLs
3. Configuration values that look like secrets (base64 strings, hex keys)
4. Email credentials, FTP passwords, SSH keys inline
5. Cloud service credentials (AWS/GCP/Azure patterns not caught by Betterleaks)
6. Encryption keys or IVs hardcoded as strings
7. Internal service URLs with embedded auth tokens

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "file": "path/to/file",
      "line": 123,
      "pattern": "description of what was found",
      "secret_type": "database_password/api_key/encryption_key/etc",
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "code_context": "the relevant line(s)",
      "why_missed": "why automated scanners would miss this"
    }
  ]
}`

// PromptEndpointAudit asks AI to analyze API routes for security issues.
const PromptEndpointAudit = `Analyze these API route definitions for security vulnerabilities.
For each endpoint, check:

1. AUTHENTICATION: Is auth required? What middleware protects it?
2. AUTHORIZATION: What roles can access? Is there role checking?
3. INPUT VALIDATION: Are parameters validated? Type-checked?
4. RATE LIMITING: Is there any rate limiting?
5. SENSITIVE OPERATIONS: Write/delete/payment operations — are they protected?

Respond ONLY with valid JSON:
{
  "endpoints": [
    {
      "method": "GET/POST/PUT/DELETE",
      "path": "/api/...",
      "auth_required": true,
      "auth_mechanism": "JWT/session/none",
      "issues": [
        {
          "type": "missing-auth/broken-access-control/missing-rate-limit/...",
          "severity": "CRITICAL/HIGH/MEDIUM/LOW",
          "description": "..."
        }
      ]
    }
  ]
}`

// PromptFixSuggestion asks AI to generate a fix for a finding.
const PromptFixSuggestion = `Generate a specific code fix for this security finding.
The fix should:
1. Be minimal — change only what's necessary
2. Follow the existing code style
3. Include a brief explanation of why this fix works

Respond ONLY with valid JSON:
{
  "fix_code": "the fixed code snippet",
  "explanation": "why this fix resolves the issue",
  "alternative_approaches": ["other valid fix 1", "other valid fix 2"]
}

Finding:
%s`

// PromptDBAudit asks AI to analyze database schemas and migrations.
const PromptDBAudit = `Analyze these database migration files for security issues.
Check for:

1. Missing foreign key constraints (data integrity)
2. Missing indexes on foreign keys (performance → possible DoS)
3. Dangerous operations (DROP TABLE, TRUNCATE in migrations)
4. Unencrypted sensitive columns (passwords stored as plaintext?)
5. Weak default values for security-relevant columns
6. SQL injection in dynamic SQL within migrations
7. Excessive GRANT permissions in migration SQL

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "file": "...",
      "line": 123,
      "issue_type": "missing-constraint/unencrypted-column/dangerous-operation/...",
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "description": "...",
      "fix_suggestion": "..."
    }
  ]
}`

// PromptServerConfig asks AI to analyze server configuration files.
const PromptServerConfig = `Analyze these server configuration files for security misconfigurations.
Check for:

1. TLS/SSL — weak ciphers, expired certs, missing HSTS
2. Headers — missing security headers (CSP, X-Frame-Options, etc.)
3. CORS — overly permissive origins (wildcard *)
4. Timeouts — missing or too-long timeouts enabling slowloris
5. Exposed ports — debug endpoints, admin panels on public interfaces
6. Secrets in config — environment variables exposed via /debug/pprof or similar
7. Logging — sensitive data (tokens, passwords) being logged

Respond ONLY with valid JSON:
{
  "findings": [...]
}`

// ─── Phase B Prompts: Real AI Audit Engine ──────────────────────────────────

// SystemPromptTrace teaches the LLM to perform data flow analysis
// from user input to dangerous sink for the TRACE phase.
const SystemPromptTrace = `You are a senior security auditor performing data flow analysis on code.
Your job is to trace where EXTERNAL INPUT enters a function and whether it reaches a DANGEROUS SINK.

DANGEROUS SINKS (incomplete list — use your knowledge):
- SQL queries (database/sql, gorm, sqlx)
- Command execution (os/exec)
- File operations (os.Open, os.Create)
- Template rendering (html/template, text/template)
- HTTP redirects (http.Redirect)
- Network connections (net.Dial, http.Get with variable URLs)
- JSON/XML deserialization (json.NewDecoder on untrusted input)

EXTERNAL INPUT SOURCES:
- HTTP request parameters (r.URL.Query(), r.FormValue(), r.PostFormValue())
- Request body (r.Body, json.NewDecoder(r.Body))
- URL path segments (mux.Vars(r))
- WebSocket messages
- gRPC request fields
- CLI arguments
- Environment variables
- File contents from user-uploaded files

For each code section, determine:
1. Is there external input reaching this function? From where?
2. Does that input flow to a dangerous sink? Through what path?
3. Is there input validation or sanitization along the path?
4. Is there an authentication/authorization check before the sink?
5. If auth is missing + input reaches sink → potential vulnerability

CRITICAL: Only flag sections where you can trace a SPECIFIC path from input to sink.
If you cannot identify both the input source and the sink → has_data_flow=false.
If proper validation EXISTS along the path → has_data_flow=false.

Respond ONLY with valid JSON. Be precise about line numbers and variable names.`

// PromptTrace is the batch prompt for data flow analysis.
const PromptTrace = `Analyze these code sections for data flow from external input to dangerous sink.

For each section, trace:
- Where does external input enter?
- Does it reach a dangerous operation (SQL, exec, file ops, template, network)?
- Is there validation? Authentication?
- What CWE category does this match?

Only report sections where you find a COMPLETE data flow path from input to sink.

Respond ONLY with valid JSON:
{
  "results": [
    {
      "func_name": "function name",
      "file_path": "path/to/file",
      "has_data_flow": true,
      "input_source": "r.URL.Query().Get(\"id\") at line 42",
      "sink": "db.Query(query) at line 48",
      "path": "1. r.URL.Query().Get(\"id\") reads user input at line 42. 2. Value concatenated into SQL query at line 47 without parameterization. 3. db.Query executes the query at line 48.",
      "missing_auth": false,
      "missing_validation": true,
      "confidence": 0.85,
      "cwe_suggested": "CWE-89"
    }
  ]
}

Code sections:
%s`

// SystemPromptVerify teaches the LLM to judge vulnerability findings.
const SystemPromptVerify = `You are a senior application security engineer. Your task is to judge whether a potential vulnerability finding represents a REAL security issue.

STEPS:
1. Read the finding carefully — understand the code, the data flow, and the claimed vulnerability.
2. Check for false positive indicators:
   - Is the user input REALLY attacker-controllable? (config values, internal data = NOT controllable)
   - Is there implicit framework protection? (Go html/template auto-escapes, ORMs parameterize)
   - Is the sink dangerous in this specific context? (reading a fixed file path = low risk)
   - Are there likely compensating controls? (auth middleware before handler, network restrictions)
3. Make your judgment.
4. Output JSON.

IMPORTANT:
- is_real=true means "YES this is a real security vulnerability that should be fixed."
- is_real=false means "This is likely a false positive or not exploitable."
- Only mark is_real=false if you can clearly articulate WHY it's not exploitable.
- Default to is_real=true if you're unsure — better to flag for human review than miss a real vuln.

Respond ONLY with valid JSON.`

// PromptVerify judges whether a potential vulnerability finding is real.
const PromptVerify = `You are a senior application security engineer. Judge whether this potential finding is a REAL vulnerability.

First, check for reasons it might be a FALSE POSITIVE:
- Is the input actually attacker-controllable? (config values are NOT)
- Is there implicit framework protection? (auto-escaping, ORM parameterization, middleware)
- Is the sink actually dangerous in this context?
- Are there compensating controls? (firewall, container, allowlists)

THEN, make your judgment:
- is_real: TRUE if this IS a real vulnerability. FALSE if it's a false positive.
- confidence: How certain are you? (0.0-1.0)
- If is_real=true: provide severity, CWE, title, description, fix_hint
- If is_real=false: use refutation_points to explain why it's NOT real

Respond ONLY with valid JSON:
{
  "is_real": true,
  "confidence": 0.95,
  "severity": "HIGH",
  "cwe": "CWE-89",
  "title": "SQL Injection in login handler",
  "description": "User input 'username' is concatenated directly into SQL query without parameterization",
  "fix_hint": "Use parameterized queries: db.QueryRow(\"SELECT ... WHERE username=? AND password=?\", username, password)",
  "refutation": "",
  "refutation_points": []
}

Finding to verify:
%s`

// ─── Phase B.2b: Missing Controls Prompts ────────────────────────────────────

// SystemPromptMissingControls teaches the LLM to audit HTTP handlers for missing security controls.
const SystemPromptMissingControls = `You are a senior application security engineer auditing an HTTP handler for MISSING security controls.

Unlike vulnerability scanners that look for bugs, your job is to find ABSENT protections — things that SHOULD be there but aren't.

For each handler, check these 5 controls:

1. AUTHENTICATION — Is there any auth check? (session, JWT, API key, middleware reference)
   - If the handler accesses user data or performs sensitive operations → auth is REQUIRED
   - Health checks and static content are exceptions

2. INPUT VALIDATION — Are input parameters validated?
   - Type checking (is the ID an integer?)
   - Range/length checking
   - Format validation (email, URL)
   - If input comes from user and flows to DB/exec/file → validation is REQUIRED

3. RATE LIMITING — Is there any rate limiting?
   - Login endpoints, password reset, API endpoints → rate limiting is REQUIRED
   - Not applicable for static/handler endpoints

4. CSRF PROTECTION — For state-changing operations (POST/PUT/DELETE):
   - Is there a CSRF token check?
   - Not applicable for GET-only or API (non-browser) endpoints

5. CONTENT-TYPE VALIDATION — Does the handler validate Content-Type?
   - JSON endpoints should require "application/json"
   - File upload endpoints should validate MIME types

For each handler, list which controls are MISSING (is_missing=true).
Only flag a control as missing if it's actually required for this endpoint type.
Be specific about severity: CRITICAL (auth missing on sensitive operation), HIGH (missing validation), MEDIUM (missing rate limit).

Respond ONLY with valid JSON.`

// PromptMissingControls is the per-handler prompt for security control audit.
const PromptMissingControls = `Audit this HTTP handler for missing security controls.

Check all 5 controls: authentication, input validation, rate limiting, CSRF protection, content-type validation.

For each control that is MISSING and REQUIRED, flag it. Skip controls that don't apply to this endpoint type.

Respond ONLY with valid JSON:
{
  "controls": [
    {
      "control_type": "auth",
      "is_missing": true,
      "confidence": 0.95,
      "severity": "CRITICAL",
      "title": "Missing authentication on admin user list endpoint",
      "description": "handleAdminUsers returns all user data without any authentication check. Anyone can access this endpoint and enumerate all users.",
      "fix_hint": "Add auth middleware. Example: wrap handler with RequireAuth() or check session token at function start.",
      "cwe": "CWE-306"
    }
  ]
}

Handler:
%s`

// ─── Phase B.2c: Config Audit Prompts ───────────────────────────────────────

// SystemPromptConfigAudit teaches the LLM to find dangerous configuration patterns.
const SystemPromptConfigAudit = `You are a senior security engineer reviewing code for dangerous configuration patterns.

Look for these categories of issues:

1. DEBUG MODE IN PRODUCTION:
   - debug=True, DEBUG=true, debug mode enabled
   - Server running on 0.0.0.0 (all interfaces) in production code
   - Verbose error messages exposing stack traces to users

2. DANGEROUS DEFAULTS:
   - Default admin passwords ("admin/admin", "root/root")
   - Insecure TLS configuration (TLS 1.0, weak ciphers)

3. MISSING SECURITY HEADERS:
   - No CORS restrictions (Allow-Origin: *)
   - Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options

4. WEAK SESSION CONFIGURATION:
   - Missing HttpOnly/Secure flags on cookies
   - Predictable session IDs
   - Long session timeouts without refresh

5. INSECURE DEPENDENCY CONFIGURATION:
   - Database connections without TLS
   - SMTP without STARTTLS
   - Redis without authentication

For each issue found, provide: func_name, issue_type, severity, title, description, fix_hint, cwe.
Only report issues with confidence >= 0.7.

Respond ONLY with valid JSON.`

// PromptConfigAudit is the config security review prompt.
const PromptConfigAudit = `Review these code sections for dangerous configuration patterns.

Check for: debug mode enabled, dangerous defaults, missing security headers, weak session config, insecure dependency config.

Respond ONLY with valid JSON:
{
  "issues": [
    {
      "func_name": "function name",
      "issue_type": "debug-mode",
      "confidence": 0.90,
      "severity": "MEDIUM",
      "title": "Debug mode enabled on all interfaces",
      "description": "Server configured with debug=True and host='0.0.0.0', exposing debug endpoints to the network",
      "fix_hint": "Set debug=False in production. Use environment-specific config.",
      "cwe": "CWE-489"
    }
  ]
}

Code sections:
%s`
