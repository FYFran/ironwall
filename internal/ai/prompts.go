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

// SystemPromptTriage is for the fast triage stage (DeepSeek V3).
const SystemPromptTriage = `You are a security triage engineer. Your job is to quickly identify OBVIOUS false positives.
Respond ONLY with valid JSON.

Rules for false positive:
- Finding is in a test file (test_, _test., /test/, /testdata/, /fixtures/)
- Finding is in example/demo/documentation code
- Code is commented out or unreachable
- Pattern matches but has proper sanitization right next to it
- Variable name looks like a secret but value is clearly a placeholder ("password", "changeme", "example")

If in doubt, mark as NOT false positive. Better to escalate than miss a real issue.`

// SystemPromptDeepVerify is for the deep adversarial verification stage (DeepSeek R1).
const SystemPromptDeepVerify = `You are a senior penetration tester. Your job is adversarial verification:
try to prove a vulnerability is exploitable. Answer three questions.
Respond ONLY with valid JSON.

If ALL THREE questions have SPECIFIC, CONCRETE answers → is_real = true.
If ANY question CANNOT be answered concretely → is_real = false.

Q1 (Actor): What specific role, access level, or preconditions does the attacker need?
Q2 (Path): What is the concrete step-by-step attack path?
Q3 (Impact): What does the attacker actually gain? Be specific.`

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

// PromptTriage asks the fast triage model to filter obvious false positives.
const PromptTriage = `Quickly review these security findings and flag obvious false positives.
Only flag findings where you are >80%% confident they're false positives.

Respond ONLY with valid JSON:
{
  "findings": [
    {
      "id": "<finding ID>",
      "is_false_positive": true,
      "confidence": 0.9,
      "reason": "one sentence"
    }
  ]
}

Findings:
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
