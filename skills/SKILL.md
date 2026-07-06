# Ironwall — 7-Step Security Audit Skill

**Skill for Claude Code.** Wraps the ironwall CLI for interactive security auditing.

## Metadata

- **Name:** ironwall
- **Version:** 0.1.0
- **Author:** FYFran (Wang Yifan)
- **License:** MIT
- **Requires:** ironwall CLI installed (`go install github.com/FYFran/ironwall/cmd/ironwall@latest`)

## Description

Run a 7-step security audit pipeline against any codebase. Ironwall detects:
1. **Secret scanning** — API keys, tokens, passwords (gitleaks)
2. **SAST analysis** — SQL injection, XSS, command injection (semgrep + AI)
3. **Endpoint audit** — Auth bypass, IDOR, missing access control (AI)
4. **Hardcoded secrets** — Patterns that gitleaks missed (regex + AI)
5. **Dependency CVE** — Known vulnerabilities in dependencies (govulncheck/npm/pip)
6. **Server configuration** — Docker, nginx, env misconfigurations
7. **Database audit** — Migration risks, SQL anti-patterns

All scanning happens **locally**. Your code never leaves your machine.

## Usage

### Basic scan
```
/ironwall scan .
```

### Quick scan (secrets only, < 30s)
```
/ironwall quick .
```

### Full scan with AI analysis
```
/ironwall scan . --ai
```
Requires `DEEPSEEK_API_KEY` or `IRONWALL_AI_KEY` set.

### Generate markdown report
```
/ironwall scan . --format markdown
```

### JSON output for CI
```
/ironwall scan . --format json --output report.json
```

### Scan a GitHub repo
```
git clone https://github.com/user/repo /tmp/repo
/ironwall scan /tmp/repo --format markdown
```

## Instructions for Claude

When the user invokes this skill:

1. **Run the scan** — Execute `ironwall scan <target>` with appropriate flags.
   - For quick checks: `ironwall quick <target>`
   - For detailed reports: `ironwall scan <target> --format markdown`
   - For AI-assisted: `ironwall scan <target> --ai` (ensure API key is set)

2. **Interpret results** — Review the findings and explain:
   - Which findings are **CRITICAL** (fix immediately)
   - Which are **HIGH** (fix before next deploy)
   - Which are **MEDIUM/LOW** (track in backlog)
   - Which might be **false positives** (explain the heuristic)

3. **Suggest fixes** — For each critical/high finding:
   - Show the vulnerable code
   - Provide a concrete fix
   - Explain why the fix works

4. **Generate summary** — After the scan:
   - Total findings by severity
   - Top 3 most critical issues
   - Recommended action items

## Attack Scenario Verification

Every finding goes through three questions:
- **Q1 (Actor):** Who can exploit this? What access do they need?
- **Q2 (Path):** What are the exact steps to exploit?
- **Q3 (Impact):** What does the attacker gain?

If all three have concrete answers → **real vulnerability.**
If any question can't be answered → **likely false positive.**

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | terminal | `terminal`, `markdown`, `json` |
| `--output` | auto | Output file path |
| `--quick` | false | Steps 1+4 only |
| `--ai` | false | Enable AI analysis |
| `--ai-model` | deepseek-chat | Model name |
| `--timeout` | 300 | Max seconds |
| `--verbose` | false | Verbose output |

## Environment Variables

- `IRONWALL_AI_KEY` or `DEEPSEEK_API_KEY` — AI API key
- `IRONWALL_AI_ENDPOINT` — Custom API endpoint (default: DeepSeek)

## Example Session

```
User: /ironwall scan ./my-go-api

Claude runs: ironwall scan ./my-go-api

Output:
🔍 ironwall v0.1.0 — 7-Step Security Audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:    ./my-go-api
Duration:  12.3s

🔑 Secret scanning         2 found
🔬 SAST analysis            5 found
🔗 Endpoint audit          3 found
🔐 Hardcoded secrets       0 found
📦 Dependency CVE          1 found
🖥️  Server config           SKIP
🗄️  Database audit          2 found

📊 SUMMARY
🔴 CRITICAL: 1  🟠 HIGH: 5  🟡 MEDIUM: 5  🟢 LOW: 3

Claude: Found 13 findings. 1 CRITICAL — hardcoded JWT secret in config.go.
This allows anyone with source code access to forge valid JWT tokens.
Fix: move to environment variable. Here's the code change...

[Detailed fix provided]
```

## Installation

```bash
# Install ironwall CLI
go install github.com/FYFran/ironwall/cmd/ironwall@latest

# Install required external tools
go install github.com/gitleaks/gitleaks/v8@latest
pip install semgrep

# Optional: for AI-assisted analysis
export DEEPSEEK_API_KEY="sk-..."

# Verify installation
ironwall version
```

## Repository

- **GitHub:** https://github.com/FYFran/ironwall
- **Issues:** https://github.com/FYFran/ironwall/issues
- **Methodology:** https://github.com/FYFran/ironwall/blob/main/docs/methodology.md
