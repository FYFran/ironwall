package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ReportBuilder Tests
// =============================================================================

func TestReportBuilder_BuildReport_CRITICAL(t *testing.T) {
	builder := NewReportBuilder()
	result := AnalystResult{
		FindingID:     "GOLDEN-001",
		Title:         "DES Cipher Used for Encryption",
		Severity:      SevCritical,
		IsExploitable: true,
		Confidence:    0.95,
		Narrative:     "DES is a broken 56-bit cipher. Feasible to brute-force with cloud GPUs.",
		AttackPath: []AttackStep{
			{StepNumber: 1, Description: "Intercept ciphertext", FileRef: "crypto.go", LineRef: 27},
			{StepNumber: 2, Description: "Brute-force 56-bit key", FileRef: "crypto.go", LineRef: 28},
			{StepNumber: 3, Description: "Decrypt all traffic", FileRef: "crypto.go", LineRef: 33},
		},
		Evidence: []EvidenceItem{
			{Type: "code", Description: "Uses crypto/des package", FilePath: "crypto.go", LineNumber: 27, CodeSnippet: "des.NewCipher(key)", Confidence: "certain"},
		},
		Verification: VerificationResult{
			Verified: true,
			Method:   "ast-reachability",
			Detail:   "encryptDES is called from main() with user-controlled plaintext",
			IsReachable: true,
			ReachPath:  "main() → encryptDES(plaintext, key)",
		},
		CWE:           "CWE-327",
		CVSS:          7.4,
		FixSuggestion: "Replace with AES-256-GCM.",
	}

	report, err := builder.BuildReport(result)
	require.NoError(t, err)
	require.NotEmpty(t, report)

	// CRITICAL findings get all 6 sections.
	assert.Contains(t, report, "Executive Summary")
	assert.Contains(t, report, "Analysis Narrative")
	assert.Contains(t, report, "Evidence")
	assert.Contains(t, report, "Attack Path")
	assert.Contains(t, report, "Verification")
	assert.Contains(t, report, "Remediation")
	assert.Contains(t, report, "CONFIRMED — EXPLOITABLE")
	assert.Contains(t, report, "CWE-327")
}

func TestReportBuilder_BuildReport_HIGH(t *testing.T) {
	builder := NewReportBuilder()
	result := AnalystResult{
		FindingID:     "GOLDEN-005",
		Title:         "SQL Injection in Flask Route",
		Severity:      SevHigh,
		IsExploitable: true,
		Confidence:    0.88,
		Narrative:     "f-string interpolation on user input in SQL query.",
		AttackPath: []AttackStep{
			{StepNumber: 1, Description: "Send malicious username", FileRef: "injection.py", LineRef: 10},
		},
		Evidence: []EvidenceItem{
			{Type: "code", Description: "f-string in SQL query", FilePath: "injection.py", LineNumber: 13, Confidence: "certain"},
		},
		CWE: "CWE-89",
		CVSS: 8.6,
		FixSuggestion: "Use parameterized queries.",
	}

	report, err := builder.BuildReport(result)
	require.NoError(t, err)

	// HIGH findings get 4 sections (no Narrative, no Verification).
	assert.Contains(t, report, "Summary")
	assert.Contains(t, report, "Evidence")
	assert.Contains(t, report, "Attack Path")
	assert.Contains(t, report, "Remediation")
	assert.NotContains(t, report, "Analysis Narrative")
	assert.NotContains(t, report, "Verification")
}

func TestReportBuilder_BuildReport_MEDIUM(t *testing.T) {
	builder := NewReportBuilder()
	result := AnalystResult{
		FindingID:     "GOLDEN-002",
		Title:         "math/rand for Token Generation",
		Severity:      SevMedium,
		IsExploitable: true,
		Confidence:    0.70,
		Narrative:     "math/rand is not cryptographically secure.",
		CWE:           "CWE-338",
		CVSS:          5.9,
		FixSuggestion: "Use crypto/rand instead.",
	}

	report, err := builder.BuildReport(result)
	require.NoError(t, err)

	// MEDIUM gets 1 condensed section.
	assert.Contains(t, report, "Finding")
	assert.Contains(t, report, "crypto/rand")
	assert.NotContains(t, report, "Analysis Narrative")
	assert.NotContains(t, report, "Attack Path")
	assert.NotContains(t, report, "Verification")
}

func TestReportBuilder_BuildReport_REJECTED(t *testing.T) {
	builder := NewReportBuilder()
	result := AnalystResult{
		FindingID:     "GOLDEN-010",
		Title:         "Hardcoded Placeholder Token",
		Severity:      SevLow,
		IsExploitable: false,
		Confidence:    0.95,
		Narrative:     "These are documentation placeholders, not real secrets.",
		CWE:           "CWE-798",
		CVSS:          0.0,
		FixSuggestion: "",
	}

	report, err := builder.BuildReport(result)
	require.NoError(t, err)

	assert.Contains(t, report, "REJECTED — NOT EXPLOITABLE")
}

func TestReportBuilder_EmptyID_ReturnsError(t *testing.T) {
	builder := NewReportBuilder()
	_, err := builder.BuildReport(AnalystResult{})
	assert.Error(t, err)
}

func TestReportBuilder_BuildSections_ReturnsOrdered(t *testing.T) {
	builder := NewReportBuilder()
	result := AnalystResult{
		FindingID:     "TEST-001",
		Title:         "Test",
		Severity:      SevCritical,
		IsExploitable: true,
		Confidence:    0.9,
		Narrative:     "test narrative",
		AttackPath:    []AttackStep{{StepNumber: 1, Description: "test step"}},
		Evidence:      []EvidenceItem{{Type: "code", Description: "test evidence", Confidence: "certain"}},
		Verification:  VerificationResult{Verified: true, Method: "api-call", Detail: "test verification"},
		CWE:           "CWE-79",
		CVSS:          7.0,
		FixSuggestion: "test fix",
	}

	sections, err := builder.BuildSections(result)
	require.NoError(t, err)
	require.Len(t, sections, 6)

	// Verify order.
	for i, sec := range sections {
		assert.Equal(t, i+1, sec.Order, "section %d order mismatch", i+1)
	}
}

func TestReportBuilder_RawFindingsInFooter(t *testing.T) {
	builder := NewReportBuilder()
	result := AnalystResult{
		FindingID:     "TEST-001",
		Title:         "Test",
		Severity:      SevHigh,
		IsExploitable: true,
		Confidence:    0.9,
		Narrative:     "test",
		CWE:           "CWE-79",
		CVSS:          7.0,
		RawFindings: []RawFinding{
			{Source: "gitleaks", RuleID: "aws-access-key", FilePath: "secrets.py", Line: 5, Snippet: "AKIA..."},
			{Source: "semgrep", RuleID: "hardcoded-secret", FilePath: "secrets.py", Line: 5, Snippet: "AWS_ACCESS_KEY"},
		},
	}

	report, err := builder.BuildReport(result)
	require.NoError(t, err)

	assert.Contains(t, report, "Raw Scanner Findings")
	assert.Contains(t, report, "gitleaks")
	assert.Contains(t, report, "semgrep")
}

// =============================================================================
// golden.json Validation Set Tests
// =============================================================================

// GoldenEntry mirrors the structure in golden.json.
type GoldenEntry struct {
	ID              string               `json:"id"`
	Source          string               `json:"source"`
	Title           string               `json:"title"`
	Description     string               `json:"description"`
	Severity        string               `json:"severity"`
	FilePath        string               `json:"file_path"`
	LineNumber      int                  `json:"line_number"`
	CodeSnippet     string               `json:"code_snippet"`
	Category        string               `json:"category"`
	IsExploitable   bool                 `json:"is_exploitable"`
	AttackSteps     []AttackStep         `json:"attack_steps"`
	CVSS            float64              `json:"cvss"`
	CWE             string               `json:"cwe"`
	Fix             string               `json:"fix"`
	AIShouldConfirm bool                 `json:"ai_should_confirm"`
	AIShouldReject  bool                 `json:"ai_should_reject"`
	Notes           string               `json:"notes"`
}

// GoldenSet is the full golden.json data.
type GoldenSet struct {
	Version     string        `json:"version"`
	Created     string        `json:"created"`
	Description string        `json:"description"`
	Findings    []GoldenEntry `json:"findings"`
	Metrics     struct {
		Total                    int     `json:"total"`
		Critical                 int     `json:"critical"`
		High                     int     `json:"high"`
		Medium                   int     `json:"medium"`
		Low                      int     `json:"low"`
		ShouldConfirm            int     `json:"should_confirm"`
		ShouldReject             int     `json:"should_reject"`
		ExpectedAIPrecision      string  `json:"expected_ai_precision"`
		BaselineScannerPrecision float64 `json:"baseline_scanner_precision"`
		BaselineScannerNote      string  `json:"baseline_scanner_note,omitempty"`
	} `json:"metrics"`
}

func TestGoldenJSON_LoadsAndValidates(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "testdata", "agent_bench", "golden.json")
	data, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden.json not found at %s", goldenPath)

	var golden GoldenSet
	err = json.Unmarshal(data, &golden)
	require.NoError(t, err, "golden.json is not valid JSON")

	// Verify counts match.
	assert.Equal(t, 10, golden.Metrics.Total, "expected 10 findings")
	assert.Len(t, golden.Findings, 10, "should have exactly 10 findings")

	// Verify should_confirm + should_reject = total.
	confirmCount := 0
	rejectCount := 0
	for _, f := range golden.Findings {
		if f.AIShouldConfirm {
			confirmCount++
		}
		if f.AIShouldReject {
			rejectCount++
		}
	}
	assert.Equal(t, golden.Metrics.ShouldConfirm, confirmCount, "should_confirm count mismatch")
	assert.Equal(t, golden.Metrics.ShouldReject, rejectCount, "should_reject count mismatch")
}

func TestGoldenJSON_AllFindingsHaveRequiredFields(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "testdata", "agent_bench", "golden.json")
	data, err := os.ReadFile(goldenPath)
	require.NoError(t, err)

	var golden GoldenSet
	err = json.Unmarshal(data, &golden)
	require.NoError(t, err)

	for _, f := range golden.Findings {
		t.Run(f.ID, func(t *testing.T) {
			assert.NotEmpty(t, f.ID, "ID required")
			assert.NotEmpty(t, f.Title, "Title required")
			assert.NotEmpty(t, f.Severity, "Severity required")
			assert.NotEmpty(t, f.FilePath, "FilePath required")
			assert.Greater(t, f.LineNumber, 0, "LineNumber must be > 0")
			assert.NotEmpty(t, f.Category, "Category required")
			assert.NotEmpty(t, f.CWE, "CWE required")
			assert.NotEmpty(t, f.Fix, "Fix required")

			// CRITICAL/HIGH findings must have attack steps.
			if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
				assert.NotEmpty(t, f.AttackSteps, "CRITICAL/HIGH must have attack_steps")
			}

			// Severity must be valid.
			validSeverities := map[string]bool{
				"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true,
			}
			assert.True(t, validSeverities[f.Severity], "invalid severity: %s", f.Severity)
		})
	}
}

func TestGoldenJSON_NoOverlappingConfirmReject(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "testdata", "agent_bench", "golden.json")
	data, err := os.ReadFile(goldenPath)
	require.NoError(t, err)

	var golden GoldenSet
	err = json.Unmarshal(data, &golden)
	require.NoError(t, err)

	for _, f := range golden.Findings {
		assert.False(t, f.AIShouldConfirm && f.AIShouldReject,
			"%s: ai_should_confirm and ai_should_reject cannot both be true", f.ID)
	}
}

// =============================================================================
// Mock LLM Client — for testing Agent output format.
// =============================================================================

// MockLLMClient is a mock LLM client that returns predefined responses.
type MockLLMClient struct {
	Responses []string
	CallCount int
}

func (m *MockLLMClient) Chat(systemPrompt, userPrompt string) (string, error) {
	if m.CallCount >= len(m.Responses) {
		return `{"error": "no more mock responses"}`, nil
	}
	resp := m.Responses[m.CallCount]
	m.CallCount++
	return resp, nil
}

// TestMockLLMClient_ParsesAnalystJSON validates that the mock client
// can return JSON that matches AnalystResult structure.
func TestMockLLMClient_ParsesAnalystJSON(t *testing.T) {
	mock := &MockLLMClient{
		Responses: []string{`{
			"finding_id": "TEST-001",
			"title": "Command Injection via shell=True",
			"severity": "CRITICAL",
			"is_exploitable": true,
			"confidence": 0.95,
			"narrative": "The code passes user input directly to subprocess with shell=True.",
			"attack_path": [
				{"step_number": 1, "description": "Send malicious cmd param", "file_ref": "injection.py", "line_ref": 30}
			],
			"evidence": [
				{"type": "code", "description": "shell=True with user input", "file_path": "injection.py", "line_number": 32, "code_snippet": "subprocess.check_output(cmd, shell=True)", "confidence": "certain"}
			],
			"verification": {
				"verified": true,
				"method": "ast-reachability",
				"detail": "Direct path from request.args to subprocess.check_output",
				"is_reachable": true,
				"reach_path": "request.args.get('cmd') → subprocess.check_output(cmd, shell=True)"
			},
			"cwe": "CWE-78",
			"cvss": 9.8,
			"fix_suggestion": "Never use shell=True with user input."
		}`},
	}

	resp, err := mock.Chat("system", "user")
	require.NoError(t, err)

	var result AnalystResult
	err = json.Unmarshal([]byte(resp), &result)
	require.NoError(t, err, "Mock response must parse as AnalystResult")

	assert.Equal(t, "CRITICAL", string(result.Severity))
	assert.True(t, result.IsExploitable)
	assert.Len(t, result.AttackPath, 1)
	assert.Len(t, result.Evidence, 1)
	assert.True(t, result.Verification.Verified)
}

// =============================================================================
// AnalystResult → ReportBuilder integration test.
// =============================================================================

func TestAnalystResult_ToReport_Integration(t *testing.T) {
	// Simulate: mock LLM returns JSON → unmarshal → pass to ReportBuilder → get markdown.
	mock := &MockLLMClient{
		Responses: []string{`{
			"finding_id": "IRON-001",
			"title": "Hardcoded AWS Credentials in secrets.py",
			"severity": "CRITICAL",
			"is_exploitable": true,
			"confidence": 0.98,
			"narrative": "Both AWS_ACCESS_KEY and AWS_SECRET_KEY are hardcoded in source code. If pushed to a public repository, anyone can extract these credentials and gain full AWS API access. The key pattern AKIA* matches IAM user access keys.",
			"attack_path": [
				{"step_number": 1, "description": "Clone or view the public repository", "file_ref": "secrets.py", "line_ref": 5},
				{"step_number": 2, "description": "Extract AWS_ACCESS_KEY and AWS_SECRET_KEY", "file_ref": "secrets.py", "line_ref": 6},
				{"step_number": 3, "description": "Configure AWS CLI with stolen credentials", "file_ref": null, "line_ref": 0},
				{"step_number": 4, "description": "Access all AWS resources the IAM user has permissions for", "file_ref": null, "line_ref": 0}
			],
			"evidence": [
				{"type": "code", "description": "Hardcoded AWS access key matching AKIA* pattern", "file_path": "secrets.py", "line_number": 5, "code_snippet": "AWS_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLE\"", "confidence": "certain"},
				{"type": "code", "description": "Hardcoded AWS secret key in adjacent line", "file_path": "secrets.py", "line_number": 6, "code_snippet": "AWS_SECRET_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"", "confidence": "certain"}
			],
			"verification": {
				"verified": true,
				"method": "regex-match",
				"detail": "AKIA* pattern matches IAM user access key format. Secret key matches 40-char base64 pattern.",
				"is_reachable": false
			},
			"cwe": "CWE-798",
			"cvss": 9.8,
			"fix_suggestion": "Replace hardcoded credentials with environment variables or IAM roles. Use os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'). For production: use IAM roles (EC2, ECS, Lambda) or AWS Secrets Manager.",
			"raw_findings": [
				{"source": "gitleaks", "rule_id": "aws-access-key", "file_path": "secrets.py", "line": 5, "snippet": "AKIA..."},
				{"source": "semgrep", "rule_id": "generic.secrets.security.detected-aws-access-key", "file_path": "secrets.py", "line": 5, "snippet": "AWS_ACCESS_KEY"}
			]
		}`},
	}

	// Phase 1: LLM → JSON → AnalystResult.
	resp, err := mock.Chat("system", "user")
	require.NoError(t, err)

	var result AnalystResult
	err = json.Unmarshal([]byte(resp), &result)
	require.NoError(t, err)

	// Phase 2: AnalystResult → ReportBuilder → Markdown.
	builder := NewReportBuilder()
	report, err := builder.BuildReport(result)
	require.NoError(t, err)

	// Verify report contains key elements.
	assert.Contains(t, report, "# Security Finding: Hardcoded AWS Credentials in secrets.py")
	assert.Contains(t, report, "CONFIRMED — EXPLOITABLE")
	assert.Contains(t, report, "Executive Summary")
	assert.Contains(t, report, "Analysis Narrative")
	assert.Contains(t, report, "Evidence")
	assert.Contains(t, report, "Attack Path")
	assert.Contains(t, report, "Verification")
	assert.Contains(t, report, "Remediation")
	assert.Contains(t, report, "CWE-798")
	assert.Contains(t, report, "9.8")

	t.Logf("Generated report:\n%s", report)
}

// =============================================================================
// JSON parse resilience tests — simulates the 3-layer fallback from GoldHunter.
// =============================================================================

func TestParseAnalystJSON_ValidJSON(t *testing.T) {
	valid := `{"finding_id": "X", "title": "T", "severity": "HIGH", "is_exploitable": true, "confidence": 0.8, "narrative": "n", "cwe": "CWE-79", "cvss": 7.0}`

	var result AnalystResult
	err := json.Unmarshal([]byte(valid), &result)
	assert.NoError(t, err)
	assert.Equal(t, SevHigh, result.Severity)
}

func TestParseAnalystJSON_MissingOptionalFields(t *testing.T) {
	// Only required fields — attack_path, evidence, verification can be missing.
	minimal := `{"finding_id": "X", "title": "T", "severity": "LOW", "is_exploitable": false, "confidence": 0.5, "narrative": "n", "cwe": "CWE-79", "cvss": 0.0}`

	var result AnalystResult
	err := json.Unmarshal([]byte(minimal), &result)
	assert.NoError(t, err)
	assert.Empty(t, result.AttackPath)
	assert.Empty(t, result.Evidence)
	assert.False(t, result.Verification.Verified)
}
