package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// gitleaksFinding is the JSON structure gitleaks outputs per finding.
type gitleaksFinding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string   `json:"RuleID"`
	Fingerprint string   `json:"Fingerprint"`
}

// GitleaksResult wraps the output of `gitleaks detect --report-format json`.
type GitleaksResult struct {
	Findings []gitleaksFinding
	RawJSON  string
}

// RunGitleaks runs gitleaks detect on the given target directory.
// It returns parsed findings and any error.
func RunGitleaks(target string) (*GitleaksResult, error) {
	args := []string{
		"detect",
		"--no-git",
		"--source", target,
		"-f", "json",
		"-r", "-", // JSON to stdout
		"--no-banner",
		"--log-level", "error",
		"--exit-code", "0",
	}
	cmd := exec.Command("gitleaks", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		raw := strings.TrimSpace(string(out))
		if raw == "" {
			return nil, fmt.Errorf("gitleaks failed: %w (no output)", err)
		}
		if !strings.HasPrefix(raw, "[") && !strings.HasPrefix(raw, "{") {
			return nil, fmt.Errorf("gitleaks failed: %w\n%s", err, string(out))
		}
		return parseGitleaksOutput(out)
	}
	return parseGitleaksOutput(out)
}

// parseGitleaksOutput parses gitleaks JSON output.
func parseGitleaksOutput(raw []byte) (*GitleaksResult, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "[]" {
		return &GitleaksResult{}, nil
	}

	var findings []gitleaksFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks JSON output: %w\nraw: %s", err, s)
	}

	return &GitleaksResult{
		Findings: findings,
		RawJSON:  s,
	}, nil
}

// ToFindings converts gitleaks findings to ironwall Finding structs.
func (r *GitleaksResult) ToFindings(target string) []report.Finding {
	var findings []report.Finding
	for i, f := range r.Findings {
		severity := classifyGitleaksSeverity(f)
		findings = append(findings, report.Finding{
			ID:          fmt.Sprintf("IRON-GITLEAKS-%03d", i+1),
			Title:       fmt.Sprintf("Secret detected: %s", f.Description),
			Description: fmt.Sprintf("Gitleaks detected a %s in %s:%d. Rule: %s. Entropy: %.2f", f.Description, f.File, f.StartLine, f.RuleID, f.Entropy),
			Severity:    severity,
			FilePath:    f.File,
			LineNumber:  f.StartLine,
			CodeSnippet: fmt.Sprintf("  %d | %s", f.StartLine, maskSecret(f.Secret)),
			Step:        1,
			Category:    "secret-detected",
			CWE:         mapSeverityToCWE(severity),
			CVSS:        mapSeverityToCVSS(severity),
			ToolOutput:  fmt.Sprintf("Rule: %s | Tags: %v | Entropy: %.2f", f.RuleID, f.Tags, f.Entropy),
			References:  []string{"https://github.com/gitleaks/gitleaks"},
		})
	}
	return findings
}

// classifyGitleaksSeverity maps gitleaks rule IDs and tags to ironwall severity.
func classifyGitleaksSeverity(f gitleaksFinding) report.Severity {
	// Check tags for severity hints
	for _, tag := range f.Tags {
		switch strings.ToLower(tag) {
		case "critical", "key", "credentials":
			return report.SevCritical
		case "api", "token":
			return report.SevHigh
		}
	}

	// Entropy-based heuristic
	if f.Entropy > 5.0 {
		return report.SevHigh
	}
	return report.SevMedium
}

// mapSeverityToCWE maps severity to a representative CWE.
func mapSeverityToCWE(s report.Severity) string {
	switch s {
	case report.SevCritical:
		return "CWE-798" // Hardcoded Credentials
	case report.SevHigh:
		return "CWE-200" // Exposure of Sensitive Information
	default:
		return "CWE-312" // Cleartext Storage of Sensitive Information
	}
}

// mapSeverityToCVSS maps severity to a rough CVSS score.
func mapSeverityToCVSS(s report.Severity) float64 {
	switch s {
	case report.SevCritical:
		return 9.8
	case report.SevHigh:
		return 7.5
	case report.SevMedium:
		return 5.0
	case report.SevLow:
		return 2.5
	default:
		return 0.0
	}
}

// maskSecret replaces the middle of a secret with asterisks for safe display.
func maskSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}
