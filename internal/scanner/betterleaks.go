package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// BetterleaksFinding is the JSON structure Betterleaks outputs.
// Identical to gitleaks format — drop-in compatible.
type BetterleaksFinding struct {
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
	Verified    bool     `json:"Verified,omitempty"` // Betterleaks CEL verification
}

// BetterleaksResult wraps the output of `betterleaks detect --report-format json`.
// Drop-in compatible with GitleaksResult.
type BetterleaksResult struct {
	Findings []BetterleaksFinding
	RawJSON  string
}

// RunBetterleaks runs Betterleaks detect on the given target directory.
// Falls back to gitleaks if Betterleaks is not installed.
// Betterleaks uses BPE tokenization (98.6% recall) instead of Shannon entropy (70.4%).
func RunBetterleaks(target string) (*BetterleaksResult, error) {
	// Prefer Betterleaks (MIT license, 98.6% recall, actively maintained)
	if _, err := exec.LookPath("betterleaks"); err == nil {
		return runBetterleaksCmd("betterleaks", target)
	}
	// Fall back to gitleaks
	return runBetterleaksCmd("gitleaks", target)
}

func runBetterleaksCmd(binary, target string) (*BetterleaksResult, error) {
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
	cmd := exec.Command(binary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		raw := strings.TrimSpace(string(out))
		if raw == "" {
			return nil, fmt.Errorf("%s failed: %w (no output)", binary, err)
		}
		if !strings.HasPrefix(raw, "[") && !strings.HasPrefix(raw, "{") {
			return nil, fmt.Errorf("%s failed: %w\n%s", binary, err, string(out))
		}
		return parseBetterleaksOutput(out)
	}
	return parseBetterleaksOutput(out)
}

// parseBetterleaksOutput parses Betterleaks/gitleaks JSON output.
func parseBetterleaksOutput(raw []byte) (*BetterleaksResult, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "[]" {
		return &BetterleaksResult{}, nil
	}

	var findings []BetterleaksFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse betterleaks JSON output: %w\nraw: %s", err, s)
	}

	return &BetterleaksResult{
		Findings: findings,
		RawJSON:  s,
	}, nil
}

// ToFindings converts Betterleaks findings to ironwall Finding structs.
func (r *BetterleaksResult) ToFindings(target string) []report.Finding {
	var findings []report.Finding
	for i, f := range r.Findings {
		severity := classifyBetterleaksSeverity(f)
		findings = append(findings, report.Finding{
			ID:          fmt.Sprintf("IRON-SECRET-%03d", i+1),
			Title:       fmt.Sprintf("Secret detected: %s", f.Description),
			Description: fmt.Sprintf("Betterleaks detected a %s in %s:%d. Rule: %s. Entropy: %.2f", f.Description, f.File, f.StartLine, f.RuleID, f.Entropy),
			Severity:    severity,
			FilePath:    f.File,
			LineNumber:  f.StartLine,
			CodeSnippet: fmt.Sprintf("  %d | %s", f.StartLine, maskSecret(f.Secret)),
			Step:        1,
			Category:    "secret-detected",
			CWE:         mapBetterleaksSeverityToCWE(severity),
			CVSS:        mapBetterleaksSeverityToCVSS(severity),
			ToolOutput:  fmt.Sprintf("Rule: %s | Tags: %v | Entropy: %.2f | Verified: %v", f.RuleID, f.Tags, f.Entropy, f.Verified),
			References:  []string{"https://github.com/zricethezav/betterleaks"},
		})
	}
	return findings
}

// classifyBetterleaksSeverity maps Betterleaks rule IDs and tags to ironwall severity.
func classifyBetterleaksSeverity(f BetterleaksFinding) report.Severity {
	// Check tags for severity hints
	for _, tag := range f.Tags {
		switch strings.ToLower(tag) {
		case "critical", "key", "credentials":
			return report.SevCritical
		case "api", "token":
			return report.SevHigh
		}
	}

	// Entropy-based heuristic (Betterleaks BPE is more accurate than Shannon)
	if f.Entropy > 5.0 {
		return report.SevHigh
	}
	return report.SevMedium
}

func mapBetterleaksSeverityToCWE(s report.Severity) string {
	switch s {
	case report.SevCritical:
		return "CWE-798"
	case report.SevHigh:
		return "CWE-200"
	default:
		return "CWE-312"
	}
}

func mapBetterleaksSeverityToCVSS(s report.Severity) float64 {
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
