package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// GosecResult holds the results of a gosec scan.
type GosecResult struct {
	Issues []GosecIssue `json:"Issues"`
}

// GosecIssue is a single gosec finding (parsed from JSON output).
type GosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Cwe        struct {
		ID  string `json:"ID"`
		URL string `json:"URL"`
	} `json:"cwe"`
	RuleID string `json:"rule_id"`
	What   string `json:"details"`
	File   string `json:"file"`
	Line   string `json:"line"`
	Col    string `json:"column"`
	Code   string `json:"code"`
}

// RunGosec runs gosec CLI on the target directory and parses JSON output.
func RunGosec(target string) (*GosecResult, error) {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("gosec: resolve path: %w", err)
	}

	// Run gosec from target directory with JSON output
	cmd := exec.Command("gosec", "-fmt=json", "-no-fail", "-quiet", "./...")
	cmd.Dir = absTarget

	output, err := cmd.Output()
	if err != nil {
		// gosec exits non-zero when issues found — that's expected, try to parse anyway
		if len(output) == 0 {
			return nil, fmt.Errorf("gosec: %w (no output)", err)
		}
	}

	var result GosecResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("gosec: parse JSON: %w (output: %.200s)", err, string(output))
	}

	// Make file paths absolute
	for i := range result.Issues {
		if !filepath.IsAbs(result.Issues[i].File) {
			result.Issues[i].File = filepath.Join(absTarget, result.Issues[i].File)
		}
	}

	return &result, nil
}

// ToFindings converts gosec issues to ironwall Finding structs.
func (r *GosecResult) ToFindings(target string) []report.Finding {
	if r == nil || len(r.Issues) == 0 {
		return nil
	}

	absTarget, _ := filepath.Abs(target)

	var findings []report.Finding
	for i, iss := range r.Issues {
		sev := mapGosecSeverityStr(iss.Severity)
		cwe := iss.Cwe.ID
		category := mapGosecRuleToCategory(iss.RuleID)
		lineNum, _ := strconv.Atoi(iss.Line)

		filePath := iss.File
		// Make relative to target if absolute
		if strings.HasPrefix(filePath, absTarget) {
			filePath = strings.TrimPrefix(filePath, absTarget+"/")
			filePath = strings.TrimPrefix(filePath, absTarget+"\\")
		}

		var codeSnippet string
		if iss.Code != "" {
			codeSnippet = fmt.Sprintf("  %s | %s", iss.Line, strings.TrimSpace(iss.Code))
		}

		description := iss.What
		confidence := mapGosecConfidence(iss.Confidence)
		if confidence > 0 {
			description += fmt.Sprintf("\nGosec confidence: %.0f%%", confidence*100)
		}

		suffix := ""
		if iss.RuleID != "" {
			suffix = " " + iss.RuleID
		}

		findings = append(findings, report.Finding{
			ID:          fmt.Sprintf("IRON-GOSEC-%03d", i+1),
			Title:       fmt.Sprintf("Potential%s: %s", suffix, iss.What),
			Description: description,
			Severity:    sev,
			FilePath:    filePath,
			LineNumber:  lineNum,
			CodeSnippet: codeSnippet,
			Step:        2,
			Category:    category,
			CWE:         cwe,
			CVSS:        report.SeverityToCVSS(sev),
			ToolOutput:  fmt.Sprintf("Rule: %s | Line: %s | Column: %s", iss.RuleID, iss.Line, iss.Col),
			References:  []string{"https://github.com/securego/gosec#available-rules"},
		})
	}
	return findings
}

func mapGosecSeverityStr(s string) report.Severity {
	switch strings.ToUpper(s) {
	case "HIGH":
		return report.SevHigh
	case "MEDIUM":
		return report.SevMedium
	case "LOW":
		return report.SevLow
	default:
		return report.SevLow
	}
}

func mapGosecConfidence(s string) float64 {
	switch strings.ToUpper(s) {
	case "HIGH":
		return 0.9
	case "MEDIUM":
		return 0.6
	case "LOW":
		return 0.3
	default:
		return 0.0
	}
}

func mapGosecRuleToCategory(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "G1"):
		return "hardcoded-credentials"
	case strings.HasPrefix(ruleID, "G2"):
		return "sql-injection"
	case strings.HasPrefix(ruleID, "G3"):
		return "path-traversal"
	case strings.HasPrefix(ruleID, "G4"):
		return "weak-crypto"
	case strings.HasPrefix(ruleID, "G5"):
		return "insecure-configuration"
	case strings.HasPrefix(ruleID, "G6"):
		return "injection"
	case isTaintRule(ruleID):
		return "injection"
	default:
		return "static-analysis"
	}
}

func isTaintRule(ruleID string) bool {
	taintPrefixes := []string{"G701", "G702", "G703", "G704", "G705", "G706", "G707", "G708", "G709", "G710"}
	for _, p := range taintPrefixes {
		if strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}
