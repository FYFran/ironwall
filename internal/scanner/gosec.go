package scanner

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/rules"

	"github.com/FYFran/ironwall/internal/report"
)

// GosecResult holds the results of an embedded gosec scan.
type GosecResult struct {
	Issues  []*issue.Issue
	Metrics *gosec.Metrics
	Errors  map[string][]gosec.Error
}

// RunGosec runs an embedded gosec scan on the target directory.
// This replaces the semgrep subprocess with native Go AST analysis.
func RunGosec(target string) (*GosecResult, error) {
	conf := gosec.NewConfig()
	// Configure for thorough analysis
	conf.Set("G101", map[string]interface{}{
		"mode": "strict",
	})
	conf.Set("G401", map[string]interface{}{"mode": "strict"})
	conf.Set("G501", map[string]interface{}{"mode": "strict"})

	analyzer := gosec.NewAnalyzer(conf, false, true, false, 0, nil)

	// Load all default gosec rules
	ruleList := rules.Generate(false)
	ruleDefs, ruleSuppressed := ruleList.RulesInfo()
	analyzer.LoadRules(ruleDefs, ruleSuppressed)

	// Run the scan
	err := analyzer.Process(nil, target+"/...")
	if err != nil {
		return nil, fmt.Errorf("gosec process failed: %w", err)
	}

	issues, metrics, errs := analyzer.Report()

	return &GosecResult{
		Issues:  issues,
		Metrics: metrics,
		Errors:  errs,
	}, nil
}

// ToFindings converts gosec issues to ironwall Finding structs.
func (r *GosecResult) ToFindings(target string) []report.Finding {
	if r == nil || len(r.Issues) == 0 {
		return nil
	}

	var findings []report.Finding
	for i, iss := range r.Issues {
		sev := mapGosecSeverity(iss.Severity)
		cwe := iss.Cwe.ID
		category := mapGosecRuleToCategory(iss.RuleID)
		lineNum, _ := strconv.Atoi(iss.Line)

		var codeSnippet string
		if iss.Code != "" {
			codeSnippet = fmt.Sprintf("  %s | %s", iss.Line, strings.TrimSpace(iss.Code))
		}

		description := iss.What
		if iss.Confidence > 0 {
			description += fmt.Sprintf("\nGosec confidence: %.0f%%", float64(iss.Confidence)*100)
		}

		findings = append(findings, report.Finding{
			ID:          fmt.Sprintf("IRON-GOSEC-%03d", i+1),
			Title:       fmt.Sprintf("[%s] %s", iss.RuleID, iss.What),
			Description: description,
			Severity:    sev,
			FilePath:    iss.File,
			LineNumber:  lineNum,
			CodeSnippet: codeSnippet,
			Step:        2,
			Category:    category,
			CWE:         cwe,
			CVSS:        report.SeverityToCVSS(sev),
			ToolOutput:  fmt.Sprintf("Rule: %s | Line: %s | Column: %s", iss.RuleID, iss.Line, iss.Col),
			References:  []string{fmt.Sprintf("https://github.com/securego/gosec#available-rules")},
		})
	}
	return findings
}

// mapGosecSeverity maps gosec Score to ironwall Severity.
func mapGosecSeverity(s issue.Score) report.Severity {
	switch s {
	case issue.High:
		return report.SevHigh
	case issue.Medium:
		return report.SevMedium
	case issue.Low:
		return report.SevLow
	default:
		return report.SevLow
	}
}

// mapGosecRuleToCategory maps gosec rule IDs to ironwall categories.
func mapGosecRuleToCategory(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "G1"): // G101-G112: Hardcoded credentials
		return "hardcoded-credentials"
	case strings.HasPrefix(ruleID, "G2"): // G201-G204: SQL injection
		return "sql-injection"
	case strings.HasPrefix(ruleID, "G3"): // G301-G307: File operations
		return "path-traversal"
	case strings.HasPrefix(ruleID, "G4"): // G401-G407: Crypto
		return "weak-crypto"
	case strings.HasPrefix(ruleID, "G5"): // G501-G505: Blocklisted imports
		return "insecure-configuration"
	case strings.HasPrefix(ruleID, "G6"): // G601-G602: Memory issues
		return "injection"
	case isTaintRule(ruleID): // G7xx: Taint analysis rules
		return "injection"
	default:
		return "static-analysis"
	}
}

// isTaintRule checks if a gosec rule ID is a taint analysis rule.
func isTaintRule(ruleID string) bool {
	taintPrefixes := []string{"G701", "G702", "G703", "G704", "G705", "G706", "G707", "G708", "G709", "G710"}
	for _, p := range taintPrefixes {
		if strings.HasPrefix(ruleID, p) {
			return true
		}
	}
	return false
}

