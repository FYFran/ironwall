package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// SemgrepFinding is the JSON structure semgrep outputs per match.
type SemgrepFinding struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			CWE      []string `json:"cwe"`
			OWASP    []string `json:"owasp"`
			Category string `json:"category"`
		} `json:"metadata"`
		Lines string `json:"lines"`
		Fix   string `json:"fix"`
	} `json:"extra"`
}

// SemgrepResult wraps the output of `semgrep scan --json`.
type SemgrepResult struct {
	Results []SemgrepFinding `json:"results"`
	Errors  []interface{}    `json:"errors"`
	RawJSON string
}

// RunSemgrep runs semgrep scan on the given target with specified rules.
// rules can be "" for auto-detection, or a semgrep rule string like "p/python".
func RunSemgrep(target string, rules string) (*SemgrepResult, error) {
	args := []string{
		"scan",
		"--json",
		"--quiet",
		"--no-git-ignore",
	}
	if rules != "" {
		args = append(args, "--config", rules)
	} else {
		args = append(args, "--config", "auto")
	}
	args = append(args, target)

	cmd := exec.Command("semgrep", args...)
	out, err := cmd.CombinedOutput()
	// semgrep returns exit code 1 when findings exist, which is normal.
	if err != nil {
		raw := strings.TrimSpace(string(out))
		if raw == "" || (!strings.HasPrefix(raw, "{") && !strings.HasPrefix(raw, "[")) {
			return nil, fmt.Errorf("semgrep failed: %w\n%s", err, string(out))
		}
		return parseSemgrepOutput(out)
	}
	return parseSemgrepOutput(out)
}

// parseSemgrepOutput parses semgrep JSON output.
func parseSemgrepOutput(raw []byte) (*SemgrepResult, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "{}" {
		return &SemgrepResult{}, nil
	}

	var result SemgrepResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep JSON: %w\nraw: %s", err, s[:min(len(s), 200)])
	}
	result.RawJSON = s
	return &result, nil
}

// ToFindings converts semgrep findings to ironwall Finding structs.
func (r *SemgrepResult) ToFindings(target string) []report.Finding {
	var findings []report.Finding
	for i, f := range r.Results {
		sev := mapSemgrepSeverity(f.Extra.Severity)
		cwe := ""
		if len(f.Extra.Metadata.CWE) > 0 {
			cwe = f.Extra.Metadata.CWE[0]
		}
		category := f.Extra.Metadata.Category
		if category == "" {
			category = f.CheckID
		}

		var codeSnippet string
		if f.Extra.Lines != "" {
			codeSnippet = fmt.Sprintf("  %d | %s", f.Start.Line, strings.TrimSpace(f.Extra.Lines))
		}

		findings = append(findings, report.Finding{
			ID:            fmt.Sprintf("IRON-SEMGREP-%03d", i+1),
			Title:         fmt.Sprintf("%s: %s", f.CheckID, f.Extra.Message),
			Description:   fmt.Sprintf("Semgrep rule %s detected: %s", f.CheckID, f.Extra.Message),
			Severity:      sev,
			FilePath:      f.Path,
			LineNumber:    f.Start.Line,
			CodeSnippet:   codeSnippet,
			Step:          2,
			Category:      category,
			CWE:           cwe,
			CVSS:          report.SeverityToCVSS(sev),
			ToolOutput:    fmt.Sprintf("Rule: %s | Severity: %s | OWASP: %v", f.CheckID, f.Extra.Severity, f.Extra.Metadata.OWASP),
			FixSuggestion: f.Extra.Fix,
			References:    []string{"https://semgrep.dev/r/" + f.CheckID},
		})
	}
	return findings
}

// mapSemgrepSeverity maps semgrep severity strings to ironwall Severity.
func mapSemgrepSeverity(s string) report.Severity {
	switch strings.ToUpper(s) {
	case "ERROR", "CRITICAL":
		return report.SevCritical
	case "WARNING":
		return report.SevHigh
	case "INFO":
		return report.SevMedium
	default:
		return report.SevLow
	}
}
