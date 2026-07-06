package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// KICSResult holds the results of a KICS IaC scan.
// KICS: 2400+ queries, 22+ IaC formats, Apache 2.0 license.
type KICSResult struct {
	Findings []KICSFinding
}

// KICSFinding is a single KICS query result.
type KICSFinding struct {
	QueryID      string `json:"query_id"`
	QueryName    string `json:"query_name"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	Description  string `json:"description"`
	FileName     string `json:"file_name"`
	Line         int    `json:"line"`
	Platform     string `json:"platform"`
	CWE          string `json:"cwe"`
	Remediation  string `json:"remediation"`
}

// RunKICS runs KICS on the target directory for IaC security analysis.
// Covers: Terraform, CloudFormation, K8s, Docker, Helm, Ansible, Pulumi, ARM, Bicep, etc.
func RunKICS(target string) (*KICSResult, error) {
	if _, err := exec.LookPath("kics"); err != nil {
		return nil, fmt.Errorf("kics not installed (https://github.com/Checkmarx/kics): %w", err)
	}

	args := []string{
		"scan",
		"-p", target,
		"--no-color",
		"--silent",
		"--report-formats", "json",
		"--output-path", filepath.Join(target, ".ironwall-kics"),
		"--ignore-on-exit", "results", // Don't fail on findings
	}
	cmd := exec.Command("kics", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		raw := strings.TrimSpace(string(out))
		// KICS returns non-zero on findings — that's expected
		if raw == "" {
			return &KICSResult{}, nil
		}
	}

	// KICS writes JSON to a file, read it
	// Try multiple possible output paths
	jsonPaths := []string{
		filepath.Join(target, ".ironwall-kics", "results.json"),
		filepath.Join(target, ".ironwall-kics"),
	}
	for _, p := range jsonPaths {
		data, err := readFile(p)
		if err == nil {
			result, err := parseKICSParseResult(data)
			if err == nil {
				return result, nil
			}
		}
	}

	return &KICSResult{}, nil
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func parseKICSParseResult(data []byte) (*KICSResult, error) {
	var rawResults struct {
		Queries []KICSFinding `json:"queries"`
	}
	// KICS JSON format: { "queries": [...] } or direct array
	if err := json.Unmarshal(data, &rawResults); err != nil {
		// Try direct array
		var arr []KICSFinding
		if err2 := json.Unmarshal(data, &arr); err2 != nil {
			return nil, fmt.Errorf("parse kics: %w / %w", err, err2)
		}
		return &KICSResult{Findings: arr}, nil
	}
	return &KICSResult{Findings: rawResults.Queries}, nil
}

// ToFindings converts KICS findings to ironwall Finding structs.
func (r *KICSResult) ToFindings() []report.Finding {
	if r == nil || len(r.Findings) == 0 {
		return nil
	}

	var findings []report.Finding
	for i, f := range r.Findings {
		sev := mapKICSSeverity(f.Severity)
		findings = append(findings, report.Finding{
			ID:            fmt.Sprintf("IRON-KICS-%03d", i+1),
			Title:         fmt.Sprintf("[%s] %s: %s", f.Platform, f.QueryName, f.Description),
			Description:   fmt.Sprintf("KICS query %s detected in %s: %s", f.QueryID, f.FileName, f.Description),
			Severity:      sev,
			FilePath:      f.FileName,
			LineNumber:    f.Line,
			Step:          6,
			Category:      f.Category,
			CWE:           f.CWE,
			CVSS:          report.SeverityToCVSS(sev),
			FixSuggestion: f.Remediation,
			ToolOutput:    fmt.Sprintf("KICS Query: %s | Platform: %s", f.QueryID, f.Platform),
			References:    []string{fmt.Sprintf("https://docs.kics.io/queries/%s", strings.ToLower(f.QueryID))},
		})
	}
	return findings
}

func mapKICSSeverity(s string) report.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return report.SevCritical
	case "HIGH":
		return report.SevHigh
	case "MEDIUM":
		return report.SevMedium
	case "LOW":
		return report.SevLow
	case "INFO":
		return report.SevInfo
	default:
		return report.SevMedium
	}
}
