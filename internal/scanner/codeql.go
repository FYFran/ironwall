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

// CodeQLResult holds the results of a CodeQL analysis.
type CodeQLResult struct {
	Findings []CodeQLFinding
}

// CodeQLFinding is a single SARIF result from CodeQL.
type CodeQLFinding struct {
	RuleID      string `json:"ruleId"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	FilePath    string `json:"filePath"`
	StartLine   int    `json:"startLine"`
	Description string `json:"description"`
	CWE         string `json:"cwe"`
}

// RunCodeQL runs CodeQL analysis on the target directory.
// CodeQL provides deep semantic analysis (data flow, taint tracking).
// F1 score 74.4% vs Semgrep 69.4% on OWASP Benchmark.
func RunCodeQL(target string) (*CodeQLResult, error) {
	if _, err := exec.LookPath("codeql"); err != nil {
		return nil, fmt.Errorf("codeql CLI not installed (https://github.com/github/codeql): %w", err)
	}

	// Detect languages in the target
	langs := detectLanguages(target)
	if len(langs) == 0 {
		return nil, fmt.Errorf("no supported languages detected for CodeQL analysis")
	}

	// Create temp directory for CodeQL database
	dbDir, err := os.MkdirTemp("", "ironwall-codeql-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dbDir)

	// Step 1: Create CodeQL database
	createArgs := append([]string{"database", "create", dbDir, "--source-root", target}, langs...)
	createArgs = append(createArgs, "--overwrite")
	cmd := exec.Command("codeql", createArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("codeql database create failed: %w\n%s", err, string(out))
	}

	// Step 2: Analyze with security queries
	sarifFile := filepath.Join(os.TempDir(), "ironwall-codeql-result.sarif")
	defer os.Remove(sarifFile)

	analyzeArgs := []string{
		"database", "analyze", dbDir,
		"--format", "sarif-latest",
		"--output", sarifFile,
		"--", "security-extended",
	}
	cmd = exec.Command("codeql", analyzeArgs...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		// CodeQL may return non-zero on findings — parse SARIF anyway
		if _, statErr := os.Stat(sarifFile); statErr != nil {
			return nil, fmt.Errorf("codeql analyze failed: %w\n%s", err, string(out))
		}
	}

	// Parse SARIF output
	return parseCodeQLSARIF(sarifFile)
}

// parseCodeQLSARIF parses a SARIF file from CodeQL into ironwall findings.
func parseCodeQLSARIF(path string) (*CodeQLResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SARIF: %w", err)
	}

	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
			Tool struct {
				Driver struct {
					Rules []struct {
						ID                      string `json:"id"`
						ShortDescription        struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						FullDescription         struct {
							Text string `json:"text"`
						} `json:"fullDescription"`
						DefaultSeverity         string   `json:"defaultSeverity"`
						Tags                    []string `json:"tags"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, fmt.Errorf("parse SARIF JSON: %w", err)
	}

	// Build rule lookup
	ruleMap := make(map[string]struct {
		Description string
		Severity    string
		Tags        []string
	})
	for _, run := range sarif.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			ruleMap[rule.ID] = struct {
				Description string
				Severity    string
				Tags        []string
			}{
				Description: rule.ShortDescription.Text,
				Severity:    rule.DefaultSeverity,
				Tags:        rule.Tags,
			}
		}
	}

	result := &CodeQLResult{}
	for _, run := range sarif.Runs {
		for _, r := range run.Results {
			var filePath string
			var startLine int
			if len(r.Locations) > 0 {
				filePath = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
				startLine = r.Locations[0].PhysicalLocation.Region.StartLine
			}

			rule := ruleMap[r.RuleID]
			cwe := extractCWEFromTags(rule.Tags)

			result.Findings = append(result.Findings, CodeQLFinding{
				RuleID:      r.RuleID,
				Message:     r.Message.Text,
				Severity:    r.Level,
				FilePath:    filePath,
				StartLine:   startLine,
				Description: rule.Description,
				CWE:         cwe,
			})
		}
	}

	return result, nil
}

// ToFindings converts CodeQL findings to ironwall Finding structs.
func (r *CodeQLResult) ToFindings() []report.Finding {
	if r == nil || len(r.Findings) == 0 {
		return nil
	}

	var findings []report.Finding
	for i, f := range r.Findings {
		sev := mapCodeQLSeverity(f.Severity)
		findings = append(findings, report.Finding{
			ID:          fmt.Sprintf("IRON-CODEQL-%03d", i+1),
			Title:       fmt.Sprintf("[%s] %s", f.RuleID, f.Message),
			Description: f.Description,
			Severity:    sev,
			FilePath:    f.FilePath,
			LineNumber:  f.StartLine,
			Step:        2,
			Category:    f.RuleID,
			CWE:         f.CWE,
			CVSS:        report.SeverityToCVSS(sev),
			ToolOutput:  fmt.Sprintf("CodeQL rule: %s", f.RuleID),
			References:  []string{fmt.Sprintf("https://codeql.github.com/codeql-query-help/go/%s", f.RuleID)},
		})
	}
	return findings
}

func mapCodeQLSeverity(s string) report.Severity {
	switch strings.ToLower(s) {
	case "error":
		return report.SevCritical
	case "warning":
		return report.SevHigh
	case "note":
		return report.SevMedium
	default:
		return report.SevLow
	}
}

func extractCWEFromTags(tags []string) string {
	for _, tag := range tags {
		if strings.HasPrefix(tag, "CWE-") {
			return tag
		}
		if strings.HasPrefix(tag, "external/cwe/cwe-") {
			return strings.ToUpper(strings.TrimPrefix(tag, "external/cwe/"))
		}
	}
	return ""
}

// detectLanguages detects programming languages in the target for CodeQL.
func detectLanguages(target string) []string {
	var langs []string

	hasExt := func(ext string) bool {
		var found bool
		_ = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if err != nil || found {
				return nil
			}
			if info.IsDir() {
				base := filepath.Base(path)
				if base == ".git" || base == "node_modules" || base == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) == ext {
				found = true
			}
			return nil
		})
		return found
	}

	langMap := map[string]string{
		".go":   "go",
		".py":   "python",
		".js":   "javascript",
		".ts":   "javascript",
		".java": "java",
		".rb":   "ruby",
		".cs":   "csharp",
		".cpp":  "cpp",
		".c":    "cpp",
	}

	for ext, lang := range langMap {
		if hasExt(ext) {
			langs = append(langs, "--language="+lang)
		}
	}

	return langs
}
