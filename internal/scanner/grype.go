package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// GrypeResult holds CVE scanning results from grype.
type GrypeResult struct {
	Matches    []GrypeMatch `json:"matches"`
	SourceInfo interface{}  `json:"source"`
}

// GrypeMatch is a single CVE match from grype.
type GrypeMatch struct {
	Vulnerability struct {
		ID          string   `json:"id"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		URLs        []string `json:"urls"`
		CVSS        []struct {
			Version string  `json:"version"`
			Score   float64 `json:"metrics.baseScore"`
		} `json:"cvss"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"artifact"`
}

// RunGrype runs grype vulnerability scanning on the target.
// Can accept an SBOM from RunSyft for unified scanning.
func RunGrype(target string) (*GrypeResult, error) {
	if _, err := exec.LookPath("grype"); err != nil {
		return nil, fmt.Errorf("grype not installed (https://github.com/anchore/grype): %w", err)
	}

	args := []string{
		"dir:" + target,
		"-o", "json",
		"--quiet",
		"--fail-on", "", // Don't fail on findings
	}
	cmd := exec.Command("grype", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		raw := strings.TrimSpace(string(out))
		if raw == "" {
			return nil, fmt.Errorf("grype failed: %w", err)
		}
		if !strings.HasPrefix(raw, "{") {
			return nil, fmt.Errorf("grype failed: %w\n%s", err, string(out))
		}
	}

	var result GrypeResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse grype output: %w", err)
	}

	return &result, nil
}

// ToFindings converts grype CVE matches to ironwall Finding structs.
func (r *GrypeResult) ToFindings() []report.Finding {
	if r == nil || len(r.Matches) == 0 {
		return nil
	}

	var findings []report.Finding
	for i, m := range r.Matches {
		sev := mapGrypeSeverity(m.Vulnerability.Severity)
		cvss := extractCVSS(m.Vulnerability.CVSS)
		if cvss == 0 {
			cvss = report.SeverityToCVSS(sev)
		}

		findings = append(findings, report.Finding{
			ID:          fmt.Sprintf("IRON-CVE-%03d", i+1),
			Title:       fmt.Sprintf("[%s] %s — %s@%s", m.Vulnerability.Severity, m.Vulnerability.ID, m.Artifact.Name, m.Artifact.Version),
			Description: m.Vulnerability.Description,
			Severity:    sev,
			FilePath:    m.Artifact.Name,
			Step:        5,
			Category:    "known-cve",
			CWE:         "CWE-937",
			CVSS:        cvss,
			FixSuggestion: "Check for patched version or workaround.",
			References:  m.Vulnerability.URLs,
		})
	}
	return findings
}

func mapGrypeSeverity(s string) report.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return report.SevCritical
	case "HIGH":
		return report.SevHigh
	case "MEDIUM":
		return report.SevMedium
	case "LOW":
		return report.SevLow
	default:
		return report.SevInfo
	}
}

func extractCVSS(cvssList []struct {
	Version string  `json:"version"`
	Score   float64 `json:"metrics.baseScore"`
}) float64 {
	for _, c := range cvssList {
		if strings.HasPrefix(c.Version, "3") {
			return c.Score
		}
	}
	if len(cvssList) > 0 {
		return cvssList[0].Score
	}
	return 0
}
