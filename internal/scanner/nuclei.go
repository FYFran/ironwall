package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// NucleiFinding represents a single nuclei template match.
type NucleiFinding struct {
	TemplateID  string `json:"template-id"`
	Info        struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	MatchedAt   string `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	IP          string `json:"ip"`
	Host        string `json:"host"`
}

// NucleiResult wraps nuclei JSON output.
type NucleiResult struct {
	Findings []NucleiFinding
}

// RunNuclei runs nuclei against configuration files in the target directory.
// Nuclei is used to detect misconfigurations in Docker, nginx, Kubernetes, etc.
func RunNuclei(target string) (*NucleiResult, error) {
	args := []string{
		"-silent",
		"-json",
		"-tags", "config,misconfiguration,exposure",
		"-target", target,
	}
	cmd := exec.Command("nuclei", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		raw := strings.TrimSpace(string(out))
		// nuclei returns non-zero on findings — that's expected
		if raw == "" {
			return &NucleiResult{}, nil
		}
		if !strings.HasPrefix(raw, "{") {
			return nil, fmt.Errorf("nuclei failed: %w\n%s", err, string(out))
		}
	}

	return parseNucleiOutput(out)
}

// parseNucleiOutput parses newline-delimited JSON from nuclei.
func parseNucleiOutput(raw []byte) (*NucleiResult, error) {
	result := &NucleiResult{}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var finding NucleiFinding
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue // Skip malformed lines
		}
		result.Findings = append(result.Findings, finding)
	}
	return result, nil
}

// ToFindings converts nuclei findings to ironwall Finding structs.
func (r *NucleiResult) ToFindings() []report.Finding {
	var findings []report.Finding
	for i, f := range r.Findings {
		sev := mapNucleiSeverity(f.Info.Severity)
		findings = append(findings, report.Finding{
			ID:          fmt.Sprintf("IRON-NUCLEI-%03d", i+1),
			Title:       fmt.Sprintf("[%s] %s", f.TemplateID, f.Info.Name),
			Description: f.Info.Description,
			Severity:    sev,
			FilePath:    f.MatchedAt,
			LineNumber:  0,
			Step:        6,
			Category:    mapNucleiTags(f.Info.Tags),
			CWE:         "",
			CVSS:        report.SeverityToCVSS(sev),
			ToolOutput:  fmt.Sprintf("Template: %s | Host: %s", f.TemplateID, f.Host),
			References:  []string{fmt.Sprintf("https://templates.nuclei.sh/%s", f.TemplateID)},
		})
	}
	return findings
}

func mapNucleiSeverity(s string) report.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return report.SevCritical
	case "high":
		return report.SevHigh
	case "medium":
		return report.SevMedium
	case "low":
		return report.SevLow
	default:
		return report.SevInfo
	}
}

func mapNucleiTags(tags []string) string {
	for _, tag := range tags {
		switch strings.ToLower(tag) {
		case "misconfiguration":
			return "insecure-configuration"
		case "exposure":
			return "information-disclosure"
		case "cve":
			return "known-cve"
		}
	}
	return "misconfiguration"
}
