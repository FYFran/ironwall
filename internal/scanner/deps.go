package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// DepsResult holds dependency check results for a single ecosystem.
type DepsResult struct {
	Findings  []report.Finding
	Ecosystem string
}

// RunGoVulnCheck runs govulncheck on a Go project and returns findings.
func RunGoVulnCheck(target string) (*DepsResult, error) {
	// govulncheck ./... from target directory
	cmd := exec.Command("go", "vulncheck", "-json", "./...")
	cmd.Dir = target
	out, err := cmd.CombinedOutput()
	if err != nil {
		// govulncheck returns non-zero when vulns are found
		raw := strings.TrimSpace(string(out))
		if raw == "" || !strings.HasPrefix(raw, "{") {
			return nil, fmt.Errorf("govulncheck failed: %w\n%s", err, string(out))
		}
	}

	return parseGoVulnOutput(out, "go")
}

// RunNpmAudit runs npm audit on a Node.js project.
func RunNpmAudit(target string) (*DepsResult, error) {
	cmd := exec.Command("npm", "audit", "--json")
	cmd.Dir = target
	out, err := cmd.CombinedOutput()
	if err != nil {
		raw := strings.TrimSpace(string(out))
		if raw == "" {
			return &DepsResult{Ecosystem: "npm"}, nil
		}
		if !strings.HasPrefix(raw, "{") {
			return nil, fmt.Errorf("npm audit failed: %w\n%s", err, string(out))
		}
	}
	return parseNpmAuditOutput(out)
}

// RunPipAudit runs pip-audit on a Python project.
func RunPipAudit(target string) (*DepsResult, error) {
	cmd := exec.Command("pip-audit", "--format", "json")
	cmd.Dir = target
	out, err := cmd.CombinedOutput()
	// pip-audit returns exit 1 when vulns found
	raw := strings.TrimSpace(string(out))
	if err != nil && raw == "" {
		return &DepsResult{Ecosystem: "pip"}, nil
	}
	return parsePipAuditOutput(out)
}

// DetectEcosystem checks which dependency files exist in the target.
func DetectEcosystem(target string) []string {
	var ecosystems []string
	if fileExists(target + "/go.mod") {
		ecosystems = append(ecosystems, "go")
	}
	if fileExists(target + "/package.json") {
		ecosystems = append(ecosystems, "npm")
	}
	if fileExists(target+"/requirements.txt") || fileExists(target+"/pyproject.toml") {
		ecosystems = append(ecosystems, "pip")
	}
	return ecosystems
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// parseGoVulnOutput parses govulncheck JSON output.
func parseGoVulnOutput(raw []byte, eco string) (*DepsResult, error) {
	var vulnData struct {
		Vulns []struct {
			ID       string   `json:"id"`
			Details  string   `json:"details"`
			Aliases  []string `json:"aliases"`
			Symbols  []string `json:"symbols"`
			ModPath  string   `json:"mod_path"`
			Fixed    string   `json:"fixed_version"`
			Severity string   `json:"severity"`
		} `json:"vulns"`
	}

	if err := json.Unmarshal(raw, &vulnData); err != nil {
		// Try array format
		var arr []struct {
			ID       string `json:"id"`
			Details  string `json:"details"`
			Severity string `json:"severity"`
		}
		if err2 := json.Unmarshal(raw, &arr); err2 != nil {
			return nil, fmt.Errorf("parse govulncheck: %w", err)
		}
		for _, v := range arr {
			vulnData.Vulns = append(vulnData.Vulns, struct {
				ID       string   `json:"id"`
				Details  string   `json:"details"`
				Aliases  []string `json:"aliases"`
				Symbols  []string `json:"symbols"`
				ModPath  string   `json:"mod_path"`
				Fixed    string   `json:"fixed_version"`
				Severity string   `json:"severity"`
			}{ID: v.ID, Details: v.Details, Severity: v.Severity})
		}
	}

	result := &DepsResult{Ecosystem: eco}
	for _, v := range vulnData.Vulns {
		sev := mapVulnSeverity(v.Severity)
		result.Findings = append(result.Findings, report.Finding{
			Title:         fmt.Sprintf("%s: %s", v.ID, report.TruncateString(v.Details, 100)),
			Description:   fmt.Sprintf("Known vulnerability %s in %s. %s", v.ID, v.ModPath, v.Details),
			Severity:      sev,
			FilePath:      "go.mod",
			LineNumber:    0,
			Step:          5,
			Category:      "known-cve",
			CWE:           "CWE-937",
			CVSS:          report.SeverityToCVSS(sev),
			FixSuggestion: fmt.Sprintf("Upgrade to %s or later", v.Fixed),
			References:    []string{fmt.Sprintf("https://pkg.go.dev/vuln/%s", v.ID)},
		})
	}
	return result, nil
}

// parseNpmAuditOutput parses npm audit JSON.
func parseNpmAuditOutput(raw []byte) (*DepsResult, error) {
	var auditData struct {
		Vulnerabilities map[string]struct {
			Name         string        `json:"name"`
			Severity     string        `json:"severity"`
			Range        string        `json:"range"`
			Via          []interface{} `json:"via"`
			Effects      []string      `json:"effects"`
			FixAvailable interface{}   `json:"fix_available"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(raw, &auditData); err != nil {
		return nil, fmt.Errorf("parse npm audit: %w", err)
	}

	result := &DepsResult{Ecosystem: "npm"}
	for key, v := range auditData.Vulnerabilities {
		sev := mapVulnSeverity(v.Severity)
		result.Findings = append(result.Findings, report.Finding{
			Title:       fmt.Sprintf("npm: %s — %s", v.Name, v.Severity),
			Description: fmt.Sprintf("npm audit found vulnerability in %s: severity %s, affected range %s", v.Name, v.Severity, v.Range),
			Severity:    sev,
			FilePath:    "package.json",
			Step:        5,
			Category:    "known-cve",
			CWE:         "CWE-937",
			CVSS:        report.SeverityToCVSS(sev),
			References:  []string{fmt.Sprintf("https://www.npmjs.com/advisories?search=%s", key)},
		})
	}
	return result, nil
}

// parsePipAuditOutput parses pip-audit JSON.
func parsePipAuditOutput(raw []byte) (*DepsResult, error) {
	var auditData []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vulns   []struct {
			ID          string   `json:"id"`
			Description string   `json:"description"`
			FixVersions []string `json:"fix_versions"`
		} `json:"vulns"`
	}

	if err := json.Unmarshal(raw, &auditData); err != nil {
		return nil, fmt.Errorf("parse pip audit: %w", err)
	}

	result := &DepsResult{Ecosystem: "pip"}
	for _, pkg := range auditData {
		for _, v := range pkg.Vulns {
			fix := "none"
			if len(v.FixVersions) > 0 {
				fix = v.FixVersions[0]
			}
			result.Findings = append(result.Findings, report.Finding{
				Title:       fmt.Sprintf("pip: %s — %s", pkg.Name, v.ID),
				Description: fmt.Sprintf("pip-audit found %s in %s %s: %s. Fix: %s", v.ID, pkg.Name, pkg.Version, v.Description, fix),
				Severity:    report.SevHigh,
				FilePath:    "requirements.txt",
				Step:        5,
				Category:    "known-cve",
				CWE:         "CWE-937",
				CVSS:        7.5,
				References:  []string{fmt.Sprintf("https://osv.dev/vulnerability/%s", v.ID)},
			})
		}
	}
	return result, nil
}

func mapVulnSeverity(s string) report.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return report.SevCritical
	case "high":
		return report.SevHigh
	case "moderate", "medium":
		return report.SevMedium
	case "low":
		return report.SevLow
	default:
		return report.SevMedium
	}
}
