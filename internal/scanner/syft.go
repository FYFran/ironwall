package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// SyftResult holds SBOM generation results.
type SyftResult struct {
	Format    string // "cyclonedx-json" or "spdx-json"
	SBOM      string // Raw SBOM JSON
	ComponentCount int
}

// RunSyft generates an SBOM from the target directory using syft CLI.
// Returns CycloneDX JSON format suitable for grype scanning.
func RunSyft(target string) (*SyftResult, error) {
	if _, err := exec.LookPath("syft"); err != nil {
		return nil, fmt.Errorf("syft not installed (https://github.com/anchore/syft): %w", err)
	}

	args := []string{
		"scan", target,
		"-o", "cyclonedx-json",
		"--quiet",
	}
	cmd := exec.Command("syft", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		raw := strings.TrimSpace(string(out))
		if raw == "" {
			return nil, fmt.Errorf("syft failed: %w", err)
		}
		// Syft may still produce output on non-zero exit
		if !strings.HasPrefix(raw, "{") {
			return nil, fmt.Errorf("syft failed: %w\n%s", err, string(out))
		}
	}

	result := &SyftResult{
		Format: "cyclonedx-json",
		SBOM:   strings.TrimSpace(string(out)),
	}

	// Count components
	var sbom struct {
		Components []interface{} `json:"components"`
	}
	if json.Unmarshal([]byte(result.SBOM), &sbom) == nil {
		result.ComponentCount = len(sbom.Components)
	}

	return result, nil
}

// ToFindings converts syft SBOM data to ironwall findings.
// This primarily enriches the report with SBOM metadata.
func (r *SyftResult) ToFindings() []report.Finding {
	if r == nil || r.SBOM == "" {
		return nil
	}

	return []report.Finding{
		{
			Title:       fmt.Sprintf("SBOM generated: %d components detected", r.ComponentCount),
			Description: fmt.Sprintf("Software Bill of Materials (SBOM) generated in CycloneDX format. %d components inventoried for vulnerability tracking.", r.ComponentCount),
			Severity:    report.SevInfo,
			FilePath:    "sbom.cdx.json",
			Step:        8,
			Category:    "sbom",
			CWE:         "",
			CVSS:        0,
			References:  []string{"https://github.com/anchore/syft"},
		},
	}
}
