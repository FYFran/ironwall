package pipeline

import (
	"context"
	"os"

	"github.com/FYFran/ironwall/internal/report"
	"github.com/FYFran/ironwall/internal/scanner"
)

// Step5Deps runs dependency vulnerability checking.
// Uses ecosystem-specific tools (govulncheck, npm, pip) + unified scanner (grype).
type Step5Deps struct{}

func (s *Step5Deps) Name() string { return "Step 5: Dependency CVE" }
func (s *Step5Deps) Description() string {
	return "Check dependencies for known vulnerabilities (govulncheck, npm audit, pip-audit, grype)"
}
func (s *Step5Deps) IsSkippable() bool       { return true }
func (s *Step5Deps) RequiredTools() []string { return nil }

func (s *Step5Deps) Run(ctx context.Context, target string) ([]report.Finding, error) {
	var allFindings []report.Finding

	// Ecosystem-specific scanners (govulncheck, npm audit, pip-audit)
	ecosystems := scanner.DetectEcosystem(target)
	for _, eco := range ecosystems {
		switch eco {
		case "go":
			result, err := scanner.RunGoVulnCheck(target)
			if err == nil {
				allFindings = append(allFindings, result.Findings...)
			}
		case "npm":
			result, err := scanner.RunNpmAudit(target)
			if err == nil {
				allFindings = append(allFindings, result.Findings...)
			}
		case "pip":
			result, err := scanner.RunPipAudit(target)
			if err == nil {
				allFindings = append(allFindings, result.Findings...)
			}
		}
	}

	// Unified vulnerability scanner via Grype (optional, if installed)
	// Grype covers ALL ecosystems in one tool (Go, npm, pip, RPM, DEB, Java, etc.)
	grypeResult, err := scanner.RunGrype(target)
	if err == nil {
		allFindings = append(allFindings, grypeResult.ToFindings()...)
	}

	// SBOM generation via Syft (optional, if installed)
	syftResult, err := scanner.RunSyft(target)
	if err == nil {
		allFindings = append(allFindings, syftResult.ToFindings()...)
	}

	// Assign step numbers
	for i := range allFindings {
		if allFindings[i].Step == 0 {
			allFindings[i].Step = 5
		}
	}

	return allFindings, nil
}

// fileExistsDeprecated kept for backward compat — use scanner.DetectEcosystem instead.
func fileExistsDeprecated(target, name string) bool {
	_, err := os.Stat(target + "/" + name)
	return err == nil
}
