package pipeline

import (
	"context"
	"os"

	"github.com/FYFran/ironwall/internal/report"
	"github.com/FYFran/ironwall/internal/scanner"
)

// Step5Deps runs dependency vulnerability checking.
type Step5Deps struct{}

func (s *Step5Deps) Name() string { return "Step 5: Dependency CVE" }
func (s *Step5Deps) Description() string {
	return "Check dependencies for known vulnerabilities (govulncheck, npm audit, pip-audit)"
}
func (s *Step5Deps) IsSkippable() bool       { return true }
func (s *Step5Deps) RequiredTools() []string { return nil } // Tools checked per-ecosystem

func (s *Step5Deps) Run(ctx context.Context, target string) ([]report.Finding, error) {
	ecosystems := scanner.DetectEcosystem(target)
	if len(ecosystems) == 0 {
		return nil, nil
	}

	var allFindings []report.Finding

	for _, eco := range ecosystems {
		switch eco {
		case "go":
			result, err := scanner.RunGoVulnCheck(target)
			if err != nil {
				// Tool not available is not fatal
				continue
			}
			allFindings = append(allFindings, result.Findings...)

		case "npm":
			result, err := scanner.RunNpmAudit(target)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, result.Findings...)

		case "pip":
			result, err := scanner.RunPipAudit(target)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, result.Findings...)
		}
	}

	// Assign step numbers
	for i := range allFindings {
		allFindings[i].Step = 5
	}

	return allFindings, nil
}

// fileExists checks if a file exists relative to a target directory.
func fileExists(target, name string) bool {
	_, err := os.Stat(target + "/" + name)
	return err == nil
}
