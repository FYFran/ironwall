package pipeline

import (
	"context"
	"fmt"

	"github.com/FYFran/ironwall/internal/report"
	"github.com/FYFran/ironwall/internal/scanner"
)

// Step1Gitleaks runs gitleaks secret scanning on the target.
type Step1Gitleaks struct{}

func (s *Step1Gitleaks) Name() string { return "Step 1: Secret Scanning" }
func (s *Step1Gitleaks) Description() string {
	return "Scan for hardcoded secrets and credentials using gitleaks"
}
func (s *Step1Gitleaks) IsSkippable() bool       { return false } // TIER1: cannot skip
func (s *Step1Gitleaks) RequiredTools() []string { return []string{"gitleaks"} }

func (s *Step1Gitleaks) Run(ctx context.Context, target string) ([]report.Finding, error) {
	result, err := scanner.RunGitleaks(target)
	if err != nil {
		return nil, fmt.Errorf("gitleaks scan failed: %w", err)
	}

	findings := result.ToFindings(target)
	return findings, nil
}
