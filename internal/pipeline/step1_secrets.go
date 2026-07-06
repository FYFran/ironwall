package pipeline

import (
	"context"
	"fmt"

	"github.com/FYFran/ironwall/internal/report"
	"github.com/FYFran/ironwall/internal/scanner"
)

// Step1Secrets runs secret scanning using Betterleaks (preferred) or gitleaks (fallback).
// Betterleaks: BPE tokenization, 98.6% recall, MIT license, drop-in gitleaks replacement.
type Step1Secrets struct{}

func (s *Step1Secrets) Name() string { return "Step 1: Secret Scanning" }
func (s *Step1Secrets) Description() string {
	return "Scan for hardcoded secrets and credentials using Betterleaks (BPE tokenization, 98.6% recall)"
}
func (s *Step1Secrets) IsSkippable() bool       { return false } // TIER1: cannot skip
func (s *Step1Secrets) RequiredTools() []string { return nil }   // Auto-detects betterleaks or fallback gitleaks

func (s *Step1Secrets) Run(ctx context.Context, target string) ([]report.Finding, error) {
	result, err := scanner.RunBetterleaks(target)
	if err != nil {
		return nil, fmt.Errorf("secret scan failed: %w", err)
	}

	findings := result.ToFindings(target)
	return findings, nil
}
