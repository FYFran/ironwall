package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/FYFran/ironwall/internal/ai"
	"github.com/FYFran/ironwall/internal/classify"
	"github.com/FYFran/ironwall/internal/report"
	"github.com/FYFran/ironwall/internal/scanner"
)

// Step2SAST runs static analysis with AI false-positive filtering.
// Uses embedded gosec (Go AST) for Go projects, falls back to semgrep for other languages.
type Step2SAST struct {
	aiClient *ai.Client
	verifier *classify.Verifier
}

func NewStep2SAST(aiClient *ai.Client) *Step2SAST {
	return &Step2SAST{
		aiClient: aiClient,
		verifier: classify.NewVerifier(aiClient),
	}
}

func (s *Step2SAST) Name() string        { return "Step 2: SAST Analysis" }
func (s *Step2SAST) Description() string { return "Static analysis via gosec (Go) / semgrep (multi-lang) with AI false-positive filtering" }
func (s *Step2SAST) IsSkippable() bool   { return true }
func (s *Step2SAST) RequiredTools() []string { return nil } // gosec is embedded, semgrep is optional fallback

func (s *Step2SAST) Run(ctx context.Context, target string) ([]report.Finding, error) {
	var allFindings []report.Finding

	// Detect project language
	isGoProject := hasGoFiles(target)

	if isGoProject {
		// Use embedded gosec — zero external dependency, fast
		gosecFindings, err := s.runGosec(ctx, target)
		if err == nil {
			allFindings = append(allFindings, gosecFindings...)
		}
		// On gosec error, try semgrep as fallback
		if err != nil && isToolAvailable("semgrep") {
			semgrepFindings, semgrepErr := s.runSemgrep(ctx, target)
			if semgrepErr == nil {
				allFindings = append(allFindings, semgrepFindings...)
			}
		}
	} else {
		// Non-Go project: use semgrep if available
		if isToolAvailable("semgrep") {
			semgrepFindings, err := s.runSemgrep(ctx, target)
			if err == nil {
				allFindings = append(allFindings, semgrepFindings...)
			}
		}
	}

	// Apply severity classification + test-file downgrade + AI verification
	for i := range allFindings {
		allFindings[i].Severity = classify.DowngradeForTestFile(allFindings[i].FilePath, allFindings[i].Severity)

		if allFindings[i].Severity >= report.SevMedium {
			at := s.verifier.Verify(ctx, &allFindings[i])
			allFindings[i].AttackScenario = at
			if !at.IsReal {
				allFindings[i].Severity = report.SevInfo
				allFindings[i].Description += "\n[AI Review: Likely false positive — attack scenario could not be verified.]"
			}
		}
	}

	return allFindings, nil
}

// runGosec runs the embedded gosec scanner on a Go project.
func (s *Step2SAST) runGosec(ctx context.Context, target string) ([]report.Finding, error) {
	result, err := scanner.RunGosec(target)
	if err != nil {
		return nil, fmt.Errorf("gosec: %w", err)
	}
	return result.ToFindings(target), nil
}

// runSemgrep runs semgrep as a fallback scanner.
func (s *Step2SAST) runSemgrep(ctx context.Context, target string) ([]report.Finding, error) {
	result, err := scanner.RunSemgrep(target, "auto")
	if err != nil {
		return nil, fmt.Errorf("semgrep: %w", err)
	}
	findings := result.ToFindings(target)

	// AI false-positive filtering
	if s.aiClient != nil && s.aiClient.Available() && len(findings) > 0 {
		filtered, err := s.filterWithAI(ctx, findings)
		if err == nil {
			findings = filtered
		}
	}
	return findings, nil
}

// filterWithAI uses AI to review findings and identify false positives.
func (s *Step2SAST) filterWithAI(ctx context.Context, findings []report.Finding) ([]report.Finding, error) {
	summary := "SAST findings to review:\n\n"
	for i, f := range findings {
		summary += fmt.Sprintf("[%d] %s | File: %s:%d | %s\n    Code: %s\n\n",
			i, f.Title, f.FilePath, f.LineNumber, f.Category,
			report.TruncateString(f.CodeSnippet, 120))
	}

	response, err := s.aiClient.Chat(ctx, ai.SystemPromptBase, ai.PromptSASTReview+"\n\n"+summary)
	if err != nil {
		return nil, err
	}

	aiLower := strings.ToLower(response)
	for i := range findings {
		idPattern := fmt.Sprintf("[%d]", i)
		if strings.Contains(aiLower, idPattern+" false") ||
			strings.Contains(aiLower, idPattern+" not real") ||
			strings.Contains(aiLower, idPattern+" safe") {
			findings[i].Severity = report.SevInfo
			findings[i].AIConfidence = 0.2
			findings[i].Description += "\n[AI Review: Flagged as likely false positive.]"
		}
	}

	return findings, nil
}

// hasGoFiles checks if the target directory contains any .go files (not in vendor/testdata).
func hasGoFiles(target string) bool {
	var found bool
	_ = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if found {
			return filepath.SkipAll
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == ".git" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" {
			found = true
		}
		return nil
	})
	return found
}
