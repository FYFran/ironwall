package pipeline

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/FYFran/ironwall/internal/ai"
	"github.com/FYFran/ironwall/internal/classify"
	"github.com/FYFran/ironwall/internal/report"
	"github.com/FYFran/ironwall/internal/scanner"
)

// Step2SAST runs static analysis with AI false-positive filtering.
// Uses embedded gosec (Go AST) for Go projects, falls back to semgrep for other languages.
type Step2SAST struct {
	engine   *ai.Engine
	verifier *classify.Verifier
}

func NewStep2SAST(engine *ai.Engine) *Step2SAST {
	return &Step2SAST{
		engine:   engine,
		verifier: classify.NewVerifier(engine),
	}
}

func (s *Step2SAST) Name() string        { return "Step 2: SAST Analysis" }
func (s *Step2SAST) Description() string { return "Static analysis via gosec (Go) / semgrep (multi-lang) with AI false-positive filtering" }
func (s *Step2SAST) IsSkippable() bool   { return true }
func (s *Step2SAST) RequiredTools() []string { return nil } // gosec is embedded, semgrep is optional

func (s *Step2SAST) Run(ctx context.Context, target string) ([]report.Finding, error) {
	var allFindings []report.Finding

	// Detect project language
	isGoProject := hasGoFiles(target)

	if isGoProject {
		// Layer 1: Embedded gosec — zero external dependency, fastest (77ms)
		gosecFindings, err := s.runGosec(ctx, target)
		if err == nil {
			allFindings = append(allFindings, gosecFindings...)
		}
		// Layer 2: CodeQL — deep semantic data flow analysis (optional, if installed)
		if _, lookErr := exec.LookPath("codeql"); lookErr == nil {
			codeqlFindings, codeqlErr := s.runCodeQL(ctx, target)
			if codeqlErr == nil {
				allFindings = append(allFindings, codeqlFindings...)
			}
		}
		// Layer 3: Semgrep fallback — broad pattern matching
		if err != nil && isToolAvailable("semgrep") {
			semgrepFindings, semgrepErr := s.runSemgrep(ctx, target)
			if semgrepErr == nil {
				allFindings = append(allFindings, semgrepFindings...)
			}
		}
	} else {
		// Non-Go: try bandit first (Python-specific, fastest), then CodeQL, then semgrep
		if hasPythonFiles(target) && isToolAvailable("bandit") {
			banditFindings, banditErr := s.runBandit(ctx, target)
			if banditErr == nil {
				allFindings = append(allFindings, banditFindings...)
			}
			// Ironwall custom: CWE-501 trust boundary + CWE-90 LDAP injection
			customFindings, customErr := s.runIronwallCustom(ctx, target)
			if customErr == nil {
				allFindings = append(allFindings, customFindings...)
			}
		}
		if _, lookErr := exec.LookPath("codeql"); lookErr == nil {
			codeqlFindings, codeqlErr := s.runCodeQL(ctx, target)
			if codeqlErr == nil {
				allFindings = append(allFindings, codeqlFindings...)
			}
		}
		if isToolAvailable("semgrep") {
			// Use both auto + p/python for maximum Python coverage
			rules := "auto,.semgrep/"
			if hasPythonFiles(target) {
				rules = "auto,p/python,.semgrep/"
			}
			semgrepFindings, err := s.runSemgrepWithRules(ctx, target, rules)
			if err == nil {
				allFindings = append(allFindings, semgrepFindings...)
			}
		}
	}

	// Apply severity classification + test-file downgrade
	for i := range allFindings {
		allFindings[i].Severity = classify.DowngradeForTestFile(allFindings[i].FilePath, allFindings[i].Severity)
	}

	// Run multi-stage AI verification on all findings at once (batch)
	if s.engine != nil && s.engine.Available() && len(allFindings) > 0 {
		var status ai.AnalysisStatus
		allFindings, status = s.engine.Analyze(ctx, allFindings)
		if status.TriageErrors > 0 || status.DeepErrors > 0 {
			log.Printf("[step2] AI partial: triage(%d/%d) deep(%d/%d) errors",
				status.TriageRuns-status.TriageErrors, status.TriageRuns,
				status.DeepRuns-status.DeepErrors, status.DeepRuns)
		}
	} else {
		// No AI: apply heuristic verification to medium+ findings
		for i := range allFindings {
			if allFindings[i].Severity <= report.SevMedium { // Critical/High/Medium only (lower=more severe)
				allFindings[i].AttackScenario = classify.HeuristicAttackTest(&allFindings[i])
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

// runCodeQL runs CodeQL for deep semantic analysis (data flow, taint tracking).
func (s *Step2SAST) runCodeQL(ctx context.Context, target string) ([]report.Finding, error) {
	result, err := scanner.RunCodeQL(target)
	if err != nil {
		return nil, fmt.Errorf("codeql: %w", err)
	}
	return result.ToFindings(), nil
}

// runSemgrep runs semgrep with auto-detection rules.
func (s *Step2SAST) runSemgrep(ctx context.Context, target string) ([]report.Finding, error) {
	return s.runSemgrepWithRules(ctx, target, "auto")
}

// runSemgrepWithRules runs semgrep with specified rule set.
func (s *Step2SAST) runSemgrepWithRules(ctx context.Context, target string, rules string) ([]report.Finding, error) {
	result, err := scanner.RunSemgrep(target, rules)
	if err != nil {
		return nil, fmt.Errorf("semgrep: %w", err)
	}
	return result.ToFindings(target), nil
}

// runBandit runs bandit for Python-specific security analysis.
func (s *Step2SAST) runBandit(ctx context.Context, target string) ([]report.Finding, error) {
	result, err := scanner.RunBandit(target)
	if err != nil {
		return nil, fmt.Errorf("bandit: %w", err)
	}
	return result.ToFindings(), nil
}

// runIronwallCustom runs the standalone CWE-501/CWE-90 AST scanner for Python.
func (s *Step2SAST) runIronwallCustom(ctx context.Context, target string) ([]report.Finding, error) {
	results, err := scanner.RunIronwallCustomScanner(target)
	if err != nil {
		return nil, fmt.Errorf("ironwall-custom: %w", err)
	}
	br := &scanner.BanditResult{Results: results}
	return br.ToFindings(), nil
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

// hasPythonFiles checks if target contains .py files.
func hasPythonFiles(target string) bool {
	var found bool
	_ = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || found {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == ".git" || base == "node_modules" || base == "__pycache__" || base == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".py" {
			found = true
		}
		return nil
	})
	return found
}
