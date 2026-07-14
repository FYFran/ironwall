package pipeline

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/FYFran/ironwall/internal/config"
	"github.com/FYFran/ironwall/internal/report"
)

// Step is the interface each audit step must implement.
type Step interface {
	Name() string
	Description() string
	Run(ctx context.Context, target string) ([]report.Finding, error)
	IsSkippable() bool
	RequiredTools() []string
}

// Pipeline orchestrates the execution of audit steps.
type Pipeline struct {
	steps []Step
	cfg   *config.Config
}

// New creates a new Pipeline with the given configuration.
func New(cfg *config.Config) *Pipeline {
	return &Pipeline{cfg: cfg}
}

// Register adds a step to the pipeline.
func (p *Pipeline) Register(step Step) {
	p.steps = append(p.steps, step)
}

// Run executes all registered steps in order.
func (p *Pipeline) Run(ctx context.Context, target string) (*report.ScanResult, error) {
	result := &report.ScanResult{
		Version: config.Version,
		Target:  target,
	}

	startTime := time.Now()
	result.StartedAt = startTime.Format(time.RFC3339)

	if p.cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(p.cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	for _, step := range p.steps {
		select {
		case <-ctx.Done():
			result.SkippedSteps = append(result.SkippedSteps,
				fmt.Sprintf("%s: cancelled (timeout or interrupt)", step.Name()))
			continue
		default:
		}

		if !p.checkTools(step.RequiredTools()) {
			if step.IsSkippable() {
				result.SkippedSteps = append(result.SkippedSteps,
					fmt.Sprintf("%s: required tools not available (%v)", step.Name(), step.RequiredTools()))
				continue
			}
			return nil, fmt.Errorf("step %q: required tools not available: %v", step.Name(), step.RequiredTools())
		}

		findings, err := step.Run(ctx, target)
		if err != nil {
			if step.Name() == "Step 1: Secret Scanning" {
				return nil, fmt.Errorf("step %q (TIER1) failed: %w", step.Name(), err)
			}
			result.SkippedSteps = append(result.SkippedSteps,
				fmt.Sprintf("%s: %v", step.Name(), err))
			continue
		}

		for i := range findings {
			if isTestFile(findings[i].FilePath) {
				findings[i].Severity = report.SevInfo
				findings[i].Title = "[TEST/EXAMPLE] " + findings[i].Title
				findings[i].Description = "Found in test/example code. " + findings[i].Description
			}
			if findings[i].ID == "" {
				findings[i].ID = fmt.Sprintf("IRON-%03d", result.Summary.Total+1)
			}
			result.Summary.AddFinding(findings[i])
		}
		result.Findings = append(result.Findings, findings...)
	}

	// Deduplicate findings across steps
	before := len(result.Findings)
	result.Findings = DeduplicateFindings(result.Findings)
	if before != len(result.Findings) {
		fmt.Printf("  Deduplicated: %d -> %d findings\n", before, len(result.Findings))
	}

	// Recompute summary after dedup
	result.Summary = report.ScanSummary{}
	for _, f := range result.Findings {
		result.Summary.AddFinding(f)
	}

	// Infer AI analysis status from findings
	result.AnalysisStatus = inferAIStatus(result.Findings, p.cfg.AIEnabled)

	result.CompletedAt = time.Now().Format(time.RFC3339)
	result.Duration = time.Since(startTime).Round(time.Millisecond).String()
	return result, nil
}

func (p *Pipeline) checkTools(tools []string) bool {
	for _, tool := range tools {
		if !isToolAvailable(tool) {
			if p.cfg.Verbose {
				fmt.Printf("  ⚠ tool not found: %s\n", tool)
			}
			return false
		}
	}
	return true
}

func inferAIStatus(findings []report.Finding, aiEnabled bool) string {
	if !aiEnabled {
		return "skipped"
	}
	aiMarkers := 0
	for _, f := range findings {
		if f.AIConfidence > 0 || strings.Contains(f.Description, "[AI Triage") || strings.Contains(f.Description, "[AI Deep Verify") {
			aiMarkers++
		}
	}
	if aiMarkers == 0 {
		return "error" // AI enabled but no findings show AI processing
	}
	if aiMarkers < len(findings) {
		return "partial"
	}
	return "full"
}

func isToolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// isTestFile checks if a file path is a test file or in a test/example directory.
func isTestFile(path string) bool {
	lower := strings.ToLower(path)
	// File-level patterns
	if strings.Contains(lower, "_test.") || strings.HasPrefix(lower, "test_") {
		return true
	}
	// Directory patterns — check both with leading separator and at path start
	for _, dir := range []string{"testdata", "fixtures", "test", "_examples", "examples"} {
		for _, sep := range []string{"/", "\\"} {
			if strings.Contains(lower, sep+dir+sep) || strings.HasPrefix(lower, dir+sep) {
				return true
			}
		}
	}
	return false
}
