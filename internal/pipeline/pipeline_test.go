package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/FYFran/ironwall/internal/config"
	"github.com/FYFran/ironwall/internal/report"
)

// mockStep is a test step that returns predefined findings.
type mockStep struct {
	name        string
	description string
	skippable   bool
	tools       []string
	findings    []report.Finding
	err         error
	delay       time.Duration
}

func (m *mockStep) Name() string            { return m.name }
func (m *mockStep) Description() string     { return m.description }
func (m *mockStep) IsSkippable() bool       { return m.skippable }
func (m *mockStep) RequiredTools() []string { return m.tools }

func (m *mockStep) Run(ctx context.Context, target string) ([]report.Finding, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	return m.findings, nil
}

func TestPipelineRun_AllSteps(t *testing.T) {
	cfg := config.Defaults()
	cfg.Target = "/test"
	cfg.TimeoutSeconds = 10

	pipe := New(cfg)

	pipe.Register(&mockStep{
		name:      "Step 1: Secret Scanning",
		skippable: false,
		tools:     []string{},
		findings: []report.Finding{
			{
				Title:      "Test finding 1",
				Severity:   report.SevCritical,
				FilePath:   "test.go",
				LineNumber: 10,
				Category:   "secret",
				Step:       1,
			},
		},
	})

	pipe.Register(&mockStep{
		name:      "Step 2: SAST Analysis",
		skippable: true,
		tools:     []string{},
		findings: []report.Finding{
			{
				Title:      "SQL Injection",
				Severity:   report.SevHigh,
				FilePath:   "handler.go",
				LineNumber: 25,
				Category:   "sql",
				Step:       2,
			},
		},
	})

	pipe.Register(&mockStep{
		name:      "Step 4: Hardcoded Secrets",
		skippable: true,
		tools:     []string{},
		findings: []report.Finding{
			{
				Title:      "Hardcoded key",
				Severity:   report.SevMedium,
				FilePath:   "config.go",
				LineNumber: 5,
				Category:   "hardcoded",
				Step:       4,
			},
		},
	})

	ctx := context.Background()
	result, err := pipe.Run(ctx, cfg.Target)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "/test", result.Target)
	assert.Equal(t, config.Version, result.Version)
	assert.Equal(t, 3, result.Summary.Total)
	assert.Equal(t, 1, result.Summary.Critical)
	assert.Equal(t, 1, result.Summary.High)
	assert.Equal(t, 1, result.Summary.Medium)
	assert.NotEmpty(t, result.StartedAt)
	assert.NotEmpty(t, result.CompletedAt)
	assert.NotEmpty(t, result.Duration)
}

func TestPipelineRun_SkipSkippable(t *testing.T) {
	cfg := config.Defaults()
	cfg.Target = "/test"
	cfg.TimeoutSeconds = 10

	pipe := New(cfg)

	pipe.Register(&mockStep{
		name:      "Step 2: SAST Analysis",
		skippable: true,
		tools:     []string{"nonexistent-tool-xyz"},
		findings:  nil,
	})

	pipe.Register(&mockStep{
		name:      "Step 4: Hardcoded Secrets",
		skippable: true,
		tools:     []string{},
		findings: []report.Finding{
			{
				Title:    "Still runs",
				Severity: report.SevLow,
				Step:     4,
			},
		},
	})

	ctx := context.Background()
	result, err := pipe.Run(ctx, cfg.Target)

	require.NoError(t, err)
	assert.Equal(t, 1, result.Summary.Total)
	assert.Equal(t, 1, len(result.SkippedSteps))
	assert.Contains(t, result.SkippedSteps[0], "Step 2")
}

func TestPipelineRun_TIER1Failure(t *testing.T) {
	cfg := config.Defaults()
	cfg.Target = "/test"
	cfg.TimeoutSeconds = 10

	pipe := New(cfg)

	pipe.Register(&mockStep{
		name:      "Step 1: Secret Scanning",
		skippable: false,
		tools:     []string{"nonexistent-tool-xyz"},
	})

	ctx := context.Background()
	_, err := pipe.Run(ctx, cfg.Target)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "Step 1")
	assert.Contains(t, err.Error(), "not available")
}

func TestPipelineRun_Timeout(t *testing.T) {
	cfg := config.Defaults()
	cfg.Target = "/test"
	cfg.TimeoutSeconds = 1

	pipe := New(cfg)

	pipe.Register(&mockStep{
		name:      "Step 1: Secret Scanning",
		skippable: false,
		tools:     []string{},
		delay:     2 * time.Second,
		findings: []report.Finding{
			{Title: "Should be interrupted", Severity: report.SevLow, Step: 1, Category: "x"},
		},
	})

	ctx := context.Background()
	_, err := pipe.Run(ctx, cfg.Target)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "TIER1")
}

func TestPipelineRun_StepError(t *testing.T) {
	cfg := config.Defaults()
	cfg.Target = "/test"
	cfg.TimeoutSeconds = 10

	pipe := New(cfg)

	pipe.Register(&mockStep{
		name:      "Step 1: Secret Scanning",
		skippable: false,
		tools:     []string{},
		findings:  nil,
		err:       assert.AnError,
	})

	ctx := context.Background()
	_, err := pipe.Run(ctx, cfg.Target)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "TIER1")
}

func TestFindingIDAssignment(t *testing.T) {
	cfg := config.Defaults()
	cfg.Target = "/test"

	pipe := New(cfg)

	pipe.Register(&mockStep{
		name:      "Step 1: Secret Scanning",
		skippable: false,
		tools:     []string{},
		findings: []report.Finding{
			{Title: "A", Severity: report.SevHigh, Step: 1, FilePath: "a.go", LineNumber: 1, Category: "cat-a"},
			{Title: "B", Severity: report.SevMedium, Step: 1, FilePath: "b.go", LineNumber: 2, Category: "cat-b"},
		},
	})

	pipe.Register(&mockStep{
		name:      "Step 2: SAST",
		skippable: true,
		tools:     []string{},
		findings: []report.Finding{
			{Title: "C", Severity: report.SevLow, Step: 2, FilePath: "c.go", LineNumber: 3, Category: "cat-c"},
		},
	})

	ctx := context.Background()
	result, err := pipe.Run(ctx, cfg.Target)

	require.NoError(t, err)
	assert.Equal(t, 3, len(result.Findings), "distinct file/line/category should not be deduped")
	assert.Equal(t, "IRON-001", result.Findings[0].ID)
	assert.Equal(t, "IRON-002", result.Findings[1].ID)
	assert.Equal(t, "IRON-003", result.Findings[2].ID)
}

func TestDedupMergeFindings(t *testing.T) {
	findings := []report.Finding{
		{Title: "Finding from Step 1", Severity: report.SevMedium, FilePath: "x.go", LineNumber: 10, Category: "secret", Step: 1},
		{Title: "Same finding from Step 4", Severity: report.SevHigh, FilePath: "x.go", LineNumber: 10, Category: "hardcoded-secret", Step: 4},
	}

	result := DeduplicateFindings(findings)

	assert.Equal(t, 1, len(result), "same file+line+normalized-category should dedup")
	assert.Equal(t, report.SevHigh, result[0].Severity, "keeps higher severity")
	assert.True(t, result[0].Step == 1, "keeps earlier step number")
}
