package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// Engine is the Ironwall Agent Engine — the core AI-powered analysis pipeline.
//
// Architecture:
//
//	Scanner Findings → Orchestrator (rule-based pre-filter)
//	                 → ContextProvider (AST analysis)
//	                 → Analyst (4-step OBSERVE→TRACE→VERIFY→ASSESS)
//	                 → Verifier (API key check + AST reachability)
//	                 → ReportBuilder (6-section markdown)
type Engine struct {
	analyst       *Analyst
	builder       *DefaultReportBuilder
	providers     *ContextProviderRegistry
	offlineEngine *OfflineEngine

	aiEnabled   bool
	offlineMode bool
	batchMode   bool
}

// EngineOption configures an Engine.
type EngineOption func(*Engine)

// WithAI enables AI-powered analysis.
func WithAI(analyst *Analyst) EngineOption {
	return func(e *Engine) {
		e.analyst = analyst
		e.aiEnabled = true
	}
}

// WithBatchMode enables batch processing of findings.
func WithBatchMode() EngineOption {
	return func(e *Engine) {
		e.batchMode = true
	}
}

// WithOfflineFallback enables offline rule-based analysis when AI is unavailable.
func WithOfflineFallback(providers *ContextProviderRegistry) EngineOption {
	return func(e *Engine) {
		e.offlineEngine = NewOfflineEngine(providers)
		e.offlineMode = true
	}
}

// NewEngine creates a new Agent Engine.
func NewEngine(builder *DefaultReportBuilder, providers *ContextProviderRegistry, opts ...EngineOption) *Engine {
	e := &Engine{
		builder:   builder,
		providers: providers,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Analyze runs the Agent Engine on a batch of scanner findings.
func (e *Engine) Analyze(ctx context.Context, findings []InputFinding) []InputFinding {
	if len(findings) == 0 {
		return findings
	}

	startTime := time.Now()
	log.Printf("[Agent Engine] Analyzing %d findings (ai=%v, offline=%v, batch=%v)",
		len(findings), e.aiEnabled, e.offlineMode, e.batchMode)

	// Phase 0: Pre-filter — skip INFO/LOW findings.
	var toAnalyze []InputFinding
	var passThrough []InputFinding
	for _, f := range findings {
		if f.Severity.NeedsAnalysis() {
			toAnalyze = append(toAnalyze, f)
		} else {
			passThrough = append(passThrough, f)
		}
	}

	if len(toAnalyze) == 0 {
		return findings
	}

	// Phase 1: AI Analysis (or offline fallback).
	var results []*AnalystResult
	if e.aiEnabled && e.analyst != nil {
		var err error
		if e.batchMode && len(toAnalyze) > 3 {
			results, err = e.analyst.AnalyzeBatch(ctx, toAnalyze)
		} else {
			results, err = e.analyzeOneByOne(ctx, toAnalyze)
		}
		if err != nil {
			log.Printf("[Agent Engine] AI analysis failed: %v — falling back to offline", err)
			results = e.offlineAnalyze(toAnalyze)
		}
	} else if e.offlineMode && e.offlineEngine != nil {
		results = e.offlineAnalyze(toAnalyze)
	} else {
		return findings
	}

	// Phase 2: Apply results back to findings.
	enrichedFindings := e.applyResults(toAnalyze, results)

	elapsed := time.Since(startTime)
	log.Printf("[Agent Engine] Analysis complete in %s — %d findings analyzed", elapsed, len(toAnalyze))

	return append(enrichedFindings, passThrough...)
}

// analyzeOneByOne analyzes each finding individually for quality.
func (e *Engine) analyzeOneByOne(ctx context.Context, findings []InputFinding) ([]*AnalystResult, error) {
	results := make([]*AnalystResult, len(findings))
	var lastErr error

	for i, f := range findings {
		result, err := e.analyst.AnalyzeFinding(ctx, f)
		if err != nil {
			lastErr = err
			results[i] = &AnalystResult{
				FindingID:     f.ID,
				Title:         f.Title,
				Severity:      InputSeverityToAgent(f.Severity),
				IsExploitable: false,
				Confidence:    0.0,
				Narrative:     fmt.Sprintf("Analysis error: %v", err),
			}
			continue
		}
		results[i] = result
	}

	return results, lastErr
}

// offlineAnalyze uses the rule-based offline engine.
func (e *Engine) offlineAnalyze(findings []InputFinding) []*AnalystResult {
	if e.offlineEngine == nil {
		return nil
	}

	results := make([]*AnalystResult, len(findings))
	for i, f := range findings {
		ctx, _ := e.providers.GetContext(f.FilePath, f.LineNumber)
		results[i] = e.offlineEngine.Analyze(f, ctx)
	}
	return results
}

// applyResults maps AnalystResults back to InputFindings.
func (e *Engine) applyResults(findings []InputFinding, results []*AnalystResult) []InputFinding {
	if len(results) != len(findings) {
		resultMap := make(map[string]*AnalystResult)
		for _, r := range results {
			if r != nil {
				resultMap[r.FindingID] = r
			}
		}
		for i := range findings {
			if r, ok := resultMap[findings[i].ID]; ok {
				applyResultToFinding(&findings[i], r)
			}
		}
		return findings
	}

	for i := range findings {
		if results[i] != nil {
			applyResultToFinding(&findings[i], results[i])
		}
	}
	return findings
}

// applyResultToFinding applies an AnalystResult to an InputFinding.
func applyResultToFinding(f *InputFinding, r *AnalystResult) {
	f.AIConfidence = r.Confidence

	// If AI determined it's not exploitable with high confidence, downgrade.
	if !r.IsExploitable && r.Confidence >= 0.7 {
		f.Severity = InputSevInfo
		f.Description += fmt.Sprintf(
			"\n[Agent Analysis: NOT EXPLOITABLE (confidence %.0f%%) — %s]",
			r.Confidence*100, truncateForField(r.Narrative, 200))
		return
	}

	// If AI confirmed exploitable, enrich the finding.
	if r.IsExploitable && r.Confidence >= 0.7 {
		f.AttackScenario = &AttackScenario{
			Actor:       extractActorFromNarrative(r.Narrative),
			Path:        buildAttackPathString(r.AttackPath),
			Impact:      extractImpactFromNarrative(r.Narrative),
			IsReal:      r.IsExploitable,
			Explanation: r.Narrative,
		}

		if r.FixSuggestion != "" {
			f.FixSuggestion = r.FixSuggestion
		}
		if r.CVSS > f.CVSS {
			f.CVSS = r.CVSS
		}

		f.Description += fmt.Sprintf(
			"\n[Agent Analysis: CONFIRMED EXPLOITABLE (confidence %.0f%%) — %d attack steps identified]",
			r.Confidence*100, len(r.AttackPath))
	}
}

// extractActorFromNarrative extracts attacker profile from narrative text.
func extractActorFromNarrative(narrative string) string {
	lower := strings.ToLower(narrative)
	if strings.Contains(lower, "unauthenticated") {
		return "Unauthenticated remote attacker"
	}
	if strings.Contains(lower, "authenticated") {
		return "Authenticated user with access to the vulnerable endpoint"
	}
	if strings.Contains(lower, "anyone") {
		return "Anyone with access to the source code or repository"
	}
	return "Attacker with access to the vulnerable input"
}

// buildAttackPathString converts AttackSteps to a formatted string.
func buildAttackPathString(steps []AttackStep) string {
	if len(steps) == 0 {
		return "Attack path not constructed."
	}
	var buf strings.Builder
	for _, s := range steps {
		buf.WriteString(fmt.Sprintf("%d. %s", s.StepNumber, s.Description))
		if s.FileRef != "" {
			buf.WriteString(fmt.Sprintf(" (%s", s.FileRef))
			if s.LineRef > 0 {
				buf.WriteString(fmt.Sprintf(":%d", s.LineRef))
			}
			buf.WriteString(")")
		}
		buf.WriteString("\n")
	}
	return buf.String()
}

// extractImpactFromNarrative extracts impact from the narrative.
func extractImpactFromNarrative(narrative string) string {
	lower := strings.ToLower(narrative)
	if strings.Contains(lower, "remote code execution") || strings.Contains(lower, "rce") {
		return "Remote code execution on the server. Full system compromise."
	}
	if strings.Contains(lower, "data breach") || strings.Contains(lower, "data leak") {
		return "Unauthorized data access and potential data breach."
	}
	if strings.Contains(lower, "privilege escalation") {
		return "Privilege escalation to higher access levels."
	}
	return "Unauthorized access or system compromise depending on exploit context."
}

// GenerateReport generates a markdown report for a single analyzed finding.
func (e *Engine) GenerateReport(result AnalystResult) (string, error) {
	return e.builder.BuildReport(result)
}

// GenerateBatchReport generates a combined report for multiple analyzed findings.
func (e *Engine) GenerateBatchReport(results []*AnalystResult) (string, error) {
	var buf strings.Builder

	buf.WriteString("# Ironwall Agent Security Audit Report\n\n")
	buf.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("**Findings Analyzed:** %d\n\n", len(results)))
	buf.WriteString("---\n\n")

	for _, r := range results {
		if r == nil {
			continue
		}
		report, err := e.builder.BuildReport(*r)
		if err != nil {
			buf.WriteString(fmt.Sprintf("### Error generating report for %s: %v\n\n", r.FindingID, err))
			continue
		}
		buf.WriteString(report)
		buf.WriteString("\n---\n\n")
	}

	buf.WriteString(fmt.Sprintf("\n*Report generated by Ironwall Agent Engine v0.5.0 at %s*\n", time.Now().Format(time.RFC3339)))
	return buf.String(), nil
}

// Available returns whether AI analysis is available.
func (e *Engine) Available() bool {
	return e.aiEnabled && e.analyst != nil
}

// AnalyzeSingle is a convenience method for analyzing one finding.
func (e *Engine) AnalyzeSingle(ctx context.Context, f InputFinding) (*AnalystResult, error) {
	if e.aiEnabled && e.analyst != nil {
		return e.analyst.AnalyzeFinding(ctx, f)
	}
	if e.offlineEngine != nil {
		ctx, _ := e.providers.GetContext(f.FilePath, f.LineNumber)
		return e.offlineEngine.Analyze(f, ctx), nil
	}
	return nil, fmt.Errorf("no analysis engine available")
}

func truncateForField(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// NewDefaultEngine creates an Engine with sensible defaults for production use.
func NewDefaultEngine(llmClient LLMClient, scriptPath string) *Engine {
	providers := NewContextProviderRegistry(NewGenericContextProvider())
	providers.Register(NewGoContextProvider())
	providers.Register(NewPythonContextProvider(scriptPath))

	builder := NewReportBuilder()
	analyst := NewAnalyst(llmClient, providers)

	return NewEngine(builder, providers,
		WithAI(analyst),
		WithBatchMode(),
		WithOfflineFallback(providers),
	)
}

// NewOfflineEngineOnly creates an Engine with only offline analysis.
func NewOfflineEngineOnly() *Engine {
	providers := NewContextProviderRegistry(NewGenericContextProvider())
	providers.Register(NewGoContextProvider())
	providers.Register(NewPythonContextProvider(
		os.Getenv("IRONWALL_PYTHON_SCRIPT"),
	))

	builder := NewReportBuilder()

	return NewEngine(builder, providers,
		WithOfflineFallback(providers),
	)
}
