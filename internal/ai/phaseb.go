package ai

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/FYFran/ironwall/internal/ai/observe"
	"github.com/FYFran/ironwall/internal/report"
)

// ─── Phase B: Real AI Audit Engine ──────────────────────────────────────────

// ObserveResult wraps observe.ObserveResult for external consumption.
type ObserveResult = observe.ObserveResult

// ObservedSection wraps observe.ObservedSection.
type ObservedSection = observe.ObservedSection

// Observe runs Phase 1 (OBSERVE) — AST-based code analysis, no AI calls.
func (e *Engine) Observe(target string) (*ObserveResult, error) {
	obs := observe.NewObserver()
	return obs.Observe(target)
}

// ObserveFiles runs OBSERVE on specific files.
func (e *Engine) ObserveFiles(files []string) (*ObserveResult, error) {
	obs := observe.NewObserver()
	return obs.ObserveFiles(files)
}

// ─── Phase B.2a: TRACE (data flow) ──────────────────────────────────────────

// TraceResult holds the LLM's analysis of data flow through an observed section.
type TraceResult struct {
	Section          ObservedSection `json:"section"`
	HasDataFlow      bool            `json:"has_data_flow"`
	InputSource      string          `json:"input_source"`
	Sink             string          `json:"sink"`
	Path             string          `json:"path"`
	MissingAuth      bool            `json:"missing_auth"`
	MissingValidation bool           `json:"missing_validation"`
	Confidence       float64         `json:"confidence"`
	CWESuggested     string          `json:"cwe_suggested"`
}

// Trace runs Phase 2a (TRACE) — LLM data flow analysis.
// chains is optional cross-file taint chains from call graph (nil = skip).
func (e *Engine) Trace(ctx context.Context, sections []ObservedSection, chains []observe.TaintChain) ([]TraceResult, error) {
	if len(sections) == 0 || !e.Available() {
		return nil, nil
	}
	client := e.deepClient
	if client == nil || !client.Available() {
		client = e.triageClient
	}
	if client == nil || !client.Available() {
		return nil, fmt.Errorf("no AI client available for TRACE")
	}

	var results []TraceResult
	batches := batchTraceSections(sections, 10)
	for batchIdx, batch := range batches {
		if batchIdx > 0 {
			time.Sleep(batchInterval)
		}
		batchResults, err := e.traceBatch(ctx, client, batch, chains)
		if err != nil {
			log.Printf("[AI TRACE] batch %d/%d failed: %v", batchIdx+1, len(batches), err)
			continue
		}
		results = append(results, batchResults...)
	}
	log.Printf("[AI TRACE] analyzed %d sections → %d potential vulns (chains=%d)", len(sections), len(results), len(chains))
	return results, nil
}

func (e *Engine) traceBatch(ctx context.Context, client *Client, sections []ObservedSection, chains []observe.TaintChain) ([]TraceResult, error) {
	summary := buildTraceSummaryWithCG(sections, chains)
	prompt := fmt.Sprintf(PromptTrace, summary)

	var response struct {
		Results []struct {
			FuncName          string  `json:"func_name"`
			FilePath          string  `json:"file_path"`
			HasDataFlow       bool    `json:"has_data_flow"`
			InputSource       string  `json:"input_source"`
			Sink              string  `json:"sink"`
			Path              string  `json:"path"`
			MissingAuth       bool    `json:"missing_auth"`
			MissingValidation bool    `json:"missing_validation"`
			Confidence        float64 `json:"confidence"`
			CWESuggested      string  `json:"cwe_suggested"`
		} `json:"results"`
	}

	err := client.ChatJSONWithMaxTokens(ctx, SystemPromptTrace, prompt, &response, 2048+len(sections)*512)
	if err != nil {
		return nil, err
	}

	var results []TraceResult
	for i, r := range response.Results {
		if i >= len(sections) {
			break
		}
		if r.HasDataFlow && r.Confidence >= 0.6 {
			results = append(results, TraceResult{
				Section:           sections[i],
				HasDataFlow:       r.HasDataFlow,
				InputSource:       r.InputSource,
				Sink:              r.Sink,
				Path:              r.Path,
				MissingAuth:       r.MissingAuth,
				MissingValidation: r.MissingValidation,
				Confidence:        r.Confidence,
				CWESuggested:      r.CWESuggested,
			})
		}
	}
	return results, nil
}

func buildTraceSummaryWithCG(sections []ObservedSection, chains []observe.TaintChain) string {
	var sb strings.Builder
	for i, s := range sections {
		sb.WriteString(fmt.Sprintf("### Section %d\n", i+1))
		sb.WriteString(fmt.Sprintf("Function: %s\n", s.FuncName))
		sb.WriteString(fmt.Sprintf("File: %s:%d-%d\n", s.FilePath, s.LineStart, s.LineEnd))
		sb.WriteString(fmt.Sprintf("Package: %s\n", s.PackageName))
		if s.StructName != "" {
			sb.WriteString(fmt.Sprintf("Receiver: %s\n", s.StructName))
		}
		sb.WriteString(fmt.Sprintf("IsHandler: %v\n", s.IsHandler))
		sb.WriteString(fmt.Sprintf("HasAuthCheck: %v\n", s.HasAuthCheck))
		sb.WriteString(fmt.Sprintf("Security Concerns: %v\n", s.Concerns))
		if len(s.Imports) > 0 {
			sb.WriteString(fmt.Sprintf("Imports: %v\n", s.Imports))
		}
		// v4.1: Inject cross-file taint chains if this function participates in any
		if len(chains) > 0 {
			relevant := observe.GetChainsForFunction(chains, s.FuncName)
			if len(relevant) > 0 {
				sb.WriteString("\n")
				sb.WriteString(observe.FormatTaintChains(relevant))
			}
		}
		sb.WriteString(fmt.Sprintf("\n```go\n%s\n```\n\n", s.CodeSnippet))
	}
	return sb.String()
}

// buildTraceSummary is the backward-compatible wrapper without call graph context.
func buildTraceSummary(sections []ObservedSection) string {
	return buildTraceSummaryWithCG(sections, nil)
}

func batchTraceSections(sections []ObservedSection, batchSize int) [][]ObservedSection {
	var batches [][]ObservedSection
	for i := 0; i < len(sections); i += batchSize {
		end := i + batchSize
		if end > len(sections) {
			end = len(sections)
		}
		batches = append(batches, sections[i:end])
	}
	return batches
}

// ─── Phase B.2b: TRACE-MISSING ──────────────────────────────────────────────

type MissingControl struct {
	Section     ObservedSection `json:"section"`
	ControlType string          `json:"control_type"`
	IsMissing   bool            `json:"is_missing"`
	Confidence  float64         `json:"confidence"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	FixHint     string          `json:"fix_hint"`
	CWE         string          `json:"cwe"`
}

func (e *Engine) TraceMissing(ctx context.Context, handlers []ObservedSection) ([]MissingControl, error) {
	if len(handlers) == 0 || !e.Available() {
		return nil, nil
	}
	client := e.deepClient
	if client == nil || !client.Available() {
		client = e.triageClient
	}
	if client == nil || !client.Available() {
		return nil, fmt.Errorf("no AI client for TraceMissing")
	}

	var results []MissingControl
	for _, h := range handlers {
		prompt := fmt.Sprintf(PromptMissingControls, buildHandlerSummary(h))
		var response struct {
			Controls []struct {
				ControlType string  `json:"control_type"`
				IsMissing   bool    `json:"is_missing"`
				Confidence  float64 `json:"confidence"`
				Severity    string  `json:"severity"`
				Title       string  `json:"title"`
				Description string  `json:"description"`
				FixHint     string  `json:"fix_hint"`
				CWE         string  `json:"cwe"`
			} `json:"controls"`
		}
		err := client.ChatJSONWithMaxTokens(ctx, SystemPromptMissingControls, prompt, &response, 1024)
		if err != nil {
			log.Printf("[AI Missing] %s:%d %s() failed: %v", h.FilePath, h.LineStart, h.FuncName, err)
			continue
		}
		for _, c := range response.Controls {
			if c.IsMissing && c.Confidence >= 0.7 {
				results = append(results, MissingControl{
					Section:     h,
					ControlType: c.ControlType,
					IsMissing:   true,
					Confidence:  c.Confidence,
					Severity:    c.Severity,
					Title:       c.Title,
					Description: c.Description,
					FixHint:     c.FixHint,
					CWE:         c.CWE,
				})
			}
		}
	}
	log.Printf("[AI Missing] analyzed %d handlers → %d missing controls", len(handlers), len(results))
		results = deduplicateMissingControls(results)
		log.Printf("[AI Missing] after dedup: %d merged findings", len(results))
		results = filterMissingControls(results)
		log.Printf("[AI Missing] after filter: %d actionable findings", len(results))
	return results, nil
}

func buildHandlerSummary(s ObservedSection) string {
	var sb strings.Builder
	sb.WriteString("### HTTP Handler\n")
	sb.WriteString(fmt.Sprintf("Function: %s\n", s.FuncName))
	sb.WriteString(fmt.Sprintf("File: %s:%d-%d\n", s.FilePath, s.LineStart, s.LineEnd))
	sb.WriteString(fmt.Sprintf("Package: %s\n", s.PackageName))
	sb.WriteString(fmt.Sprintf("Known concerns: %v\n", s.Concerns))
	if s.HasAuthCheck {
		sb.WriteString("Auth check detected in function body.\n")
	} else {
		sb.WriteString("No auth check detected in function body.\n")
	}
	sb.WriteString(fmt.Sprintf("\n```go\n%s\n```\n", s.CodeSnippet))
	return sb.String()
}

func tuneMissingSeverity(m MissingControl) report.Severity {
	baseSev := parseSeverity(m.Severity)
	if baseSev == report.SevInfo {
		baseSev = report.SevMedium
	}
	switch strings.ToLower(m.ControlType) {
	case "rate_limiting", "rate-limiting":
		if baseSev < report.SevLow {
			return report.SevLow
		}
	case "csrf", "csrf_protection":
		return report.SevLow
	case "content_type", "content-type", "content_type_validation":
		return report.SevLow
	case "auth", "authentication":
		funcName := strings.ToLower(m.Section.FuncName)
		if strings.Contains(funcName, "proxy") ||
			strings.Contains(funcName, "exec") ||
			strings.Contains(funcName, "files") ||
			strings.Contains(funcName, "search") ||
			strings.Contains(funcName, "hash") ||
			strings.Contains(funcName, "health") {
			if baseSev < report.SevMedium {
				return report.SevMedium
			}
		}
	case "input_validation", "validation":
		if baseSev < report.SevMedium {
			return report.SevMedium
		}
	}
	return baseSev
}

func (e *Engine) ConvertMissingToFindings(missing []MissingControl) []report.Finding {
	var findings []report.Finding
	for i, m := range missing {
		sev := tuneMissingSeverity(m)
		findings = append(findings, report.Finding{
			ID:            fmt.Sprintf("IRON-MISS-%03d", i+1),
			Title:         m.Title,
			Description:   m.Description,
			Severity:      sev,
			FilePath:      m.Section.FilePath,
			LineNumber:    m.Section.LineStart,
			CodeSnippet:   m.Section.CodeSnippet,
			Category:      "missing-" + m.ControlType,
			AIConfidence:  m.Confidence,
			FixSuggestion: m.FixHint,
			CWE:           m.CWE,
			CVSS:          report.SeverityToCVSS(sev),
		})
	}
	return findings
}

// ─── Phase B.2c: TRACE-CONFIG ───────────────────────────────────────────────

type ConfigIssue struct {
	Section     ObservedSection `json:"section"`
	IssueType   string          `json:"issue_type"`
	Confidence  float64         `json:"confidence"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	FixHint     string          `json:"fix_hint"`
	CWE         string          `json:"cwe"`
}

func (e *Engine) TraceConfig(ctx context.Context, sections []ObservedSection) ([]ConfigIssue, error) {
	if len(sections) == 0 || !e.Available() {
		return nil, nil
	}
	client := e.deepClient
	if client == nil || !client.Available() {
		client = e.triageClient
	}
	if client == nil || !client.Available() {
		return nil, fmt.Errorf("no AI client for TraceConfig")
	}

	summary := buildConfigSummary(sections)
	prompt := fmt.Sprintf(PromptConfigAudit, summary)

	var response struct {
		Issues []struct {
			FuncName    string  `json:"func_name"`
			IssueType   string  `json:"issue_type"`
			Confidence  float64 `json:"confidence"`
			Severity    string  `json:"severity"`
			Title       string  `json:"title"`
			Description string  `json:"description"`
			FixHint     string  `json:"fix_hint"`
			CWE         string  `json:"cwe"`
		} `json:"issues"`
	}

	err := client.ChatJSONWithMaxTokens(ctx, SystemPromptConfigAudit, prompt, &response, 1024)
	if err != nil {
		return nil, err
	}

	var results []ConfigIssue
	for _, iss := range response.Issues {
		if iss.Confidence < 0.7 {
			continue
		}
		for _, s := range sections {
			if s.FuncName == iss.FuncName {
				results = append(results, ConfigIssue{
					Section:     s,
					IssueType:   iss.IssueType,
					Confidence:  iss.Confidence,
					Severity:    iss.Severity,
					Title:       iss.Title,
					Description: iss.Description,
					FixHint:     iss.FixHint,
					CWE:         iss.CWE,
				})
				break
			}
		}
	}
		// Merge with deterministic pre-scan results
		detResults := scanConfigPatterns(sections)
		results = append(results, detResults...)
		log.Printf("[AI Config] %d sections -> %d AI + %d deterministic = %d config issues", len(sections), len(results)-len(detResults), len(detResults), len(results))
		return results, nil
	}


// scanConfigPatterns does deterministic regex scanning for obvious config issues.
// This catches patterns the AI might miss (module-level code outside handlers).
func scanConfigPatterns(sections []ObservedSection) []ConfigIssue {
	var issues []ConfigIssue
	debugRe := regexp.MustCompile(`(?i)debug\s*=\s*True`)
	bindRe := regexp.MustCompile(`0\.0\.0\.0`)
	secretRe := regexp.MustCompile(`(?i)secret_key\s*=\s*["'][^"']{8,}["']`)

	for _, s := range sections {
		code := s.CodeSnippet
		if debugRe.MatchString(code) {
			issues = append(issues, ConfigIssue{
				Section: s, IssueType: "debug_mode", Confidence: 0.95,
				Severity: "CRITICAL", Title: "Debug mode enabled",
				Description: fmt.Sprintf("debug=True found in %s. Werkzeug debugger exposes /console for remote code execution.", s.FuncName),
				FixHint: "Set debug=False in production. Use environment variable: debug=os.getenv('DEBUG','false').lower()=='true'",
				CWE: "CWE-489",
			})
		}
		if bindRe.MatchString(code) {
			issues = append(issues, ConfigIssue{
				Section: s, IssueType: "bind_all", Confidence: 0.95,
				Severity: "HIGH", Title: "Server binds to all interfaces (0.0.0.0)",
				Description: fmt.Sprintf("Server binding to 0.0.0.0 in %s exposes the service on all network interfaces.", s.FuncName),
				FixHint: "Bind to 127.0.0.1 for local-only services, or use a reverse proxy for production.",
				CWE: "CWE-668",
			})
		}
		if secretRe.MatchString(code) {
			issues = append(issues, ConfigIssue{
				Section: s, IssueType: "hardcoded_secret", Confidence: 0.95,
				Severity: "HIGH", Title: "Hardcoded secret key detected",
				Description: fmt.Sprintf("Hardcoded secret_key found in %s. Session forgery possible if source code is exposed.", s.FuncName),
				FixHint: "Use os.Getenv('SECRET_KEY') or generate random key: secrets.token_hex(32)",
				CWE: "CWE-798",
			})
		}
	}
	return issues
}

func buildConfigSummary(sections []ObservedSection) string {
	var sb strings.Builder
	for i, s := range sections {
		sb.WriteString(fmt.Sprintf("### Section %d: %s\n", i+1, s.FuncName))
		sb.WriteString(fmt.Sprintf("File: %s:%d-%d\n", s.FilePath, s.LineStart, s.LineEnd))
		if len(s.Concerns) > 0 {
			sb.WriteString(fmt.Sprintf("Concerns: %v\n", s.Concerns))
		}
		maxLen := 1200
		code := s.CodeSnippet
		if len(code) > maxLen {
			code = code[:maxLen]
		}
		sb.WriteString(fmt.Sprintf("```go\n%s\n```\n\n", code))
	}
	return sb.String()
}

func (e *Engine) ConvertConfigToFindings(issues []ConfigIssue) []report.Finding {
	var findings []report.Finding
	for i, iss := range issues {
		sev := parseSeverity(iss.Severity)
		if sev == report.SevInfo {
			sev = report.SevMedium
		}
		findings = append(findings, report.Finding{
			ID:            fmt.Sprintf("IRON-CFG-%03d", i+1),
			Title:         iss.Title,
			Description:   iss.Description,
			Severity:      sev,
			FilePath:      iss.Section.FilePath,
			LineNumber:    iss.Section.LineStart,
			CodeSnippet:   iss.Section.CodeSnippet,
			Category:      "config-" + iss.IssueType,
			AIConfidence:  iss.Confidence,
			FixSuggestion: iss.FixHint,
			CWE:           iss.CWE,
			CVSS:          report.SeverityToCVSS(sev),
		})
	}
	return findings
}

// ─── Phase B.3: VERIFY ──────────────────────────────────────────────────────

type VerifiedFinding struct {
	Trace       TraceResult `json:"trace"`
	IsReal      bool        `json:"is_real"`
	Confidence  float64     `json:"confidence"`
	Severity    string      `json:"severity"`
	CWE         string      `json:"cwe"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	FixHint     string      `json:"fix_hint"`
	Refutation  string      `json:"refutation"`
}

func (e *Engine) VerifyTraces(ctx context.Context, traces []TraceResult) ([]VerifiedFinding, error) {
	if len(traces) == 0 || !e.Available() {
		return nil, nil
	}
	client := e.deepClient
	if client == nil || !client.Available() {
		client = e.triageClient
	}
	if client == nil || !client.Available() {
		return nil, fmt.Errorf("no AI client for VERIFY")
	}

	var verified []VerifiedFinding
	// Batch verify: 5 traces per API call (reduces API calls from N to N/5)
	batches := batchVerifyTraces(traces, 5)
	for batchIdx, batch := range batches {
		if batchIdx > 0 {
			time.Sleep(batchInterval)
		}
		batchResults, err := e.verifyBatch(ctx, client, batch)
		if err != nil {
			log.Printf("[AI VERIFY] batch %d/%d failed: %v", batchIdx+1, len(batches), err)
			// Fall back to one-by-one for failed batches
			for _, tr := range batch {
				if vf, err := e.verifyOne(ctx, client, tr); err == nil && vf != nil {
					verified = append(verified, *vf)
				}
			}
			continue
		}
		verified = append(verified, batchResults...)
	}
	log.Printf("[AI VERIFY] %d traces → %d confirmed vulns (%d batches)", len(traces), len(verified), len(batches))
	return verified, nil
}

// verifyBatch sends multiple traces in a single API call.
func (e *Engine) verifyBatch(ctx context.Context, client *Client, traces []TraceResult) ([]VerifiedFinding, error) {
	if len(traces) == 0 {
		return nil, nil
	}
	if len(traces) == 1 {
		vf, err := e.verifyOne(ctx, client, traces[0])
		if err != nil {
			return nil, err
		}
		if vf != nil {
			return []VerifiedFinding{*vf}, nil
		}
		return nil, nil
	}

	// Build batch prompt with explicit JSON format contract
	var sb strings.Builder
	sb.WriteString("Verify these potential vulnerability findings. For each, determine if it's a REAL vulnerability.\n\n")
	for i, tr := range traces {
		sb.WriteString(fmt.Sprintf("### Finding %d\n", i+1))
		sb.WriteString(buildVerifySummary(tr))
		sb.WriteString("\n---\n\n")
	}
	sb.WriteString("Respond ONLY with valid JSON in this EXACT format. index is 0-based (Finding 1 = index 0).\n")
	sb.WriteString("{\n")
	sb.WriteString("  \"findings\": [\n")
	sb.WriteString("    {\n")
	sb.WriteString("      \"index\": 0,\n")
	sb.WriteString("      \"is_real\": true,\n")
	sb.WriteString("      \"confidence\": 0.95,\n")
	sb.WriteString("      \"severity\": \"HIGH\",\n")
	sb.WriteString("      \"cwe\": \"CWE-89\",\n")
	sb.WriteString("      \"title\": \"SQL Injection in login\",\n")
	sb.WriteString("      \"description\": \"User input flows to SQL query without parameterization\",\n")
	sb.WriteString("      \"fix_hint\": \"Use parameterized queries\",\n")
	sb.WriteString("      \"refutation\": \"\",\n")
	sb.WriteString("      \"refutation_points\": []\n")
	sb.WriteString("    }\n")
	sb.WriteString("  ]\n")
	sb.WriteString("}\n")
	sb.WriteString("If is_real=false, leave severity/cwe/title/description/fix_hint empty and fill refutation + refutation_points.\n")

	prompt := sb.String()

	// Parse batch response
	var response struct {
		Findings []struct {
			Index            int      `json:"index"`
			IsReal           bool     `json:"is_real"`
			Confidence       float64  `json:"confidence"`
			Severity         string   `json:"severity"`
			CWE              string   `json:"cwe"`
			Title            string   `json:"title"`
			Description      string   `json:"description"`
			FixHint          string   `json:"fix_hint"`
			Refutation       string   `json:"refutation"`
			RefutationPoints []string `json:"refutation_points"`
		} `json:"findings"`
	}

	maxTokens := 2048 + len(traces)*512
	err := client.ChatJSONWithMaxTokens(ctx, SystemPromptVerify, prompt, &response, maxTokens)
	if err != nil {
		return nil, err
	}

	var verified []VerifiedFinding
	for _, r := range response.Findings {
		if r.Index < 0 || r.Index >= len(traces) {
			continue
		}
		tr := traces[r.Index]
		if !r.IsReal || r.Confidence < 0.7 {
			log.Printf("[AI VERIFY] %s:%d %s() — REJECTED: %s (confidence=%.2f)",
				tr.Section.FilePath, tr.Section.LineStart, tr.Section.FuncName,
				r.Refutation, r.Confidence)
			continue
		}
		log.Printf("[AI VERIFY] %s:%d %s() — CONFIRMED: %s (confidence=%.2f)",
			tr.Section.FilePath, tr.Section.LineStart, tr.Section.FuncName,
			r.Title, r.Confidence)
		verified = append(verified, VerifiedFinding{
			Trace: tr, IsReal: true, Confidence: r.Confidence,
			Severity: r.Severity, CWE: r.CWE,
			Title: r.Title, Description: r.Description,
			FixHint: r.FixHint, Refutation: r.Refutation,
		})
	}
	return verified, nil
}

func batchVerifyTraces(traces []TraceResult, batchSize int) [][]TraceResult {
	var batches [][]TraceResult
	for i := 0; i < len(traces); i += batchSize {
		end := i + batchSize
		if end > len(traces) {
			end = len(traces)
		}
		batches = append(batches, traces[i:end])
	}
	return batches
}

func (e *Engine) verifyOne(ctx context.Context, client *Client, tr TraceResult) (*VerifiedFinding, error) {
	prompt := fmt.Sprintf(PromptVerify, buildVerifySummary(tr))
	var response struct {
		IsReal           bool     `json:"is_real"`
		Confidence       float64  `json:"confidence"`
		Severity         string   `json:"severity"`
		CWE              string   `json:"cwe"`
		Title            string   `json:"title"`
		Description      string   `json:"description"`
		FixHint          string   `json:"fix_hint"`
		Refutation       string   `json:"refutation"`
		RefutationPoints []string `json:"refutation_points"`
	}
	err := client.ChatJSONWithMaxTokens(ctx, SystemPromptVerify, prompt, &response, 1024)
	if err != nil {
		return nil, err
	}
	if !response.IsReal || response.Confidence < 0.7 {
		log.Printf("[AI VERIFY] %s:%d %s() — REJECTED: %s (confidence=%.2f)",
			tr.Section.FilePath, tr.Section.LineStart, tr.Section.FuncName,
			response.Refutation, response.Confidence)
		return nil, nil
	}
	log.Printf("[AI VERIFY] %s:%d %s() — CONFIRMED: %s (confidence=%.2f)",
		tr.Section.FilePath, tr.Section.LineStart, tr.Section.FuncName,
		response.Title, response.Confidence)
	return &VerifiedFinding{
		Trace: tr, IsReal: true, Confidence: response.Confidence,
		Severity: response.Severity, CWE: response.CWE,
		Title: response.Title, Description: response.Description,
		FixHint: response.FixHint, Refutation: response.Refutation,
	}, nil
}

func buildVerifySummary(tr TraceResult) string {
	var sb strings.Builder
	sb.WriteString("### AI-Discovered Potential Vulnerability\n\n")
	sb.WriteString(fmt.Sprintf("**Function:** %s\n", tr.Section.FuncName))
	sb.WriteString(fmt.Sprintf("**File:** %s:%d-%d\n", tr.Section.FilePath, tr.Section.LineStart, tr.Section.LineEnd))
	sb.WriteString(fmt.Sprintf("**Input Source:** %s\n", tr.InputSource))
	sb.WriteString(fmt.Sprintf("**Sink:** %s\n", tr.Sink))
	sb.WriteString(fmt.Sprintf("**Data Flow Path:** %s\n", tr.Path))
	sb.WriteString(fmt.Sprintf("**Missing Auth:** %v | **Missing Validation:** %v\n", tr.MissingAuth, tr.MissingValidation))
	sb.WriteString(fmt.Sprintf("**Trace Confidence:** %.2f | **Suggested CWE:** %s\n\n", tr.Confidence, tr.CWESuggested))
	sb.WriteString(fmt.Sprintf("**Code:**\n```go\n%s\n```\n", tr.Section.CodeSnippet))
	return sb.String()
}

// ─── Phase B.4: Full Pipeline ───────────────────────────────────────────────

type DeepAnalysisResult struct {
	Observe      *ObserveResult    `json:"observe"`
	Traces       []TraceResult     `json:"traces"`
	Verified     []VerifiedFinding `json:"verified"`
	MissingCtrls []MissingControl  `json:"missing_controls"`
	ConfigIssues []ConfigIssue     `json:"config_issues"`
	Errors       []string          `json:"errors,omitempty"`
	Cost         string            `json:"cost"`
}

func (e *Engine) AnalyzeDeep(ctx context.Context, target string) (*DeepAnalysisResult, error) {
	result := &DeepAnalysisResult{}

	obsResult, err := e.Observe(target)
	if err != nil {
		return nil, fmt.Errorf("OBSERVE: %w", err)
	}
	result.Observe = obsResult
	log.Printf("[Phase B] OBSERVE: %d files → %d sections", obsResult.TotalFiles, obsResult.TotalSections)
	if obsResult.TotalSections == 0 {
		return result, nil
	}

	priorityCount := min(obsResult.TotalSections, 50)
	sections := obsResult.PrioritySections(priorityCount)
	handlers := obsResult.HandlerSections()

	// Phase 2a: TRACE data flow (with call graph cross-file chains if available)
	log.Printf("[Phase B] TRACE: analyzing %d sections for data flow", len(sections))
	var taintChains []observe.TaintChain
	if obsResult.CallGraph != nil {
		taintChains = obsResult.CallGraph.WalkTaintFromEntryPoints(3) // max 3 hops
		log.Printf("[Phase B] CallGraph: %d entry points → %d validated taint chains",
			len(obsResult.CallGraph.FindEntryPoints()), len(taintChains))
	} else {
		log.Printf("[Phase B] CallGraph: nil (Python project or build error) — cross-file tracing disabled")
	}
	if traces, err := e.Trace(ctx, sections, taintChains); err == nil {
		result.Traces = traces
		log.Printf("[Phase B] TRACE: %d data flow traces", len(traces))
		if len(traces) > 0 {
			if verified, verr := e.VerifyTraces(ctx, traces); verr == nil {
				result.Verified = verified
				log.Printf("[Phase B] VERIFY: %d confirmed data-flow vulns", len(verified))
			} else {
				result.Errors = append(result.Errors, "VERIFY: "+verr.Error())
			}
		}
	} else {
		result.Errors = append(result.Errors, "TRACE: "+err.Error())
	}

	// Phase 2b: TRACE-MISSING
	if len(handlers) > 0 {
		log.Printf("[Phase B] MISSING: analyzing %d handlers for missing controls", len(handlers))
		if missing, err := e.TraceMissing(ctx, handlers); err == nil {
			result.MissingCtrls = missing
			log.Printf("[Phase B] MISSING: %d missing security controls found", len(missing))
		} else {
			result.Errors = append(result.Errors, "MISSING: "+err.Error())
		}
	}

	// Phase 2c: TRACE-CONFIG
	log.Printf("[Phase B] CONFIG: analyzing %d sections for config issues", len(sections))
	if configIssues, err := e.TraceConfig(ctx, sections); err == nil {
		result.ConfigIssues = configIssues
		log.Printf("[Phase B] CONFIG: %d config issues found", len(configIssues))
	} else {
		result.Errors = append(result.Errors, "CONFIG: "+err.Error())
	}

	result.Cost = e.CostSummary()
	return result, nil
}

func (e *Engine) ConvertToFindings(verified []VerifiedFinding) []report.Finding {
	var findings []report.Finding
	for i, vf := range verified {
		sev := parseSeverity(vf.Severity)
		if sev == report.SevInfo {
			sev = report.SevMedium
		}
		findings = append(findings, report.Finding{
			ID:            fmt.Sprintf("IRON-AI-%03d", i+1),
			Title:         vf.Title,
			Description:   vf.Description,
			Severity:      sev,
			FilePath:      vf.Trace.Section.FilePath,
			LineNumber:    vf.Trace.Section.LineStart,
			CodeSnippet:   vf.Trace.Section.CodeSnippet,
			Category:      safeConcernCategory(vf.Trace.Section.Concerns),
			AIConfidence:  vf.Confidence,
			FixSuggestion: vf.FixHint,
			CWE:           vf.CWE,
			CVSS:          report.SeverityToCVSS(sev),
		})
	}
	return findings
}

func safeConcernCategory(concerns []observe.ConcernType) string {
	if len(concerns) > 0 {
		return string(concerns[0])
	}
	return "ai-discovered"
}

// ─── Dedup ──────────────────────────────────────────────────────────────────

func DeduplicatePhaseB(phaseBFindings []report.Finding, sastFindings []report.Finding) []report.Finding {
	type location struct {
		path string
		line int
	}
	sastLocs := make(map[location]bool)
	for _, f := range sastFindings {
		p := strings.ReplaceAll(f.FilePath, `\`, "/")
		sastLocs[location{p, f.LineNumber}] = true
	}

	var unique []report.Finding
	removed := 0
	for _, f := range phaseBFindings {
		if strings.HasPrefix(f.Category, "missing-") || strings.HasPrefix(f.Category, "config-") {
			unique = append(unique, f)
			continue
		}
		p := strings.ReplaceAll(f.FilePath, `\`, "/")
		isDup := false
		for offset := -3; offset <= 3; offset++ {
			if sastLocs[location{p, f.LineNumber + offset}] {
				isDup = true
				break
			}
		}
		if isDup {
			removed++
			continue
		}
		unique = append(unique, f)
	}
	if removed > 0 {
		log.Printf("[Dedup] %d Phase B → %d unique (removed %d SAST overlaps)",
			len(phaseBFindings), len(unique), removed)
	}
	return unique
}

// deduplicateMissingControls merges same-handler findings into one per handler.
// If handler has rate_limit + csrf + auth missing, produces 1 merged finding instead of 3.
func deduplicateMissingControls(controls []MissingControl) []MissingControl {
	if len(controls) <= 1 {
		return controls
	}
	type group struct {
		section  ObservedSection
		controls []MissingControl
		maxSev   string
	}
	groups := make(map[string]*group)
	var order []string
	for _, mc := range controls {
		key := fmt.Sprintf("%s:%s:%d", mc.Section.FilePath, mc.Section.FuncName, mc.Section.LineStart)
		if g, ok := groups[key]; ok {
			g.controls = append(g.controls, mc)
			if severityWeight(mc.Severity) > severityWeight(g.maxSev) {
				g.maxSev = mc.Severity
			}
		} else {
			groups[key] = &group{section: mc.Section, controls: []MissingControl{mc}, maxSev: mc.Severity}
			order = append(order, key)
		}
	}
	var merged []MissingControl
	for _, key := range order {
		g := groups[key]
		if len(g.controls) <= 1 {
			merged = append(merged, g.controls[0])
			continue
		}
		var types, descs, fixes []string
		for _, mc := range g.controls {
			types = append(types, mc.ControlType)
			descs = append(descs, mc.Description)
			if mc.FixHint != "" {
				fixes = append(fixes, mc.FixHint)
			}
		}
		merged = append(merged, MissingControl{
			Section:     g.section,
			ControlType: strings.Join(types, "+"),
			IsMissing:   true,
			Confidence:  g.controls[0].Confidence,
			Severity:    g.maxSev,
			Title:       fmt.Sprintf("Missing %d security controls in %s", len(g.controls), g.section.FuncName),
			Description: fmt.Sprintf("Handler %s is missing %d controls: %s. %s",
				g.section.FuncName, len(g.controls), strings.Join(types, ", "), strings.Join(descs, " ")),
			FixHint: strings.Join(fixes, "; "),
			CWE:     "CWE-16",
		})
	}
	return merged
}


// filterMissingControls removes low-value MISSING findings to reduce noise.
// Rules:
//  1. Drop LOW severity (not actionable)
//  2. Drop rate_limiting on health/read-only endpoints
//  3. Drop CSRF on GET-only handlers (no state change)
//  4. Drop content_type validation on GET handlers (no request body)
func filterMissingControls(controls []MissingControl) []MissingControl {
	var filtered []MissingControl
	for _, mc := range controls {
		sev := strings.ToUpper(mc.Severity)
		if sev == "LOW" || sev == "INFO" {
			continue // Rule 1: LOW severity = noise
		}
		fn := strings.ToLower(mc.Section.FuncName)
		ct := strings.ToLower(mc.ControlType)
		// Rule 2: rate limiting on utility endpoints
		if strings.Contains(ct, "rate_limit") && (strings.Contains(fn, "health") || strings.Contains(fn, "ping") || strings.Contains(fn, "index") || strings.Contains(fn, "status") || strings.Contains(fn, "ready")) {
			continue
		}
		// Rule 3: CSRF on GET-only handlers (no state change)
		if strings.Contains(ct, "csrf") && (strings.HasPrefix(fn, "get") || strings.HasPrefix(fn, "list") || strings.HasPrefix(fn, "show") || strings.HasPrefix(fn, "view")) {
			continue
		}
		// Rule 4: content_type on GET handlers
		if strings.Contains(ct, "content_type") && (strings.HasPrefix(fn, "get") || strings.HasPrefix(fn, "list")) {
			continue
		}
		filtered = append(filtered, mc)
	}
	return filtered
}

func severityWeight(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL": return 4
	case "HIGH": return 3
	case "MEDIUM": return 2
	case "LOW": return 1
	default: return 0
	}
}
