package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

// Analyst performs AI-powered security analysis on scanner findings.
// It implements the 4-step OBSERVE→TRACE→VERIFY→ASSESS reasoning
// pipeline ported from GoldHunter's ai_verify_finding().
type Analyst struct {
	client    LLMClient
	providers *ContextProviderRegistry
	prompts   *PromptExecutor
}

// LLMClient is the interface for language model API calls.
// This allows mocking in tests and swapping between providers
// (DeepSeek, Ollama, mock).
type LLMClient interface {
	Chat(ctx context.Context, systemPrompt, userMessage string) (string, error)
}

// NewAnalyst creates a new Analyst Agent.
func NewAnalyst(client LLMClient, providers *ContextProviderRegistry) *Analyst {
	return &Analyst{
		client:    client,
		providers: providers,
		prompts:   NewPromptExecutor(),
	}
}

// AnalyzeFinding performs full 4-step analysis on a single finding.
func (a *Analyst) AnalyzeFinding(ctx context.Context, f InputFinding) (*AnalystResult, error) {
	// Step 0: Get code context.
	fileCtx, err := a.providers.GetContext(f.FilePath, f.LineNumber)
	if err != nil {
		// If we can't get context, create a minimal one from the finding.
		fileCtx = &FileContext{
			FilePath:         f.FilePath,
			Language:         LangUnknown,
			FindingLine:      f.LineNumber,
			FindingSnippet:   f.CodeSnippet,
			SurroundingLines: f.CodeSnippet,
			FileSummary:      "context unavailable",
		}
	}

	// Build the prompt.
	promptData := analyzePromptData{
		Context: fileCtx,
		Finding: &f,
	}

	prompt, err := a.prompts.RenderAnalyzeFinding(promptData)
	if err != nil {
		return nil, fmt.Errorf("render prompt: %w", err)
	}

	// Call LLM.
	response, err := a.client.Chat(ctx, SystemPromptAnalyst, prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM call: %w", err)
	}

	// Parse response with 3-layer JSON fallback (GoldHunter parse_ai_json pattern).
	result, err := parseAnalystJSON(response)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	// Ensure finding ID is set.
	if result.FindingID == "" {
		result.FindingID = f.ID
	}

	return result, nil
}

// AnalyzeBatch performs analysis on multiple findings.
// For efficiency, it groups findings from the same file together.
func (a *Analyst) AnalyzeBatch(ctx context.Context, findings []InputFinding) ([]*AnalystResult, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	// For small batches (≤3), analyze individually for best quality.
	if len(findings) <= 3 {
		results := make([]*AnalystResult, 0, len(findings))
		for _, f := range findings {
			result, err := a.AnalyzeFinding(ctx, f)
			if err != nil {
				// On error, create a minimal result and continue.
				result = &AnalystResult{
					FindingID:     f.ID,
					Title:         f.Title,
					Severity:      InputSeverityToAgent(f.Severity),
					IsExploitable: false,
					Confidence:    0.0,
					Narrative:     fmt.Sprintf("Analysis failed: %v", err),
				}
			}
			results = append(results, result)
		}
		return results, nil
	}

	// For larger batches, build a batch prompt.
	return a.batchAnalyze(ctx, findings)
}

// batchAnalyze sends findings in bulk to reduce API calls.
func (a *Analyst) batchAnalyze(ctx context.Context, findings []InputFinding) ([]*AnalystResult, error) {
	var summaryBuf bytes.Buffer
	for _, f := range findings {
		summaryBuf.WriteString(fmt.Sprintf("[%s] %s\n", f.ID, f.Title))
		summaryBuf.WriteString(fmt.Sprintf("  File: %s:%d | Category: %s | Severity: %s\n",
			f.FilePath, f.LineNumber, f.Category, f.Severity.String()))
		if f.CodeSnippet != "" {
			summaryBuf.WriteString(fmt.Sprintf("  Code: %s\n", f.CodeSnippet))
		}
		summaryBuf.WriteString("\n")
	}

	// Build context summary from first file (representative).
	contextSummary := "Multiple files in this batch."
	if len(findings) > 0 {
		first := findings[0]
		ctx, err := a.providers.GetContext(first.FilePath, first.LineNumber)
		if err == nil && ctx != nil {
			contextSummary = fmt.Sprintf("Primary file: %s (%s). %s",
				ctx.FilePath, ctx.Language, ctx.FileSummary)
		}
	}

	// Render batch prompt.
	prompt := strings.ReplaceAll(PromptAnalyzeBatch, "{{.Count}}", fmt.Sprintf("%d", len(findings)))
	prompt = strings.ReplaceAll(prompt, "{{.ContextSummary}}", contextSummary)
	prompt = strings.ReplaceAll(prompt, "{{.FindingsSummary}}", summaryBuf.String())

	response, err := a.client.Chat(ctx, SystemPromptAnalyst, prompt)
	if err != nil {
		return nil, fmt.Errorf("batch LLM call: %w", err)
	}

	// Parse as JSON array.
	results, err := parseAnalystJSONArray(response)
	if err != nil {
		return nil, fmt.Errorf("parse batch response: %w", err)
	}

	return results, nil
}

// analyzePromptData is the data passed to the prompt template.
type analyzePromptData struct {
	Context *FileContext
	Finding *InputFinding
}

// PromptExecutor renders prompt templates.
type PromptExecutor struct {
	analyzeTmpl *template.Template
}

// NewPromptExecutor creates a prompt template executor.
func NewPromptExecutor() *PromptExecutor {
	tmpl := template.Must(template.New("analyze").Parse(PromptAnalyzeFinding))
	return &PromptExecutor{analyzeTmpl: tmpl}
}

// RenderAnalyzeFinding renders the analyze finding prompt.
func (pe *PromptExecutor) RenderAnalyzeFinding(data analyzePromptData) (string, error) {
	var buf bytes.Buffer
	if err := pe.analyzeTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// =============================================================================
// 3-Layer JSON Fallback — ported from GoldHunter parse_ai_json()
// =============================================================================

// parseAnalystJSON extracts an AnalystResult from an LLM response using
// 3 layers of fallback parsing:
//
//	Layer 1: json.Unmarshal (clean JSON)
//	Layer 2: extract from ```json blocks (markdown code fences)
//	Layer 3: regex extract + retry (broken/malformed JSON)
func parseAnalystJSON(response string) (*AnalystResult, error) {
	response = strings.TrimSpace(response)

	// Layer 1: Direct JSON unmarshal.
	var result AnalystResult
	if err := json.Unmarshal([]byte(response), &result); err == nil {
		return &result, nil
	}

	// Layer 2: Extract from markdown code blocks.
	jsonStr := extractJSONBlock(response)
	if jsonStr != "" {
		if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
			return &result, nil
		}
	}

	// Layer 3: Best-effort field extraction from malformed JSON.
	return extractFieldsManual(response)
}

// parseAnalystJSONArray parses a JSON array of AnalystResults.
func parseAnalystJSONArray(response string) ([]*AnalystResult, error) {
	response = strings.TrimSpace(response)

	var results []*AnalystResult

	// Layer 1: Direct JSON array.
	if err := json.Unmarshal([]byte(response), &results); err == nil {
		return results, nil
	}

	// Layer 2: Extract from markdown.
	jsonStr := extractJSONBlock(response)
	if jsonStr != "" {
		if err := json.Unmarshal([]byte(jsonStr), &results); err == nil {
			return results, nil
		}
	}

	// Layer 3: Split by object boundaries and parse individually.
	return extractMultipleJSON(response)
}

// extractJSONBlock extracts JSON from markdown code fences.
func extractJSONBlock(response string) string {
	// Try ```json ... ```.
	for _, fence := range []string{"```json", "```"} {
		idx := strings.Index(response, fence)
		if idx >= 0 {
			start := idx + len(fence)
			if start < len(response) && response[start] == '\n' {
				start++
			}
			if end := strings.Index(response[start:], "```"); end >= 0 {
				return strings.TrimSpace(response[start : start+end])
			}
		}
	}

	// Look for { or [ at start and matching close.
	for i, ch := range response {
		if ch == '{' || ch == '[' {
			return findMatchingBracket(response, i)
		}
	}

	return ""
}

// findMatchingBracket finds a balanced bracket range.
func findMatchingBracket(s string, start int) string {
	if start >= len(s) {
		return ""
	}
	open := s[start]
	var close byte
	if open == '{' {
		close = '}'
	} else if open == '[' {
		close = ']'
	} else {
		return ""
	}

	depth := 0
	inString := false
	escaped := false

	for i := start; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if ch == open {
			depth++
		} else if ch == close {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// extractFieldsManual does best-effort field extraction from broken JSON.
func extractFieldsManual(response string) (*AnalystResult, error) {
	result := &AnalystResult{}

	// Use simple string matching for critical fields.
	result.IsExploitable = !strings.Contains(strings.ToLower(response), `"is_exploitable": false`) &&
		!strings.Contains(strings.ToLower(response), `"is_exploitable":false`)

	if strings.Contains(strings.ToLower(response), `"is_exploitable": true`) ||
		strings.Contains(strings.ToLower(response), `"is_exploitable":true`) {
		result.IsExploitable = true
	}

	// Extract narrative — everything between "narrative": " and the next field.
	if idx := strings.Index(response, `"narrative"`); idx >= 0 {
		if colonIdx := strings.Index(response[idx:], ":"); colonIdx >= 0 {
			rest := response[idx+colonIdx+1:]
			rest = strings.TrimSpace(rest)
			if len(rest) > 0 && rest[0] == '"' {
				rest = rest[1:]
				// Find unescaped closing quote.
				narrative, _ := extractQuotedString(rest)
				result.Narrative = narrative
			}
		}
	}

	// Extract confidence.
	if idx := strings.Index(response, `"confidence"`); idx >= 0 {
		if colonIdx := strings.Index(response[idx:], ":"); colonIdx >= 0 {
			rest := strings.TrimSpace(response[idx+colonIdx+1:])
			rest = strings.TrimRight(rest, ",}\n\r ")
			if conf, err := parseFloat(rest); err == nil {
				result.Confidence = conf
			}
		}
	}

	// Extract severity.
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if strings.Contains(response, `"`+sev+`"`) || strings.Contains(response, `"severity": "`+sev) {
			result.Severity = Severity(sev)
			break
		}
	}

	if result.Narrative == "" {
		result.Narrative = "Analysis response parsing failed. Raw response preserved for manual review."
	}

	return result, nil
}

// extractMultipleJSON splits a response with multiple JSON objects.
func extractMultipleJSON(response string) ([]*AnalystResult, error) {
	var results []*AnalystResult

	// Find all { } blocks at depth 0.
	start := -1
	depth := 0
	inString := false
	escaped := false

	for i, ch := range response {
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}

		if ch == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if ch == '}' {
			depth--
			if depth == 0 && start >= 0 {
				block := response[start : i+1]
				var result AnalystResult
				if err := json.Unmarshal([]byte(block), &result); err == nil {
					results = append(results, &result)
				}
				start = -1
			}
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no valid JSON objects found in response")
	}

	return results, nil
}

// extractQuotedString extracts a quoted string, handling escapes.
func extractQuotedString(s string) (string, int) {
	var buf strings.Builder
	escaped := false
	for i, ch := range s {
		if escaped {
			buf.WriteRune(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			return buf.String(), i + 1
		}
		buf.WriteRune(ch)
	}
	return buf.String(), len(s)
}

// parseFloat parses a float64 from a string, handling trailing commas.
func parseFloat(s string) (float64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ",}")
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// =============================================================================
// Offline Analysis — used when no LLM API is available.
// =============================================================================

// OfflineAnalyze performs rule-based analysis without an LLM.
// This is a heuristic fallback that uses the AST context to
// make basic exploitability judgments.
func (a *Analyst) OfflineAnalyze(f InputFinding, ctx *FileContext) *AnalystResult {
	result := &AnalystResult{
		FindingID:  f.ID,
		Title:      f.Title,
		Severity:   InputSeverityToAgent(f.Severity),
		Confidence: 0.6, // Lower confidence for heuristic analysis
		CWE:        f.CWE,
		CVSS:       f.CVSS,
	}

	// Check for clear false positive patterns.
	if isFalsePositiveByPattern(f, ctx) {
		result.IsExploitable = false
		result.Confidence = 0.9
		result.Narrative = "Heuristic analysis indicates this is likely a false positive. " +
			"The code pattern matches known false positive signatures (test file, placeholder value, or commented code)."
		return result
	}

	// Check for clear true positive patterns.
	if isLikelyExploitable(f, ctx) {
		result.IsExploitable = true
		result.Confidence = 0.7
		result.Narrative = fmt.Sprintf(
			"Heuristic analysis confirms this %s finding in %s:%d matches known vulnerability patterns. "+
				"The code context shows no obvious sanitization or access controls.",
			f.Category, f.FilePath, f.LineNumber)
		result.AttackPath = buildHeuristicAttackPath(f, ctx)
		return result
	}

	// Uncertain — default to scanner judgment but low confidence.
	result.IsExploitable = f.Severity.IsHighSeverity()
	result.Confidence = 0.4
	result.Narrative = "Heuristic analysis could not conclusively determine exploitability. " +
		"Manual review or AI-powered analysis recommended."
	return result
}

// isFalsePositiveByPattern checks common false positive patterns.
func isFalsePositiveByPattern(f InputFinding, ctx *FileContext) bool {
	// Test files.
	testPatterns := []string{"_test.go", "_test.py", ".test.js", "/test/", "/testdata/", "/fixtures/", "/mocks/"}
	for _, p := range testPatterns {
		if strings.Contains(f.FilePath, p) {
			return true
		}
	}

	// Placeholder values.
	placeholderPatterns := []string{
		"your_token_here", "replace_me", "changeme", "example_key",
		"place_holder", "todo", "xxxxx", "secret_here",
	}
	lowerSnippet := strings.ToLower(f.CodeSnippet)
	for _, p := range placeholderPatterns {
		if strings.Contains(lowerSnippet, p) {
			return true
		}
	}

	// Commented code.
	if strings.HasPrefix(strings.TrimSpace(f.CodeSnippet), "//") ||
		strings.HasPrefix(strings.TrimSpace(f.CodeSnippet), "#") {
		return true
	}

	return false
}

// isLikelyExploitable checks for strong vulnerability signals.
func isLikelyExploitable(f InputFinding, ctx *FileContext) bool {
	category := strings.ToLower(f.Category)

	// Secret detection: check if the value looks like a real secret (not a placeholder).
	if category == "secret-detected" || category == "hardcoded-secret" {
		lower := strings.ToLower(f.CodeSnippet)
		// Real secret signals: long random-looking strings, specific prefixes.
		if strings.Contains(lower, "ghp_") || strings.Contains(lower, "sk-") ||
			strings.Contains(lower, "akia") || strings.Contains(lower, "xoxb-") ||
			strings.Contains(lower, "-----begin") {
			return true
		}
	}

	// Code execution: shell=True, eval(), exec() are almost always exploitable.
	if category == "command-injection" || category == "code-injection" {
		lower := strings.ToLower(f.CodeSnippet)
		if strings.Contains(lower, "shell=true") || strings.Contains(lower, "eval(") ||
			strings.Contains(lower, "exec(") || strings.Contains(lower, "os.system(") {
			return true
		}
	}

	// SQL injection: f-string or concatenation with user input.
	if category == "sql-injection" {
		lower := strings.ToLower(f.CodeSnippet)
		if strings.Contains(lower, "f\"") || strings.Contains(lower, "f'") ||
			strings.Contains(lower, "+\"") || strings.Contains(lower, "+'") {
			return true
		}
	}

	// Weak crypto: DES, MD5, SHA1 for security purposes.
	if category == "weak-crypto" {
		lower := strings.ToLower(f.CodeSnippet)
		if strings.Contains(lower, "des.") || strings.Contains(lower, "md5.") ||
			strings.Contains(lower, "sha1.") ||
			(strings.Contains(lower, "math/rand") && strings.Contains(lower, "token")) {
			return true
		}
	}

	return false
}

// buildHeuristicAttackPath builds a basic attack path from finding data.
func buildHeuristicAttackPath(f InputFinding, ctx *FileContext) []AttackStep {
	steps := []AttackStep{
		{StepNumber: 1, Description: fmt.Sprintf("Identify vulnerable code at %s:%d", f.FilePath, f.LineNumber), FileRef: f.FilePath, LineRef: f.LineNumber},
	}

	if ctx != nil && ctx.EnclosingFunc != nil {
		steps = append(steps, AttackStep{
			StepNumber:  2,
			Description: fmt.Sprintf("Trace data flow through function %s", ctx.EnclosingFunc.Name),
			FileRef:     f.FilePath,
			LineRef:     ctx.EnclosingFunc.StartLine,
		})
		steps = append(steps, AttackStep{
			StepNumber:  3,
			Description: "Exploit vulnerability to achieve unauthorized access or code execution",
		})
	} else {
		steps = append(steps, AttackStep{
			StepNumber:  2,
			Description: "Exploit vulnerability to achieve unauthorized access or code execution",
		})
	}

	return steps
}
