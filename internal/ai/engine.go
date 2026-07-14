package ai

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/FYFran/ironwall/internal/report"
)

const aiBatchSize = 20      // per API call (balanced: prompt fits, response under max_tokens)
const batchInterval = 2000 * time.Millisecond // pause between batches (DeepSeek rate limit: 60 RPM)
const maxConcurrency = 2   // max concurrent API calls (conservative for chat model)

// Engine orchestrates multi-stage AI analysis for security findings.
type Engine struct {
	triageClient *Client // Fast model (DeepSeek V3 / deepseek-chat) — used as fallback for deep verify
	deepClient   *Client // Reasoning model (DeepSeek R1 / deepseek-reasoner)
	hasPython    bool    // Target contains Python files (enables Flask-specific FP rules)
	hasGo        bool    // Target contains Go files
}

// SetLanguages configures target language hints for conditional prompt rules.
// Call before Analyze() to avoid wasted tokens on irrelevant framework rules.
func (e *Engine) SetLanguages(hasGo, hasPython bool) {
	e.hasGo = hasGo
	e.hasPython = hasPython
}

// NewEngine creates a new multi-stage AI engine.
// triageClient: fast model, used as fallback when deepClient is unavailable
// deepClient: reasoning model for adversarial verification
// Either can be nil — the engine degrades gracefully.
func NewEngine(triageClient, deepClient *Client) *Engine {
	return &Engine{
		triageClient: triageClient,
		deepClient:   deepClient,
	}
}

// CostSummary returns a human-readable cost summary of all AI calls.
func (e *Engine) CostSummary() string {
	parts := []string{}
	if e.triageClient != nil && e.triageClient.Cost.Calls > 0 {
		parts = append(parts, "triage: "+e.triageClient.Cost.Summary(e.triageClient.model))
	}
	if e.deepClient != nil && e.deepClient.Cost.Calls > 0 {
		parts = append(parts, "deep: "+e.deepClient.Cost.Summary(e.deepClient.model))
	}
	if len(parts) == 0 {
		return "no AI calls"
	}
	return strings.Join(parts, ", ")
}

// Available returns true if at least one AI client is configured.
func (e *Engine) Available() bool {
	return (e.triageClient != nil && e.triageClient.Available()) ||
		(e.deepClient != nil && e.deepClient.Available())
}

// AnalysisStatus summarizes the AI analysis outcome.
type AnalysisStatus struct {
	Status        string // "full", "partial", "skipped", "error"
	TriageRuns    int    // number of triage batches attempted
	TriageErrors  int    // number of triage batch failures
	DeepRuns      int    // number of deep verify batches attempted
	DeepErrors    int    // number of deep verify batch failures
	FindingsAnalyzed int // total findings sent to AI
	FindingsFiltered int // findings downgraded by AI
}

// Analyze runs the full multi-stage analysis on a batch of findings.
// Returns findings with updated severity, AI confidence, and attack scenarios,
// along with the analysis status.
func (e *Engine) Analyze(ctx context.Context, findings []report.Finding) ([]report.Finding, AnalysisStatus) {
	status := AnalysisStatus{Status: "skipped"}
	if len(findings) == 0 || !e.Available() {
		return findings, status
	}

	status.Status = "full"

	// Single-stage: DeepVerify handles everything (FP detection + adversarial verification)
	// Triage is skipped — same model, adds complexity without value
	var verified []report.Finding
	var deepStatus AnalysisStatus
	client := e.deepClient
	if client == nil || !client.Available() {
		client = e.triageClient
	}
	if client != nil && client.Available() {
		verified, deepStatus = e.runDeepVerifyWithClient(ctx, findings, client)
	} else {
		verified = findings
		status.Status = "skipped"
	}
	// Merge deep verify status
	status.DeepRuns = deepStatus.DeepRuns
	status.DeepErrors = deepStatus.DeepErrors
	if deepStatus.Status == "partial" {
		status.Status = "partial"
	}

	return verified, status
}

// batchFindings splits findings into batches of at most batchSize.
func batchFindings(findings []report.Finding, batchSize int) [][]report.Finding {
	var batches [][]report.Finding
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		batches = append(batches, findings[i:end])
	}
	return batches
}

// runDeepVerifyWithClient runs deep verification using the specified client in batches.
func (e *Engine) runDeepVerifyWithClient(ctx context.Context, findings []report.Finding, client *Client) ([]report.Finding, AnalysisStatus) {
	status := AnalysisStatus{}
	var reviewList []report.Finding
	var passThrough []report.Finding
	for _, f := range findings {
		// Skip DeepVerify for MISSING detection findings — these are structural absences,
		// not SAST false positives. AI models (especially DeepSeek) over-suppress these
		// because they're trained to "challenge every finding."
		if strings.HasPrefix(f.Category, "missing-") {
			passThrough = append(passThrough, f)
			continue
		}
		if f.Severity <= report.SevMedium && f.AIConfidence == 0 {
			reviewList = append(reviewList, f)
		} else {
			passThrough = append(passThrough, f)
		}
	}

	if len(reviewList) == 0 {
		log.Printf("[AI DeepVerify] no findings to review (checked %d: %d passed severity filter, %d had AIConfidence>0)",
			len(findings), countBySeverity(findings, report.SevMedium), countWithAIConfidence(findings))
		return findings, status
	}

	batches := batchFindings(reviewList, aiBatchSize)
	status.DeepRuns = len(batches)
	log.Printf("[AI DeepVerify] reviewing %d findings in %d batches", len(reviewList), len(batches))

	for batchIdx, batch := range batches {
		if batchIdx > 0 {
			time.Sleep(batchInterval)
		}
		summary := buildFindingSummary(batch)
		prompt := fmt.Sprintf(PromptDeepVerifyBatch, summary)

		var result DeepVerifyResult
		// Dynamic max_tokens: 256 base + 200 per finding in batch (batch of 20 ≈ 4256 tokens)
		batchMaxTokens := 256 + len(batch) * 200
		err := client.ChatJSONWithMaxTokens(ctx, DeepVerifyPrompt(e.hasPython), prompt, &result, batchMaxTokens)
		if err != nil {
			log.Printf("[AI DeepVerify] batch %d/%d failed (%d findings): %v", batchIdx+1, len(batches), len(batch), err)
			status.DeepErrors++
			e.verifyBatchOneByOne(ctx, batch)
			continue
		}

		verifyMap := make(map[string]DeepVerifyVerdict)
		for _, dv := range result.Findings {
			verifyMap[strings.TrimSpace(dv.ID)] = dv
		}
		verified := 0
		for i := range batch {
			f := &batch[i]
			key := findingKey(f)
			dv, ok := verifyMap[key]
			if !ok {
				continue
			}
			f.AttackScenario = &report.AttackTest{
				Actor:       dv.Actor,
				Path:        dv.Path,
				Impact:      dv.Impact,
				IsReal:      dv.IsReal,
				Explanation: dv.Explanation,
			}
			f.AIConfidence = dv.Confidence
			if !dv.IsReal && dv.Confidence >= 0.7 {
				f.Severity = report.SevInfo
				f.Description += fmt.Sprintf("\n[AI Deep Verify: Attack scenario not viable — %s]", dv.Explanation)
				verified++
			}
		}
		if verified > 0 {
			log.Printf("[AI DeepVerify] batch %d/%d: %d suppressed (%d findings)", batchIdx+1, len(batches), verified, len(batch))
		}
	}

	if status.DeepErrors > 0 {
		status.Status = "partial"
	} else {
		status.Status = "full"
	}
	return append(reviewList, passThrough...), status
}

// verifyBatchOneByOne verifies findings individually when batch DeepVerify fails.
// Uses same SystemPromptDeepVerify as batch path for consistency.
// Same suppression threshold: !IsReal && Confidence >= 0.7.
// AttackTestResult fields map 1:1 to DeepVerifyVerdict fields.
func (e *Engine) verifyBatchOneByOne(ctx context.Context, batch []report.Finding) {
	client := e.deepClient
	if client == nil || !client.Available() {
		client = e.triageClient
	}
	if client == nil {
		return
	}
	var successCount, failCount int
	for i := range batch {
		f := &batch[i]
		key := findingKey(f)
		findingDesc := fmt.Sprintf(
			"Title: %s\nFile: %s:%d\nCategory: %s\nCode:\n%s\nDescription: %s",
			f.Title, f.FilePath, f.LineNumber, f.Category, f.CodeSnippet, f.Description,
		)
		prompt := fmt.Sprintf(PromptAttackScenario, findingDesc)

		var result AttackTestResult
		err := client.ChatJSON(ctx, DeepVerifyPrompt(e.hasPython), prompt, &result)
		if err != nil {
			log.Printf("[AI DeepVerify] one-by-one %s FAILED: %v", key, err)
			failCount++
			continue
		}

		// Detect zero-value responses (API OK but AI produced no meaningful output)
		if result.Confidence == 0 && !result.IsReal && result.Actor == "" {
			log.Printf("[AI DeepVerify] one-by-one %s returned zero-value — treating as unprocessed", key)
			failCount++
			continue
		}

		f.AttackScenario = &report.AttackTest{
			Actor:       result.Actor,
			Path:        result.Path,
			Impact:      result.Impact,
			IsReal:      result.IsReal,
			Explanation: result.Explanation,
		}
		f.AIConfidence = result.Confidence
		if !result.IsReal && result.Confidence >= 0.7 {
			f.Severity = report.SevInfo
			f.Description += fmt.Sprintf("\n[AI Deep Verify: Attack scenario not viable — %s]", result.Explanation)
		}
		successCount++
	}
	if successCount > 0 || failCount > 0 {
		log.Printf("[AI DeepVerify] one-by-one complete: %d success, %d failed (out of %d)",
			successCount, failCount, len(batch))
	}
}

// VerifySingle runs deep verification on a single finding.
// Used by steps 2 and 4 for individual finding verification.
func (e *Engine) VerifySingle(ctx context.Context, f *report.Finding) *report.AttackTest {
	if !e.Available() {
		return heuristicAttackTest(f)
	}

	findingDesc := fmt.Sprintf(
		"Title: %s\nFile: %s:%d\nCategory: %s\nCode:\n%s\nDescription: %s",
		f.Title, f.FilePath, f.LineNumber, f.Category, f.CodeSnippet, f.Description,
	)
	prompt := fmt.Sprintf(PromptAttackScenario, findingDesc)

	// Use deep model if available, otherwise triage model
	client := e.deepClient
	if client == nil || !client.Available() {
		client = e.triageClient
	}
	if client == nil || !client.Available() {
		return heuristicAttackTest(f)
	}

	var result AttackTestResult
	err := client.ChatJSON(ctx, SystemPromptBase, prompt, &result)
	if err != nil {
		return heuristicAttackTest(f)
	}

	return &report.AttackTest{
		Actor:       result.Actor,
		Path:        result.Path,
		Impact:      result.Impact,
		IsReal:      result.IsReal,
		Explanation: result.Explanation,
	}
}

// findingKey returns a unique key for a finding, preferring ID but falling back to file:line.
func findingKey(f *report.Finding) string {
	if f.ID != "" {
		return f.ID
	}
	return fmt.Sprintf("%s:%d", f.FilePath, f.LineNumber)
}

// buildFindingSummary creates a compact summary of findings for AI review.
func buildFindingSummary(findings []report.Finding) string {
	var sb strings.Builder
	for _, f := range findings {
		key := findingKey(&f)
		sb.WriteString(fmt.Sprintf("[ID: %s] %s\n", key, f.Title))
		sb.WriteString(fmt.Sprintf("  File: %s:%d\n", f.FilePath, f.LineNumber))
		sb.WriteString(fmt.Sprintf("  Category: %s | Severity: %s\n", f.Category, f.Severity.String()))
		if f.CodeSnippet != "" {
			sb.WriteString(fmt.Sprintf("  Code: %s\n", report.TruncateString(f.CodeSnippet, 400)))
		}
		sb.WriteString(fmt.Sprintf("  Description: %s\n\n", report.TruncateString(f.Description, 400)))
	}
	return sb.String()
}

// parseSeverity parses a severity string, returns SevInfo on unrecognized.
func parseSeverity(s string) report.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return report.SevCritical
	case "HIGH":
		return report.SevHigh
	case "MEDIUM":
		return report.SevMedium
	case "LOW":
		return report.SevLow
	case "INFO":
		return report.SevInfo
	default:
		return report.SevInfo // unrecognized → info (don't escalate)
	}
}

func countBySeverity(findings []report.Finding, maxSev report.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity <= maxSev {
			n++
		}
	}
	return n
}

func countWithAIConfidence(findings []report.Finding) int {
	n := 0
	for _, f := range findings {
		if f.AIConfidence > 0 {
			n++
		}
	}
	return n
}

// heuristicAttackTest provides a rule-based attack assessment when AI is unavailable.
func heuristicAttackTest(f *report.Finding) *report.AttackTest {
	at := &report.AttackTest{IsReal: true}

	switch strings.ToLower(f.Category) {
	case "secret-detected", "hardcoded-secret", "hardcoded-credentials":
		at.Actor = "Anyone with access to the source code (public repo, leaked code, former employee)"
		at.Path = fmt.Sprintf("1. Read %s\n2. Extract %s from line %d\n3. Use the credential to access the target service", f.FilePath, f.Title, f.LineNumber)
		at.Impact = "Unauthorized access to the service protected by this credential. Potential data breach, resource abuse, or lateral movement."
		at.Explanation = "Hardcoded secrets in source code are accessible to anyone who can read the repository."

	case "sql-injection":
		at.Actor = "Unauthenticated or low-privilege user with access to the vulnerable endpoint"
		at.Path = fmt.Sprintf("1. Identify the vulnerable parameter in %s\n2. Craft SQL injection payload\n3. Extract/modify database contents via the injection point at line %d", f.FilePath, f.LineNumber)
		at.Impact = "Database compromise — data extraction, modification, or deletion. Possible privilege escalation."
		at.Explanation = "SQL injection occurs when user input is concatenated directly into SQL queries."

	case "xss", "xss-reflected", "xss-stored":
		at.Actor = "Attacker who can get a victim to click a crafted link or visit a page with stored payload"
		at.Path = fmt.Sprintf("1. Craft XSS payload targeting the vulnerable parameter in %s:%d\n2. Deliver to victim (link, stored content)\n3. Execute JavaScript in victim's browser session", f.FilePath, f.LineNumber)
		at.Impact = "Session hijacking, credential theft, UI redressing, or actions performed as the victim."
		at.Explanation = "XSS occurs when unsanitized user input is reflected in HTML output."

	case "command-injection":
		at.Actor = "User with access to the vulnerable input field"
		at.Path = fmt.Sprintf("1. Identify the command injection point at %s:%d\n2. Inject shell metacharacters in the input\n3. Execute arbitrary commands on the server", f.FilePath, f.LineNumber)
		at.Impact = "Remote code execution on the server. Full system compromise possible."
		at.Explanation = "Command injection occurs when user input is passed to a shell command without sanitization."

	default:
		at.Actor = "Depends on the specific vulnerability context"
		at.Path = fmt.Sprintf("Attack path through %s:%d requires manual analysis", f.FilePath, f.LineNumber)
		at.Impact = "Requires manual assessment of the vulnerability context"
		at.Explanation = "Automated heuristic — manual review recommended for non-standard vulnerability types."
	}

	return at
}
