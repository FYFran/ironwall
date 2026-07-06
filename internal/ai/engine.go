package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// Engine orchestrates multi-stage AI analysis for security findings.
// Stage 1: Fast triage (V3) — filter obvious false positives
// Stage 2: Deep verification (R1) — adversarial reasoning on remaining findings
//
// Falls back gracefully: if one model is unavailable, uses the other.
// If no AI is available, uses heuristic analysis.
type Engine struct {
	triageClient *Client // Fast model (DeepSeek V3 / deepseek-chat)
	deepClient   *Client // Reasoning model (DeepSeek R1 / deepseek-reasoner)
}

// NewEngine creates a new multi-stage AI engine.
// triageClient: fast model for initial filtering
// deepClient: reasoning model for adversarial verification
// Either can be nil — the engine degrades gracefully.
func NewEngine(triageClient, deepClient *Client) *Engine {
	return &Engine{
		triageClient: triageClient,
		deepClient:   deepClient,
	}
}

// Available returns true if at least one AI client is configured.
func (e *Engine) Available() bool {
	return (e.triageClient != nil && e.triageClient.Available()) ||
		(e.deepClient != nil && e.deepClient.Available())
}

// Analyze runs the full multi-stage analysis on a batch of findings.
// Returns findings with updated severity, AI confidence, and attack scenarios.
func (e *Engine) Analyze(ctx context.Context, findings []report.Finding) []report.Finding {
	if len(findings) == 0 || !e.Available() {
		return findings
	}

	// Stage 1: Fast triage — filter obvious false positives
	var triaged []report.Finding
	if e.triageClient != nil && e.triageClient.Available() {
		triaged = e.runTriage(ctx, findings)
	} else {
		triaged = findings
	}

	// Stage 2: Deep adversarial verification on remaining findings
	var verified []report.Finding
	if e.deepClient != nil && e.deepClient.Available() {
		verified = e.runDeepVerify(ctx, triaged)
	} else if e.triageClient != nil && e.triageClient.Available() {
		// Fallback: use triage model for verification too
		verified = e.runDeepVerifyWithClient(ctx, triaged, e.triageClient)
	} else {
		verified = triaged
	}

	return verified
}

// runTriage runs the fast triage stage.
func (e *Engine) runTriage(ctx context.Context, findings []report.Finding) []report.Finding {
	// Filter to only medium+ severity for AI review (low/info don't need verification)
	var reviewList []report.Finding
	var passThrough []report.Finding
	for _, f := range findings {
		if f.Severity >= report.SevMedium {
			reviewList = append(reviewList, f)
		} else {
			passThrough = append(passThrough, f)
		}
	}

	if len(reviewList) == 0 {
		return findings
	}

	// Build the triage prompt
	summary := buildFindingSummary(reviewList)
	prompt := fmt.Sprintf(PromptTriage, summary)

	// Call AI for triage
	var result TriageResult
	err := e.triageClient.ChatJSON(ctx, SystemPromptTriage, prompt, &result)
	if err != nil {
		// On error, pass all findings through (fail open — don't drop real vulns)
		return findings
	}

	// Apply triage results
	triageMap := make(map[string]TriageVerdict)
	for _, tv := range result.Findings {
		triageMap[strings.TrimSpace(tv.ID)] = tv
	}

	for i := range reviewList {
		f := &reviewList[i]
		tv, ok := triageMap[f.ID]
		if !ok {
			continue
		}
		if tv.IsFalsePositive && tv.Confidence >= 0.8 {
			f.Severity = report.SevInfo
			f.AIConfidence = tv.Confidence
			f.Description += fmt.Sprintf("\n[AI Triage: Likely false positive — %s]", tv.Reason)
		}
		// Apply severity override if provided
		if tv.SeverityOverride != "" {
			if sev := parseSeverity(tv.SeverityOverride); sev != report.SevInfo {
				f.Severity = sev
			}
		}
	}

	return append(reviewList, passThrough...)
}

// runDeepVerify runs adversarial verification on findings that survived triage.
func (e *Engine) runDeepVerify(ctx context.Context, findings []report.Finding) []report.Finding {
	return e.runDeepVerifyWithClient(ctx, findings, e.deepClient)
}

// runDeepVerifyWithClient runs deep verification using the specified client.
func (e *Engine) runDeepVerifyWithClient(ctx context.Context, findings []report.Finding, client *Client) []report.Finding {
	// Only verify medium+ severity findings
	var reviewList []report.Finding
	var passThrough []report.Finding
	for _, f := range findings {
		if f.Severity >= report.SevMedium && f.AIConfidence == 0 { // Don't re-verify findings already triaged as FP
			reviewList = append(reviewList, f)
		} else {
			passThrough = append(passThrough, f)
		}
	}

	if len(reviewList) == 0 {
		return findings
	}

	// Build deep verify prompt
	summary := buildFindingSummary(reviewList)
	prompt := fmt.Sprintf(PromptDeepVerifyBatch, summary)

	var result DeepVerifyResult
	err := client.ChatJSON(ctx, SystemPromptDeepVerify, prompt, &result)
	if err != nil {
		// On error, verify one-by-one with simpler prompt
		return e.verifyOneByOne(ctx, reviewList, passThrough, client)
	}

	// Apply verification results
	verifyMap := make(map[string]DeepVerifyVerdict)
	for _, dv := range result.Findings {
		verifyMap[strings.TrimSpace(dv.ID)] = dv
	}

	for i := range reviewList {
		f := &reviewList[i]
		dv, ok := verifyMap[f.ID]
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
		}
	}

	return append(reviewList, passThrough...)
}

// verifyOneByOne falls back to individual verification when batch fails.
func (e *Engine) verifyOneByOne(ctx context.Context, reviewList, passThrough []report.Finding, client *Client) []report.Finding {
	for i := range reviewList {
		f := &reviewList[i]
		findingDesc := fmt.Sprintf(
			"Title: %s\nFile: %s:%d\nCategory: %s\nCode:\n%s\nDescription: %s",
			f.Title, f.FilePath, f.LineNumber, f.Category, f.CodeSnippet, f.Description,
		)
		prompt := fmt.Sprintf(PromptAttackScenario, findingDesc)

		var result AttackTestResult
		err := client.ChatJSON(ctx, SystemPromptBase, prompt, &result)
		if err != nil {
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
	}
	return append(reviewList, passThrough...)
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

// buildFindingSummary creates a compact summary of findings for AI review.
func buildFindingSummary(findings []report.Finding) string {
	var sb strings.Builder
	for _, f := range findings {
		sb.WriteString(fmt.Sprintf("[ID: %s] %s\n", f.ID, f.Title))
		sb.WriteString(fmt.Sprintf("  File: %s:%d\n", f.FilePath, f.LineNumber))
		sb.WriteString(fmt.Sprintf("  Category: %s | Severity: %s\n", f.Category, f.Severity.String()))
		if f.CodeSnippet != "" {
			sb.WriteString(fmt.Sprintf("  Code: %s\n", report.TruncateString(f.CodeSnippet, 150)))
		}
		sb.WriteString(fmt.Sprintf("  Description: %s\n\n", report.TruncateString(f.Description, 200)))
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
