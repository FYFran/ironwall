package classify

import (
	"context"
	"fmt"
	"strings"

	"github.com/FYFran/ironwall/internal/ai"
	"github.com/FYFran/ironwall/internal/report"
)

// Verifier checks if a security finding represents a real attack scenario.
type Verifier struct {
	client *ai.Client
}

// NewVerifier creates a new attack scenario verifier.
func NewVerifier(client *ai.Client) *Verifier {
	return &Verifier{client: client}
}

// Verify runs the three-questions attack scenario verification.
// If AI is not available, it returns a heuristic-based assessment.
func (v *Verifier) Verify(ctx context.Context, f *report.Finding) *report.AttackTest {
	if v.client == nil || !v.client.Available() {
		return heuristicAttackTest(f)
	}

	findingDesc := fmt.Sprintf(
		"Title: %s\nFile: %s:%d\nCategory: %s\nCode:\n%s\nDescription: %s",
		f.Title, f.FilePath, f.LineNumber, f.Category, f.CodeSnippet, f.Description,
	)

	prompt := fmt.Sprintf(ai.PromptAttackScenario, findingDesc)
	response, err := v.client.Chat(ctx, ai.SystemPromptBase, prompt)
	if err != nil {
		// Fall back to heuristic on API error
		return heuristicAttackTest(f)
	}

	return parseAttackTestResponse(response)
}

// parseAttackTestResponse extracts AttackTest from AI response.
// Tries JSON parsing, falls back to keyword extraction.
func parseAttackTestResponse(response string) *report.AttackTest {
	at := &report.AttackTest{}

	// Try simple keyword extraction from the response
	lower := strings.ToLower(response)

	// Determine if real
	if strings.Contains(lower, "\"is_real\": true") || strings.Contains(lower, "\"is_real\":true") {
		at.IsReal = true
	} else if strings.Contains(lower, "\"is_real\": false") || strings.Contains(lower, "\"is_real\":false") {
		at.IsReal = false
	} else {
		// Heuristic: if all three questions have substantive answers, it's real
		actorHasAnswer := strings.Contains(lower, "actor") && len(response) > 200
		pathHasAnswer := strings.Contains(lower, "path") && strings.Contains(lower, "step")
		impactHasAnswer := strings.Contains(lower, "impact") && strings.Contains(lower, "gain")
		at.IsReal = actorHasAnswer && pathHasAnswer && impactHasAnswer
	}

	// Extract fields
	at.Actor = extractJSONField(response, "actor")
	at.Path = extractJSONField(response, "path")
	at.Impact = extractJSONField(response, "impact")
	at.Explanation = extractJSONField(response, "explanation")

	if at.Explanation == "" {
		at.Explanation = response
		if len(at.Explanation) > 500 {
			at.Explanation = at.Explanation[:500] + "..."
		}
	}

	return at
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

// extractJSONField extracts a simple JSON string field from a response.
// This is a simple parser — for complex cases, proper JSON unmarshaling is needed.
func extractJSONField(jsonStr, field string) string {
	// Look for "field": "value" or "field":"value"
	patterns := []string{
		fmt.Sprintf(`"%s": "`, field),
		fmt.Sprintf(`"%s":"`, field),
	}

	for _, pattern := range patterns {
		idx := strings.Index(jsonStr, pattern)
		if idx < 0 {
			continue
		}
		start := idx + len(pattern)
		if start >= len(jsonStr) {
			continue
		}
		// Find the closing quote
		end := start
		for end < len(jsonStr) {
			if jsonStr[end] == '"' && (end == start || jsonStr[end-1] != '\\') {
				return strings.ReplaceAll(jsonStr[start:end], `\"`, `"`)
			}
			end++
		}
	}

	return ""
}
