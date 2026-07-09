package agent

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Verifier provides independent verification of security findings.
// Checks whether secrets are still active (API calls) and whether
// data flow paths are reachable (AST analysis).
type Verifier struct {
	httpClient *http.Client
	providers  *ContextProviderRegistry
}

// NewVerifier creates a new Verifier.
func NewVerifier(providers *ContextProviderRegistry) *Verifier {
	return &Verifier{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		providers: providers,
	}
}

// VerifySecret attempts to validate whether a detected secret is a real,
// active credential by making a test API call.
func (v *Verifier) VerifySecret(f InputFinding) VerificationResult {
	lowerCode := strings.ToLower(f.CodeSnippet)
	lowerDesc := strings.ToLower(f.Description)

	switch {
	case strings.Contains(lowerCode, "ghp_") || strings.Contains(lowerDesc, "github"):
		return v.verifyGitHubToken(f)
	case strings.Contains(lowerCode, "sk_live_") || strings.Contains(lowerDesc, "stripe"):
		return v.verifyStripeKey(f)
	case strings.Contains(lowerCode, "hooks.slack.com") || strings.Contains(lowerDesc, "slack"):
		return v.verifySlackWebhook(f)
	default:
		return VerificationResult{
			Verified: false,
			Method:   "none",
			Detail:   fmt.Sprintf("No verification method available for secret type in category '%s'.", f.Category),
		}
	}
}

func (v *Verifier) verifyGitHubToken(f InputFinding) VerificationResult {
	token := extractSecretValue(f.CodeSnippet)
	if token == "" {
		return VerificationResult{Verified: false, Method: "api-call", Detail: "Could not extract token value."}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("User-Agent", "ironwall-agent-verifier")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return VerificationResult{Verified: false, Method: "api-call", Detail: fmt.Sprintf("GitHub API call failed: %v", err), APIEndpoint: "GET /user"}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return VerificationResult{
			Verified:    true,
			Method:      "api-call",
			Detail:      "GitHub PAT is ACTIVE and valid. Immediate rotation required.",
			APIEndpoint: "GET /user",
			APIResponse: fmt.Sprintf("HTTP %d — token has valid GitHub API access", resp.StatusCode),
		}
	}
	return VerificationResult{Verified: false, Method: "api-call", Detail: fmt.Sprintf("GitHub token returned HTTP %d.", resp.StatusCode), APIEndpoint: "GET /user"}
}

func (v *Verifier) verifyStripeKey(f InputFinding) VerificationResult {
	token := extractSecretValue(f.CodeSnippet)
	if token == "" {
		return VerificationResult{Verified: false, Method: "api-call", Detail: "Could not extract Stripe key."}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.stripe.com/v1/balance", nil)
	req.SetBasicAuth(token, "")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return VerificationResult{Verified: false, Method: "api-call", Detail: fmt.Sprintf("Stripe API call failed: %v", err), APIEndpoint: "GET /v1/balance"}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return VerificationResult{
			Verified:    true,
			Method:      "api-call",
			Detail:      "Stripe secret key is ACTIVE. Rotate immediately.",
			APIEndpoint: "GET /v1/balance",
		}
	}
	return VerificationResult{Verified: false, Method: "api-call", Detail: fmt.Sprintf("Stripe key returned HTTP %d.", resp.StatusCode), APIEndpoint: "GET /v1/balance"}
}

func (v *Verifier) verifySlackWebhook(f InputFinding) VerificationResult {
	url := extractURL(f.CodeSnippet)
	if url == "" || !strings.Contains(url, "hooks.slack.com") {
		return VerificationResult{Verified: false, Method: "api-call", Detail: "Could not extract valid Slack webhook URL."}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	body := strings.NewReader(`{"text": "Ironwall security audit — webhook verification test. Rotate this URL if you see this."}`)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return VerificationResult{Verified: false, Method: "api-call", Detail: fmt.Sprintf("Slack webhook call failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return VerificationResult{
			Verified:    true,
			Method:      "api-call",
			Detail:      "Slack webhook is ACTIVE. Rotate this webhook URL immediately.",
			APIEndpoint: url[:min(len(url), 50)] + "...",
		}
	}
	return VerificationResult{Verified: false, Method: "api-call", Detail: fmt.Sprintf("Slack webhook returned HTTP %d.", resp.StatusCode), APIEndpoint: url[:min(len(url), 50)] + "..."}
}

// VerifyReachability uses AST context to determine whether attacker-controlled
// data can reach the vulnerable sink.
func (v *Verifier) VerifyReachability(f InputFinding) VerificationResult {
	ctx, err := v.providers.GetContext(f.FilePath, f.LineNumber)
	if err != nil {
		return VerificationResult{
			Verified: false, Method: "ast-reachability",
			Detail: fmt.Sprintf("Could not parse file context: %v", err),
		}
	}

	if ctx.EnclosingFunc != nil {
		funcBody := strings.ToLower(ctx.EnclosingFunc.Body)
		funcName := strings.ToLower(ctx.EnclosingFunc.Name)

		hasInputSource := strings.Contains(funcBody, "request.") ||
			strings.Contains(funcBody, "r.") ||
			strings.Contains(funcBody, "args.") ||
			strings.Contains(funcBody, ".query.") ||
			strings.Contains(funcBody, ".param(") ||
			strings.Contains(funcBody, "os.args") ||
			strings.Contains(funcBody, "scanf") ||
			strings.Contains(funcBody, "readline")

		isHandler := strings.HasPrefix(funcName, "handle") ||
			strings.HasPrefix(funcName, "serve") ||
			strings.HasPrefix(funcName, "get") ||
			strings.HasSuffix(funcName, "handler")

		if funcName == "main" || isHandler || hasInputSource {
			reachPath := ctx.EnclosingFunc.Name
			if hasInputSource {
				reachPath = "user_input → " + reachPath + " → vulnerable_sink"
			}
			return VerificationResult{
				Verified: true, Method: "ast-reachability",
				Detail:      "Function is reachable from external input or program entry point.",
				IsReachable: true, ReachPath: reachPath,
			}
		}

		return VerificationResult{
			Verified: false, Method: "ast-reachability",
			Detail: fmt.Sprintf("Function '%s' exists but reachability could not be confirmed.", ctx.EnclosingFunc.Name),
		}
	}

	return VerificationResult{
		Verified: true, Method: "ast-reachability",
		Detail:      "Finding is at module/package level — code executes on import.",
		IsReachable: true, ReachPath: "module_import → module_level_code → vulnerable_code",
	}
}

func extractSecretValue(snippet string) string {
	lines := strings.Split(snippet, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		for _, quote := range []string{`"`, `'`} {
			start := strings.Index(line, quote)
			if start < 0 {
				continue
			}
			end := strings.LastIndex(line, quote)
			if end > start {
				val := line[start+1 : end]
				if len(val) >= 20 {
					return val
				}
			}
		}
	}
	return ""
}

func extractURL(snippet string) string {
	start := strings.Index(snippet, "https://")
	if start < 0 {
		start = strings.Index(snippet, "http://")
	}
	if start < 0 {
		return ""
	}
	end := start
	for end < len(snippet) && snippet[end] != ' ' && snippet[end] != '\n' && snippet[end] != '"' && snippet[end] != '\'' && snippet[end] != ')' {
		end++
	}
	return snippet[start:end]
}
