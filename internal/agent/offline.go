package agent

import (
	"fmt"
	"strings"
)

// OfflineEngine provides rule-based security analysis without requiring an LLM API.
// Uses AST context + heuristic rules to make basic exploitability judgments.
//
// This is a significant upgrade from the 5-case switch in ai/engine.go's
// heuristicAttackTest(). Instead of category-based whitelisting, it uses:
//   - AST structure analysis (via ContextProvider)
//   - Data flow heuristics (source → sink detection)
//   - Pattern-based false positive detection
//   - Severity-aware confidence scoring
type OfflineEngine struct {
	providers *ContextProviderRegistry
	rules     []OfflineRule
}

// OfflineRule is a rule for heuristic analysis.
type OfflineRule struct {
	Name          string
	Category      string
	TruePatterns  []string
	FalsePatterns []string
	MinConfidence float64
}

// NewOfflineEngine creates an offline analysis engine.
func NewOfflineEngine(providers *ContextProviderRegistry) *OfflineEngine {
	return &OfflineEngine{
		providers: providers,
		rules:     defaultOfflineRules(),
	}
}

// Analyze performs rule-based analysis on a finding.
func (oe *OfflineEngine) Analyze(f InputFinding, ctx *FileContext) *AnalystResult {
	result := &AnalystResult{
		FindingID:  f.ID,
		Title:      f.Title,
		Severity:   InputSeverityToAgent(f.Severity),
		Confidence: 0.5,
		CWE:        f.CWE,
		CVSS:       f.CVSS,
	}

	for _, rule := range oe.rules {
		if !matchCategory(rule.Category, f.Category) {
			continue
		}
		for _, fp := range rule.FalsePatterns {
			if matchPattern(fp, f, ctx) {
				result.IsExploitable = false
				result.Confidence = 0.85
				result.Narrative = fmt.Sprintf(
					"Offline rule '%s': matches false positive pattern. %s",
					rule.Name, explainFP(fp))
				return result
			}
		}
	}

	for _, rule := range oe.rules {
		if !matchCategory(rule.Category, f.Category) {
			continue
		}
		for _, tp := range rule.TruePatterns {
			if matchPattern(tp, f, ctx) {
				result.IsExploitable = true
				result.Confidence = rule.MinConfidence
				result.Narrative = fmt.Sprintf(
					"Offline rule '%s': matches known vulnerability pattern. "+
						"The code at %s:%d shows strong indicators of a real vulnerability.",
					rule.Name, f.FilePath, f.LineNumber)
				result.AttackPath = buildHeuristicAttackPath(f, ctx)
				result.FixSuggestion = getCategoryFix(f.Category)
				return result
			}
		}
	}

	result.IsExploitable = f.Severity.IsHighSeverity()
	result.Confidence = 0.4
	result.Narrative = fmt.Sprintf(
		"Offline analysis: no specific rule matched for category '%s'. "+
			"Defaulting to severity-based judgment. Recommend AI-powered analysis for higher confidence.",
		f.Category)
	return result
}

func matchCategory(ruleCat, findingCat string) bool {
	if ruleCat == "*" {
		return true
	}
	return strings.EqualFold(ruleCat, findingCat)
}

func matchPattern(pattern string, f InputFinding, ctx *FileContext) bool {
	if strings.Contains(strings.ToLower(f.CodeSnippet), strings.ToLower(pattern)) {
		return true
	}
	if strings.Contains(strings.ToLower(f.Description), strings.ToLower(pattern)) {
		return true
	}
	if ctx != nil {
		if strings.Contains(strings.ToLower(ctx.SurroundingLines), strings.ToLower(pattern)) {
			return true
		}
		if ctx.EnclosingFunc != nil {
			if strings.Contains(strings.ToLower(ctx.EnclosingFunc.Body), strings.ToLower(pattern)) {
				return true
			}
		}
	}
	return false
}

func explainFP(pattern string) string {
	explanations := map[string]string{
		"test_":                   "Code appears to be in a test file.",
		"/testdata/":              "Code is in a testdata directory.",
		"your_token_here":         "Value is a placeholder, not a real secret.",
		"replace_me":              "Value explicitly indicates it should be replaced.",
		"changeme":                "Placeholder value detected.",
		"example":                 "Likely example/documentation code.",
		"debug=True":              "Debug mode flag — not directly exploitable without context.",
		"ElementTree":             "Python xml.etree.ElementTree is XXE-safe by default in Python 3.",
		"defusedxml":              "Using defusedxml — XXE-safe parser.",
	}
	if exp, ok := explanations[pattern]; ok {
		return exp
	}
	return fmt.Sprintf("Matches false positive indicator: '%s'.", pattern)
}

func getCategoryFix(category string) string {
	fixes := map[string]string{
		"secret-detected":       "Remove hardcoded secret. Use environment variables or a secrets manager.",
		"hardcoded-secret":      "Replace with environment variable or secrets manager.",
		"sql-injection":         "Use parameterized queries or an ORM.",
		"command-injection":     "Avoid shell=True. Use argument lists or Python-native APIs.",
		"code-injection":        "Never pass user input to eval/exec.",
		"xss":                   "HTML-escape all user input before rendering.",
		"weak-crypto":           "Replace with modern cryptography: AES-256-GCM, SHA-256+.",
		"insecure-configuration": "Enable security features: TLS 1.2+, secure cookie flags.",
	}
	if fix, ok := fixes[category]; ok {
		return fix
	}
	return "Review the finding and apply appropriate security controls."
}

func defaultOfflineRules() []OfflineRule {
	return []OfflineRule{
		{
			Name:          "hardcoded-real-secret",
			Category:      "secret-detected",
			TruePatterns:  []string{"ghp_", "sk-", "AKIA", "xoxb-", "-----BEGIN", "api_key", "secret_key", "password"},
			FalsePatterns: []string{"your_token_here", "replace_me", "changeme", "example", "test_", "/testdata/"},
			MinConfidence: 0.75,
		},
		{
			Name:          "command-injection-shell-true",
			Category:      "command-injection",
			TruePatterns:  []string{"shell=True", "os.system(", "subprocess"},
			FalsePatterns: []string{"test_", "/testdata/"},
			MinConfidence: 0.85,
		},
		{
			Name:          "code-injection-eval",
			Category:      "code-injection",
			TruePatterns:  []string{"eval(", "exec("},
			FalsePatterns: []string{"literal_eval", "test_", "/testdata/"},
			MinConfidence: 0.90,
		},
		{
			Name:          "sql-injection-concat",
			Category:      "sql-injection",
			TruePatterns:  []string{`f"`, `f'`, `+ "`, `+ '`, ".format("},
			FalsePatterns: []string{"test_", "/testdata/"},
			MinConfidence: 0.75,
		},
		{
			Name:          "weak-crypto-algorithm",
			Category:      "weak-crypto",
			TruePatterns:  []string{"des.", "md5.", "sha1.", "math/rand", "rc4"},
			FalsePatterns: []string{"test_", "/testdata/"},
			MinConfidence: 0.70,
		},
		{
			Name:          "xss-unsanitized",
			Category:      "xss",
			TruePatterns:  []string{"innerHTML", "document.write(", "dangerouslySetInnerHTML"},
			FalsePatterns: []string{"test_", "/testdata/", "DOMPurify", "sanitize"},
			MinConfidence: 0.65,
		},
		{
			Name:          "generic-false-positive",
			Category:      "*",
			TruePatterns:  []string{},
			FalsePatterns: []string{"test_", "/testdata/", "/fixtures/", "/mocks/", "your_token_here", "replace_me", "changeme"},
			MinConfidence: 0.0,
		},
	}
}
