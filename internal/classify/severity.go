package classify

import (
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// CategoryWeights maps finding categories to base severity.
// Higher weight = more severe by default.
var CategoryWeights = map[string]report.Severity{
	// 🔴 CRITICAL — credential leaks, RCE, data breach
	"hardcoded-secret":      report.SevCritical,
	"hardcoded-credentials": report.SevCritical,
	"secret-detected":       report.SevCritical,
	"rce":                   report.SevCritical,
	"remote-code-execution": report.SevCritical,
	"command-injection":     report.SevCritical,
	"sql-injection":         report.SevCritical,
	"authentication-bypass": report.SevCritical,
	"jwt-none-algorithm":    report.SevCritical,
	"exposed-credentials":   report.SevCritical,

	// 🟠 HIGH — injection, IDOR, privilege escalation
	"injection":             report.SevHigh,
	"idor":                  report.SevHigh,
	"broken-access-control": report.SevHigh,
	"privilege-escalation":  report.SevHigh,
	"xxe":                   report.SevHigh,
	"ssrf":                  report.SevHigh,
	"path-traversal":        report.SevHigh,
	"deserialization":       report.SevHigh,
	"xss":                   report.SevHigh,
	"xss-reflected":         report.SevHigh,
	"xss-stored":            report.SevHigh,
	"missing-auth":          report.SevHigh,
	"cors-misconfiguration": report.SevHigh,

	// 🟡 MEDIUM — rate limiting, CSRF, info leak
	"csrf":                    report.SevMedium,
	"missing-rate-limit":      report.SevMedium,
	"information-disclosure":  report.SevMedium,
	"insecure-configuration":  report.SevMedium,
	"weak-crypto":             report.SevMedium,
	"missing-security-header": report.SevMedium,
	"open-redirect":           report.SevMedium,
	"insufficient-logging":    report.SevMedium,

	// 🟢 LOW — best practices, hardening
	"hardcoded-port":      report.SevLow,
	"missing-http-only":   report.SevLow,
	"missing-secure-flag": report.SevLow,
	"debug-mode-enabled":  report.SevLow,
	"deprecated-function": report.SevLow,
}

// SeverityFromCategory returns a default severity for a given finding category.
func SeverityFromCategory(category string) report.Severity {
	category = strings.ToLower(strings.TrimSpace(category))
	if sev, ok := CategoryWeights[category]; ok {
		return sev
	}
	return report.SevMedium // Default: medium — require human review
}

// DowngradeForTestFile downgrades severity if the finding is in a test file.
func DowngradeForTestFile(filePath string, current report.Severity) report.Severity {
	lower := strings.ToLower(filePath)
	if strings.Contains(lower, "_test.") || strings.Contains(lower, "test_") ||
		strings.Contains(lower, "/test/") || strings.Contains(lower, "/tests/") ||
		strings.Contains(lower, "/testdata/") || strings.Contains(lower, "/fixtures/") ||
		strings.Contains(lower, "/mocks/") {
		switch current {
		case report.SevCritical:
			return report.SevHigh
		case report.SevHigh:
			return report.SevMedium
		case report.SevMedium:
			return report.SevLow
		default:
			return report.SevInfo
		}
	}
	return current
}

// OverrideFromAI overrides severity based on AI confidence.
// Low confidence findings get downgraded.
func OverrideFromAI(confidence float64, current report.Severity) report.Severity {
	if confidence < 0.3 {
		return report.SevInfo
	}
	if confidence < 0.6 {
		switch current {
		case report.SevCritical:
			return report.SevHigh
		case report.SevHigh:
			return report.SevMedium
		case report.SevMedium:
			return report.SevLow
		}
	}
	return current
}
