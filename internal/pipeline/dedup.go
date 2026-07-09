package pipeline

import (
	"fmt"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// dedupKey generates a deduplication key from a finding.
// Findings with the same file, line, CWE, and normalized category are considered duplicates.
// Different CWEs on the same line are NOT merged (they represent distinct vulnerability types).
func dedupKey(f report.Finding) string {
	cat := normalizeCategory(f.Category)
	cwe := normalizeCWE(f.CWE)
	return fmt.Sprintf("%s:%d:%s:%s", f.FilePath, f.LineNumber, cat, cwe)
}

// normalizeCWE extracts the numeric CWE identifier for dedup purposes.
func normalizeCWE(cwe string) string {
	cwe = strings.TrimSpace(cwe)
	if strings.HasPrefix(cwe, "CWE-") {
		return cwe
	}
	if cwe != "" {
		// Try to extract digits
		digits := ""
		for _, ch := range cwe {
			if ch >= '0' && ch <= '9' {
				digits += string(ch)
			}
		}
		if digits != "" {
			return "CWE-" + digits
		}
	}
	return cwe
}

// normalizeCategory maps similar categories to a canonical form for dedup.
func normalizeCategory(cat string) string {
	cat = strings.ToLower(strings.TrimSpace(cat))
	switch cat {
	case "secret-detected", "hardcoded-secret", "hardcoded-credentials":
		return "secret"
	case "sql-injection", "injection":
		return "injection"
	case "insecure-configuration", "debug-mode-enabled", "missing-security-header":
		return "config"
	default:
		return cat
	}
}

// DeduplicateFindings removes duplicate findings, keeping the highest severity.
// Two findings are duplicates if they share the same file, line, and normalized category.
func DeduplicateFindings(findings []report.Finding) []report.Finding {
	if len(findings) <= 1 {
		return findings
	}

	seen := make(map[string]*report.Finding)
	order := make([]string, 0, len(findings))

	for i := range findings {
		f := &findings[i]
		key := dedupKey(*f)

		if existing, ok := seen[key]; ok {
			// Merge: keep highest severity, combine descriptions
			if f.Severity < existing.Severity { // lower enum value = more severe
				existing.Severity = f.Severity
			}
			if f.Description != existing.Description {
				existing.Description += "\n[Also reported by another step: " + f.Description + "]"
			}
			// Update step to reflect multi-step detection
			if f.Step != existing.Step {
				existing.Step = min(existing.Step, f.Step)
			}
		} else {
			seen[key] = f
			order = append(order, key)
		}
	}

	result := make([]report.Finding, 0, len(order))
	for _, key := range order {
		result = append(result, *seen[key])
	}
	return result
}
