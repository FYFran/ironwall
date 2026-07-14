package missing

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// EffectivenessResult describes whether a found control is effective.
type EffectivenessResult int

const (
	EffUnknown    EffectivenessResult = iota // Not evaluated
	EffEffective                              // Control exists and appears effective
	EffDecorative                             // Control exists but is fake/stub
	EffDisabled                               // Control explicitly disabled
	EffCommentedOut                           // Control is in a comment
	EffWrongScope                             // Control is in test file only, not in real code
	EffDebugOnly                              // Control only active in debug/dev mode
)

func (e EffectivenessResult) String() string {
	switch e {
	case EffEffective:   return "effective"
	case EffDecorative:  return "decorative"
	case EffDisabled:    return "disabled"
	case EffCommentedOut: return "commented_out"
	case EffWrongScope:  return "wrong_scope"
	case EffDebugOnly:   return "debug_only"
	default:             return "unknown"
	}
}

// EffectivenessValidator checks if a "present" control is actually effective.
// This addresses Brain B attack #1: presence ≠ effectiveness.
type EffectivenessValidator struct {
	Control SecurityControl
}

// Validate checks a file for control effectiveness.
// filePath is relative to target (project root).
// Returns the effectiveness result and evidence line(s).
func (v *EffectivenessValidator) Validate(filePath string, target string) (EffectivenessResult, string) {
	fullPath := filepath.Join(target, filePath)
	f, err := os.Open(fullPath)
	if err != nil {
		return EffUnknown, ""
	}
	defer f.Close()

	relPath, _ := filepath.Rel(target, fullPath)
	if relPath == "" {
		relPath = fullPath
	}

	// Scan the file for effectiveness issues.
	// IMPORTANT: Do not short-circuit on commented-out patterns — a real
	// implementation may exist elsewhere in the file (e.g. a comment about
	// nginx rate limiting vs actual middleware.RateLimit() call).
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	lineNum := 0
	inBlockComment := false
	var evidenceLines []string
	hasNonCommentMatch := false

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Track block comments
		if strings.Contains(line, "/*") {
			inBlockComment = true
		}
		if inBlockComment {
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			// Note commented-out pattern but continue scanning
			if matchesAny(line, v.Control.PresencePatterns) {
				evidenceLines = append(evidenceLines, formatEvidence(relPath, lineNum, line, "pattern found inside block comment"))
			}
			continue
		}

		// Skip line comments entirely for presence checks
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "<!--") {
			if matchesAny(line, v.Control.PresencePatterns) {
				evidenceLines = append(evidenceLines, formatEvidence(relPath, lineNum, line, "pattern found in comment line"))
			}
			continue
		}

		// Non-comment line: check if control pattern exists here
		if matchesAny(line, v.Control.PresencePatterns) {
			hasNonCommentMatch = true
		}

		// Phase 2: Check for explicit disable
		if matchesAny(line, v.Control.DisablePatterns) {
			evidenceLines = append(evidenceLines, formatEvidence(relPath, lineNum, line, "control explicitly disabled"))
		}

		// Phase 3: Check for decorative/stub implementation
		if matchesAny(line, v.Control.DecorativePatterns) {
			evidenceLines = append(evidenceLines, formatEvidence(relPath, lineNum, line, "decorative/stub implementation detected"))
		}

		// Phase 4: Check for debug-only conditions
		if matchesAny(line, v.Control.PresencePatterns) {
			if isDebugGuarded(line) {
				evidenceLines = append(evidenceLines, formatEvidence(relPath, lineNum, line, "control guarded by DEBUG/test condition"))
			}
		}
	}

	// If we found the pattern in non-comment code, the control is effectively present
	// (unless there are explicit disable/decorative/debug issues)
	if hasNonCommentMatch {
		// Check for effectiveness issues
		for _, ev := range evidenceLines {
			if strings.Contains(ev, "disabled") {
				return EffDisabled, strings.Join(evidenceLines, "\n")
			}
			if strings.Contains(ev, "decorative") {
				return EffDecorative, strings.Join(evidenceLines, "\n")
			}
			if strings.Contains(ev, "DEBUG") {
				return EffDebugOnly, strings.Join(evidenceLines, "\n")
			}
		}
		return EffEffective, ""
	}

	if len(evidenceLines) > 0 {
		// Determine worst effectiveness
		for _, ev := range evidenceLines {
			if strings.Contains(ev, "disabled") {
				return EffDisabled, strings.Join(evidenceLines, "\n")
			}
			if strings.Contains(ev, "decorative") {
				return EffDecorative, strings.Join(evidenceLines, "\n")
			}
			if strings.Contains(ev, "DEBUG") {
				return EffDebugOnly, strings.Join(evidenceLines, "\n")
			}
		}
		return EffDecorative, strings.Join(evidenceLines, "\n")
	}

	return EffEffective, ""
}

// ValidateAuthEffectiveness does deeper analysis for auth controls.
// Checks whether the auth function actually contains a rejection path.
// filePath is relative to target (project root).
func ValidateAuthEffectiveness(filePath string, target string) (EffectivenessResult, string) {
	fullPath := filepath.Join(target, filePath)
	f, err := os.Open(fullPath)
	if err != nil {
		return EffUnknown, ""
	}
	defer f.Close()

	relPath, _ := filepath.Rel(target, fullPath)
	if relPath == "" {
		relPath = fullPath
	}

	authPattern := regexp.MustCompile(`func\s+(?:\(.*?\)\s+)?(?:auth|Auth|requireAuth|Authenticate|Authorize|checkAuth|verifyToken|validateSession)\s*\(`)
	rejectionPattern := regexp.MustCompile(`(?:return.*?(?:401|403|Unauthorized|Forbidden)|w\.WriteHeader\(401\)|w\.WriteHeader\(403\)|abort\(\)|c\.Abort|c\.JSON\(.*StatusUnauthorized|http\.Error.*401|http\.Error.*403|json\.NewEncoder.*401)`)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	lineNum := 0
	inAuthFunc := false
	braceDepth := 0
	hasRejection := false
	authStartLine := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if !inAuthFunc && authPattern.MatchString(line) {
			inAuthFunc = true
			authStartLine = lineNum
			braceDepth = 0
			hasRejection = false
		}

		if inAuthFunc {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if !hasRejection && rejectionPattern.MatchString(line) {
				hasRejection = true
			}
			if braceDepth <= 0 && authStartLine != lineNum {
				// Exited auth function
				if !hasRejection {
					return EffDecorative, formatEvidence(relPath, authStartLine, "auth function has no rejection path (no 401/403/abort) — decorative only", "")
				}
				inAuthFunc = false
			}
		}
	}

	return EffEffective, ""
}

// CheckTestFileScope checks if the control only exists in test files, not in real handlers.
func CheckTestFileScope(target string, control SecurityControl) (EffectivenessResult, string) {
	var testFiles, realFiles []string
	var testHits, realHits int

	_ = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				base := filepath.Base(path)
				if base == ".git" || base == "node_modules" || base == "vendor" || base == "__pycache__" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		isTestFile := strings.Contains(strings.ToLower(filepath.Base(path)), "_test.") ||
			strings.HasPrefix(strings.ToLower(filepath.Base(path)), "test_") ||
			strings.Contains(path, "/testdata/") || strings.Contains(path, "\\testdata\\")

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)

		hasHit := false
		for _, pat := range control.PresencePatterns {
			if matched, _ := regexp.MatchString(pat, content); matched {
				hasHit = true
				break
			}
		}

		if hasHit {
			if isTestFile {
				testFiles = append(testFiles, path)
				testHits++
			} else {
				realFiles = append(realFiles, path)
				realHits++
			}
		}
		return nil
	})

	if testHits > 0 && realHits == 0 {
		return EffWrongScope, "control only found in test files: " + strings.Join(testFiles, ", ")
	}
	return EffEffective, ""
}

// Helpers

func matchesAny(line string, patterns []string) bool {
	for _, pat := range patterns {
		if matched, _ := regexp.MatchString(pat, line); matched {
			return true
		}
	}
	return false
}

func isDebugGuarded(line string) bool {
	debugPatterns := []string{
		`if\s+(?:os\.Getenv|os\.Environ).*DEBUG`,
		`if\s+DEBUG`,
		`@pytest`,
		`if.*os\.Getenv.*==.*"dev"`,
		`if\s+is_dev\b`,
		`if\s+is_test\b`,
		`testing\.TB`,
	}
	for _, pat := range debugPatterns {
		if matched, _ := regexp.MatchString(pat, line); matched {
			return true
		}
	}
	return false
}

func formatEvidence(path string, line int, code string, reason string) string {
	result := path + ":" + itoa(line) + ": " + strings.TrimSpace(code)
	if reason != "" {
		result += " — " + reason
	}
	return result
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
