package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/FYFran/ironwall/internal/ai"
	"github.com/FYFran/ironwall/internal/classify"
	"github.com/FYFran/ironwall/internal/report"
)

// Step4Hardcoded detects hardcoded secrets that gitleaks may have missed.
type Step4Hardcoded struct {
	aiClient *ai.Client
	verifier *classify.Verifier
}

func NewStep4Hardcoded(aiClient *ai.Client) *Step4Hardcoded {
	return &Step4Hardcoded{
		aiClient: aiClient,
		verifier: classify.NewVerifier(aiClient),
	}
}

func (s *Step4Hardcoded) Name() string { return "Step 4: Hardcoded Secrets" }
func (s *Step4Hardcoded) Description() string {
	return "Deep scan for hardcoded secrets that automated scanners miss"
}
func (s *Step4Hardcoded) IsSkippable() bool       { return true }
func (s *Step4Hardcoded) RequiredTools() []string { return nil } // Pure Go + AI

// Secret patterns that gitleaks might miss.
var hardcodedPatterns = []struct {
	name     string
	regex    *regexp.Regexp
	severity report.Severity
	category string
}{
	{
		name:     "DB connection string with credentials",
		regex:    regexp.MustCompile(`(?i)(mysql|postgres|postgresql|mongodb|redis|sqlite3?)://[^:@]+:[^@]+@`),
		severity: report.SevCritical,
		category: "hardcoded-credentials",
	},
	{
		name:     "AWS account ID (12 digits)",
		regex:    regexp.MustCompile(`\b\d{12}\b`),
		severity: report.SevMedium,
		category: "information-disclosure",
	},
	{
		name:     "Private key header",
		regex:    regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`),
		severity: report.SevCritical,
		category: "hardcoded-secret",
	},
	{
		name:     "OAuth client secret pattern",
		regex:    regexp.MustCompile(`(?i)client_?secret["\s:=]+([a-zA-Z0-9_-]{16,})`),
		severity: report.SevHigh,
		category: "hardcoded-secret",
	},
	{
		name:     "Bearer token hardcoded",
		regex:    regexp.MustCompile(`(?i)Authorization\s*[:=]\s*["']Bearer\s+[a-zA-Z0-9._-]{20,}["']`),
		severity: report.SevHigh,
		category: "hardcoded-secret",
	},
	{
		name:     "Internal URL with credentials",
		regex:    regexp.MustCompile(`https?://[^@\s]+:[^@\s]+@[a-zA-Z0-9.-]+`),
		severity: report.SevCritical,
		category: "hardcoded-credentials",
	},
	{
		name:     "Hex-encoded secret (32+ hex chars as string)",
		regex:    regexp.MustCompile(`["'][0-9a-fA-F]{32,64}["']`),
		severity: report.SevMedium,
		category: "hardcoded-secret",
	},
	{
		name:     "FTP/email credential in code",
		regex:    regexp.MustCompile(`(?i)(ftp|smtp|mail|email)[_\s]*(password|passwd|pwd|pass|auth)[_\s]*[:=]\s*["'][^"']{4,}["']`),
		severity: report.SevHigh,
		category: "hardcoded-credentials",
	},
	{
		name:     "Encryption/secret key hardcoded",
		regex:    regexp.MustCompile(`(?i)(aes|encrypt(ion)?|secret|cipher|signing)[_\s]*(key|salt|iv|nonce)[_\s]*[:=]\s*["'][^"']{6,}["']`),
		severity: report.SevHigh,
		category: "hardcoded-secret",
	},
}

// Extensions to scan for hardcoded secrets.
var scanExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".tsx": true, ".jsx": true,
	".java": true, ".kt": true, ".swift": true, ".rb": true, ".php": true,
	".rs": true, ".c": true, ".cpp": true, ".h": true, ".hpp": true,
	".yaml": true, ".yml": true, ".toml": true, ".json": true, ".xml": true,
	".env": true, ".cfg": true, ".conf": true, ".ini": true, ".properties": true,
	".tf": true, ".dockerfile": true, ".sh": true, ".bash": true, ".zsh": true,
	".sql": true, ".ps1": true, ".bat": true,
}

func (s *Step4Hardcoded) Run(ctx context.Context, target string) ([]report.Finding, error) {
	var findings []report.Finding

	// Walk the target directory
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't read
		}
		if info.IsDir() {
			base := filepath.Base(path)
			// Skip common non-source directories
			if base == ".git" || base == "node_modules" || base == "vendor" ||
				base == "__pycache__" || base == ".venv" || base == "venv" ||
				base == "dist" || base == "build" || base == ".next" ||
				base == "target" || strings.HasPrefix(base, ".") && base != "." {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !scanExtensions[ext] && !scanExtensions[strings.ToLower(filepath.Base(path))] {
			return nil
		}

		// Limit file size to 1MB
		if info.Size() > 1024*1024 {
			return nil
		}

		fileFindings := scanFileForSecrets(path, target)
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		return findings, fmt.Errorf("walk error: %w", err)
	}

	// Apply severity classification
	for i := range findings {
		findings[i].Severity = classify.DowngradeForTestFile(findings[i].FilePath, findings[i].Severity)

		// Run attack scenario verification for higher-severity findings
		if findings[i].Severity >= report.SevMedium {
			at := s.verifier.Verify(ctx, &findings[i])
			findings[i].AttackScenario = at
		}
	}

	return findings, nil
}

// scanFileForSecrets scans a single file for hardcoded secret patterns.
func scanFileForSecrets(path, target string) []report.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []report.Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	relPath, _ := filepath.Rel(target, path)
	if relPath == "" {
		relPath = path
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, pattern := range hardcodedPatterns {
			if loc := pattern.regex.FindStringIndex(line); loc != nil {
				// Skip if this is in a comment (heuristic: line starts with comment char)
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
					strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") ||
					strings.HasPrefix(trimmed, "<!--") {
					continue
				}

				findings = append(findings, report.Finding{
					Title:       fmt.Sprintf("Potential %s", pattern.name),
					Description: fmt.Sprintf("Regex pattern detected a potential %s at %s:%d. This may be a hardcoded secret that automated scanners missed.", pattern.name, relPath, lineNum),
					Severity:    pattern.severity,
					FilePath:    relPath,
					LineNumber:  lineNum,
					CodeSnippet: fmt.Sprintf("  %d | %s", lineNum, strings.TrimSpace(line)),
					Step:        4,
					Category:    pattern.category,
					CWE:         "CWE-798", // Hardcoded Credentials
					CVSS:        severityToCVSS(pattern.severity),
				})
			}
		}
	}

	return findings
}

func severityToCVSS(s report.Severity) float64 {
	switch s {
	case report.SevCritical:
		return 9.8
	case report.SevHigh:
		return 7.5
	case report.SevMedium:
		return 5.0
	case report.SevLow:
		return 2.5
	default:
		return 0.0
	}
}
