package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// Step7Database analyzes SQL migration files for security issues.
type Step7Database struct{}

func (s *Step7Database) Name() string { return "Step 7: Database Audit" }
func (s *Step7Database) Description() string {
	return "Analyze SQL migration files for dangerous operations and anti-patterns"
}
func (s *Step7Database) IsSkippable() bool       { return true }
func (s *Step7Database) RequiredTools() []string { return nil }

// SQL migration file patterns.
var migrationExtensions = map[string]bool{
	".sql": true, ".psql": true, ".mysql": true,
}

// Database security checks.
var dbChecks = []struct {
	name     string
	pattern  *regexp.Regexp
	severity report.Severity
	category string
	message  string
	fix      string
}{
	{
		name:     "DROP TABLE in migration",
		pattern:  regexp.MustCompile(`(?i)DROP\s+TABLE\s+`),
		severity: report.SevCritical,
		category: "dangerous-operation",
		message:  "DROP TABLE in a migration can cause irreversible data loss.",
		fix:      "Use a multi-step migration: rename table, wait, then drop only after confirming no references.",
	},
	{
		name:     "TRUNCATE in migration",
		pattern:  regexp.MustCompile(`(?i)TRUNCATE\s+(TABLE\s+)?`),
		severity: report.SevHigh,
		category: "dangerous-operation",
		message:  "TRUNCATE removes all data instantly without possibility of rollback.",
		fix:      "Consider a soft-delete approach or ensure this migration has been reviewed for data safety.",
	},
	{
		name:     "SQL injection via dynamic SQL",
		pattern:  regexp.MustCompile(`(?i)(EXECUTE\s+IMMEDIATE|EXEC\s*\(|sp_executesql|format\s*\(.+\)\s*,\s*.+\s*\))`),
		severity: report.SevHigh,
		category: "sql-injection",
		message:  "Dynamic SQL execution found. If any part of the query comes from user input, this is SQL injection.",
		fix:      "Use parameterized queries. Never concatenate user input into SQL strings.",
	},
	{
		name:     "Weak password hash algorithm",
		pattern:  regexp.MustCompile(`(?i)(MD5\s*\(|SHA1\s*\(|SHA\s*\()\s*password`),
		severity: report.SevHigh,
		category: "weak-crypto",
		message:  "Password hashing uses MD5 or SHA1 which are cryptographically broken.",
		fix:      "Use bcrypt, scrypt, or Argon2 for password hashing.",
	},
	{
		name:     "Missing foreign key constraint",
		pattern:  regexp.MustCompile(`(?i)REFERENCES\s+\w+\s*\(\s*\w+\s*\)\s*$`),
		severity: report.SevLow,
		category: "missing-constraint",
		message:  "Foreign key reference found — verify ON DELETE behavior is intentional.",
		fix:      "Add ON DELETE CASCADE or ON DELETE RESTRICT to foreign key constraints.",
	},
	{
		name:     "Excessive GRANT permissions",
		pattern:  regexp.MustCompile(`(?i)GRANT\s+ALL\s+(PRIVILEGES\s+)?ON\s+`),
		severity: report.SevHigh,
		category: "privilege-escalation",
		message:  "GRANT ALL gives full permissions. Use principle of least privilege.",
		fix:      "Grant only the specific permissions needed (SELECT, INSERT, UPDATE, DELETE).",
	},
	{
		name:     "Plaintext password column",
		pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s+(VARCHAR|TEXT|CHAR)\s*[^(]`),
		severity: report.SevHigh,
		category: "hardcoded-credentials",
		message:  "Password column is defined as plaintext. Passwords should be stored as hashes.",
		fix:      "Store bcrypt/scrypt/argon2 hashes, not plaintext passwords.",
	},
	{
		name:     "AUTOINCREMENT without protection",
		pattern:  regexp.MustCompile(`(?i)AUTO_?INCREMENT`),
		severity: report.SevLow,
		category: "information-disclosure",
		message:  "Autoincrement IDs can leak information (order of creation, total count).",
		fix:      "Consider using UUID or ULID for primary keys in user-facing tables.",
	},
	{
		name:     "Missing index on foreign key",
		pattern:  regexp.MustCompile(`(?i)FOREIGN\s+KEY\s*\(`),
		severity: report.SevLow,
		category: "missing-constraint",
		message:  "Foreign key found — verify an index exists on the referencing column for performance.",
		fix:      "Add CREATE INDEX on foreign key columns to avoid full table scans on join/delete.",
	},
}

func (s *Step7Database) Run(ctx context.Context, target string) ([]report.Finding, error) {
	var findings []report.Finding

	// Track AUTOINCREMENT per file for merging
	type incKey struct{ file, cat string }
	autoIncLines := make(map[incKey][]int)

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" {
				return filepath.SkipDir
			}
			// Also scan directories named "migrations" or "migrate"
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if !migrationExtensions[ext] {
			return nil
		}

		// Skip very large SQL files
		if info.Size() > 500*1024 {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		relPath, _ := filepath.Rel(target, path)
		if relPath == "" || relPath == "." {
			relPath = filepath.Base(path)
		}

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, check := range dbChecks {
				if check.pattern.MatchString(line) {
					// Skip commented lines
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "#") ||
						strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
						continue
					}

					// Merge AUTOINCREMENT: collect lines per file, emit once at end
					if check.name == "AUTOINCREMENT without protection" {
						key := incKey{relPath, check.category}
						autoIncLines[key] = append(autoIncLines[key], lineNum)
						continue
					}

					findings = append(findings, report.Finding{
						Title:         fmt.Sprintf("%s in %s", check.name, filepath.Base(path)),
						Description:   fmt.Sprintf("%s\nFound at line %d: %s", check.message, lineNum, strings.TrimSpace(line)),
						Severity:      check.severity,
						FilePath:      relPath,
						LineNumber:    lineNum,
						CodeSnippet:   fmt.Sprintf("  %d | %s", lineNum, strings.TrimSpace(line)),
						Step:          7,
						Category:      check.category,
						CWE:           mapDBCategoryToCWE(check.category),
						CVSS:          severityToCVSS(check.severity),
						FixSuggestion: check.fix,
					})
				}
			}
		}
		return nil
	})

	// Merge AUTOINCREMENT findings: one finding per file with all line numbers
	for key, lines := range autoIncLines {
		if len(lines) == 0 {
			continue
		}
		lineStrs := make([]string, len(lines))
		for i, l := range lines {
			lineStrs[i] = fmt.Sprintf("%d", l)
		}
		findings = append(findings, report.Finding{
			Title:         fmt.Sprintf("AUTOINCREMENT without protection in %s (x%d occurrences)", filepath.Base(key.file), len(lines)),
			Description:   fmt.Sprintf("Autoincrement IDs can leak information (order of creation, total count). Found at lines: %s", strings.Join(lineStrs, ", ")),
			Severity:      report.SevLow,
			FilePath:      key.file,
			LineNumber:    lines[0],
			CodeSnippet:   fmt.Sprintf("  %d locations with AUTOINCREMENT in %s", len(lines), filepath.Base(key.file)),
			Step:          7,
			Category:      key.cat,
			CWE:           "CWE-200",
			CVSS:          2.5,
			FixSuggestion: "Consider using UUID or ULID for primary keys in user-facing tables.",
		})
	}

	return findings, err
}

func mapDBCategoryToCWE(cat string) string {
	switch cat {
	case "dangerous-operation":
		return "CWE-440"
	case "sql-injection":
		return "CWE-89"
	case "weak-crypto":
		return "CWE-327"
	case "privilege-escalation":
		return "CWE-250"
	case "hardcoded-credentials":
		return "CWE-798"
	case "information-disclosure":
		return "CWE-200"
	case "missing-constraint":
		return "CWE-573"
	default:
		return "CWE-16"
	}
}
