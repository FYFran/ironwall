// Package scanner — non-code file security scanner (#31).
// Scans non-code files (.env.example, Makefile, docker-compose.yml, README.md, etc.)
// for security-relevant information that SAST tools ignore.
package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// NonCodeFinding represents a security finding in a non-code file.
type NonCodeFinding struct {
	FilePath    string
	LineNumber  int
	Category    string
	Title       string
	Description string
	Severity    report.Severity
	CWE         string
	Match       string
}

// NonCodeResult holds all findings from non-code file scanning.
type NonCodeResult struct {
	Findings []NonCodeFinding
}

// ToFindings converts to report.Findings format.
func (r *NonCodeResult) ToFindings() []report.Finding {
	var findings []report.Finding
	for _, nf := range r.Findings {
		findings = append(findings, report.Finding{
			Title:         nf.Title,
			Description:   nf.Description,
			Severity:      nf.Severity,
			FilePath:      nf.FilePath,
			LineNumber:    nf.LineNumber,
			CodeSnippet:   nf.Match,
			Step:          1, // Integrates with Step 1 (Secret Scanning)
			Category:      nf.Category,
			CWE:           nf.CWE,
			FixSuggestion: "Remove or redact the sensitive information.",
		})
	}
	return findings
}

// NonCodeFilePatterns defines which non-code files to scan.
var nonCodeFilePatterns = []string{
	".env.example", ".env.sample", ".env.template", ".env.local", ".env.development",
	"Makefile", "makefile", "GNUmakefile",
	"docker-compose.yml", "docker-compose.yaml", "docker-compose.*.yml", "docker-compose.*.yaml",
	"Dockerfile", "Dockerfile.*",
	"README.md", "README", "CONTRIBUTING.md", "SETUP.md", "INSTALL.md",
	"package.json", "pyproject.toml", "setup.py", "setup.cfg",
	"nginx.conf", "nginx-*.conf", "default.conf",
	".gitlab-ci.yml", ".travis.yml", "Jenkinsfile", "bitbucket-pipelines.yml",
	"terraform.tfvars", "*.auto.tfvars", "terraform.tfstate",
	"helm/values.yaml", "helm/values-*.yaml",
	"Vagrantfile", "Vagrantfile.*",
	"config.json", "config.yaml", "config.yml", "settings.json",
}

// NonCodeChecks defines security checks for non-code files.
type nonCodeCheck struct {
	name        string
	category    string
	cwe         string
	severity    report.Severity
	pattern     *regexp.Regexp
	description string
}

var nonCodeChecks = []nonCodeCheck{
	// --- Secrets in .env files ---
	{
		name: "real-secret-in-env-example", category: "secret-in-noncode",
		cwe: "CWE-260", severity: report.SevHigh,
		pattern: regexp.MustCompile(`(?i)(SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*[^\s]{8,}`),
		description: "Environment example file may contain a real secret, not a placeholder.",
	},
	// --- IP addresses in README/docs ---
	{
		name: "ip-in-readme", category: "info-disclosure",
		cwe: "CWE-200", severity: report.SevLow,
		pattern: regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
		description: "IP address found in documentation file. May expose internal infrastructure.",
	},
	// --- Internal URLs in docs ---
	{
		name: "internal-url-in-docs", category: "info-disclosure",
		cwe: "CWE-200", severity: report.SevLow,
		pattern: regexp.MustCompile(`https?://(?:staging|dev|internal|admin|test)\.`),
		description: "Internal/staging URL found in documentation. May expose non-public environments.",
	},
	// --- Ports in config/compose ---
	{
		name: "sensitive-port-exposure", category: "config-misconfig",
		cwe: "CWE-16", severity: report.SevMedium,
		pattern: regexp.MustCompile(`(?:5432|6379|27017|3306|9042|9200|5601|8080|8443|9090|3000)\s*:`),
		description: "Database/internal service port exposed in configuration. Check if port exposure is intentional.",
	},
	// --- Privileged Docker containers ---
	{
		name: "privileged-container", category: "container-security",
		cwe: "CWE-250", severity: report.SevHigh,
		pattern: regexp.MustCompile(`privileged\s*:\s*true`),
		description: "Docker container running in privileged mode. Grants full host access.",
	},
	// --- Docker run as root ---
	{
		name: "docker-root-user", category: "container-security",
		cwe: "CWE-250", severity: report.SevMedium,
		pattern: regexp.MustCompile(`(?i)USER\s+(root|0)\b`),
		description: "Docker container running as root. Use a non-root USER for defense in depth.",
	},
	// --- npm install with unsafe permissions ---
	{
		name: "npm-unsafe-perm", category: "supply-chain",
		cwe: "CWE-1104", severity: report.SevMedium,
		pattern: regexp.MustCompile(`npm\s+(?:install|i)\s+.*--unsafe-perm`),
		description: "npm install with --unsafe-perm allows scripts to run as root.",
	},
	// --- curl piped to bash ---
	{
		name: "curl-pipe-bash", category: "supply-chain",
		cwe: "CWE-1104", severity: report.SevHigh,
		pattern: regexp.MustCompile(`curl\s+.*\|\s*(?:bash|sh|zsh)`),
		description: "curl piped to shell — no integrity verification. Attacker who compromises the URL owns the target machine.",
	},
	// --- wget piped to shell ---
	{
		name: "wget-pipe-shell", category: "supply-chain",
		cwe: "CWE-1104", severity: report.SevHigh,
		pattern: regexp.MustCompile(`wget\s+.*\|\s*(?:bash|sh|zsh)`),
		description: "wget piped to shell — same risk as curl|bash, no integrity check.",
	},
	// --- TLS verification disabled ---
	{
		name: "tls-verify-disabled", category: "config-misconfig",
		cwe: "CWE-295", severity: report.SevHigh,
		pattern: regexp.MustCompile(`(?i)(verify\s*=\s*false|ssl_verify\s*=\s*false|tls_verify\s*=\s*false|insecure_skip_verify|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|CURL_INSECURE)`),
		description: "TLS certificate verification disabled. Enables man-in-the-middle attacks.",
	},
	// --- Debug mode in config ---
	{
		name: "debug-mode-enabled", category: "config-misconfig",
		cwe: "CWE-489", severity: report.SevMedium,
		pattern: regexp.MustCompile(`(?i)(DEBUG\s*=\s*True|DEBUG\s*=\s*true|debug\s*:\s*true|ENV\s*=\s*development|NODE_ENV\s*=\s*development)`),
		description: "Debug/development mode appears enabled. Ensure this is not deployed to production.",
	},
	// --- Hardcoded AWS/GCP credentials in config ---
	{
		name: "cloud-credential-in-config", category: "secret-in-noncode",
		cwe: "CWE-798", severity: report.SevCritical,
		pattern: regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|google_application_credentials|azure_storage_key|aliyun_access_key)`),
		description: "Cloud provider credential referenced in configuration. Use IAM roles or workload identity instead.",
	},
}

// RunNonCodeScan scans non-code files for security issues.
// Integrated with Step 1 (Secret Scanning) pipeline.
func RunNonCodeScan(target string) (*NonCodeResult, error) {
	result := &NonCodeResult{}

	for _, pattern := range nonCodeFilePatterns {
		matches, _ := filepath.Glob(filepath.Join(target, pattern))
		// Also check subdirectories
		subMatches, _ := filepath.Glob(filepath.Join(target, "**", pattern))
		matches = append(matches, subMatches...)

		for _, filePath := range matches {
			scanNonCodeFile(filePath, target, result)
		}
	}

	// Also scan all files matching extensions in root
	additionalExts := []string{"*.md", "*.txt", "*.rst", "*.adoc", "Makefile"}
	for _, pattern := range additionalExts {
		matches, _ := filepath.Glob(filepath.Join(target, pattern))
		for _, filePath := range matches {
			scanNonCodeFile(filePath, target, result)
		}
	}

	return result, nil
}

func scanNonCodeFile(filePath, target string, result *NonCodeResult) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	// Skip binary files
	stat, _ := f.Stat()
	if stat.Size() > 1_000_000 { // Skip files > 1MB
		return
	}

	relPath, _ := filepath.Rel(target, filePath)
	if relPath == "" {
		relPath = filePath
	}

	// Only run context-appropriate checks
	fileName := strings.ToLower(filepath.Base(filePath))
	isEnvFile := strings.HasPrefix(fileName, ".env")
	isDockerfile := strings.HasPrefix(fileName, "dockerfile") || strings.HasPrefix(fileName, "docker-compose")
	isDocFile := strings.HasSuffix(fileName, ".md") || strings.HasSuffix(fileName, ".txt") ||
		strings.HasSuffix(fileName, ".rst") || fileName == "readme"
	isMakefile := strings.HasPrefix(fileName, "makefile") || fileName == "gnumakefile"
	_ = strings.HasSuffix(fileName, ".json") || strings.HasSuffix(fileName, ".yaml") ||
		strings.HasSuffix(fileName, ".yml") || strings.HasSuffix(fileName, ".toml") // isConfigFile — used for future context filtering

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, check := range nonCodeChecks {
			// Context-filter: only run relevant checks
			switch check.name {
			case "real-secret-in-env-example":
				if !isEnvFile {
					continue
				}
			case "ip-in-readme", "internal-url-in-docs":
				if !isDocFile {
					continue
				}
			case "privileged-container", "docker-root-user":
				if !isDockerfile && !strings.Contains(fileName, "docker-compose") {
					continue
				}
			case "npm-unsafe-perm":
				if !isMakefile && !strings.Contains(fileName, "package.json") {
					continue
				}
			case "curl-pipe-bash", "wget-pipe-shell":
				if !isMakefile && !isDockerfile && !strings.HasSuffix(fileName, ".sh") {
					continue
				}
			}

			if match := check.pattern.FindString(line); match != "" {
				// Skip commented lines
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") ||
					strings.HasPrefix(trimmed, "<!--") || strings.HasPrefix(trimmed, ">") {
					continue
				}

				// Skip placeholder values (e.g., SECRET=your-secret-here)
				if check.name == "real-secret-in-env-example" && isPlaceholderValue(match) {
					continue
				}

				result.Findings = append(result.Findings, NonCodeFinding{
					FilePath:    relPath,
					LineNumber:  lineNum,
					Category:    check.category,
					Title:       fmt.Sprintf("%s in %s", check.name, filepath.Base(filePath)),
					Description: check.description,
					Severity:    check.severity,
					CWE:         check.cwe,
					Match:       fmt.Sprintf("  %d | %s", lineNum, strings.TrimSpace(line)),
				})
			}
		}
	}
}

// isPlaceholderValue checks if a matched secret value is a placeholder, not a real secret.
// Placeholders include: your-secret, changeme, xxx, example, test, placeholder, replace, empty, null, none, false, true, localhost, 127.0.0.1
func isPlaceholderValue(match string) bool {
	lower := strings.ToLower(match)
	placeholders := []string{
		"your", "changeme", "xxx", "example", "test", "placeholder",
		"replace", "empty", "null", "none", "false", "true",
		"localhost", "127.0.0.1", "0.0.0.0",
	}
	for _, ph := range placeholders {
		if strings.Contains(lower, "="+ph) || strings.Contains(lower, "="+ph+" ") {
			return true
		}
	}
	return false
}
