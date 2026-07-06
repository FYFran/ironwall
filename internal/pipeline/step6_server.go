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
	"github.com/FYFran/ironwall/internal/scanner"
)

// Step6Server analyzes server configuration and IaC files for security issues.
// Uses regex-based checks + nuclei + KICS (optional, for deep IaC analysis).
type Step6Server struct{}

func (s *Step6Server) Name() string { return "Step 6: Server & IaC Configuration" }
func (s *Step6Server) Description() string {
	return "Analyze nginx, Dockerfile, env, Terraform, K8s for misconfigurations (regex + nuclei + KICS)"
}
func (s *Step6Server) IsSkippable() bool       { return true }
func (s *Step6Server) RequiredTools() []string { return nil }

// Server config file patterns.
var serverConfigFiles = map[string]bool{
	"nginx.conf": true, "default.conf": true,
	"Dockerfile": true, "docker-compose.yml": true, "docker-compose.yaml": true,
	".env": true, ".env.example": true, ".env.production": true, ".env.local": true,
	"docker-compose.override.yml": true,
	"supervisord.conf": true, "httpd.conf": true, "apache2.conf": true,
	"Caddyfile": true, "traefik.yml": true, "traefik.toml": true,
	// IaC files
	"main.tf": true, "variables.tf": true, "outputs.tf": true, "terraform.tfvars": true,
	"*.tf": true, "*.tfvars": true,
	"deployment.yaml": true, "deployment.yml": true, "service.yaml": true,
}

// Server security checks.
var serverChecks = []struct {
	name     string
	pattern  *regexp.Regexp
	severity report.Severity
	category string
	message  string
	fix      string
}{
	{
		name:     "TLS verification disabled",
		pattern:  regexp.MustCompile(`(?i)(InsecureSkipVerify|verify_ssl|verify\s*[:=]\s*false|tls_verify\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0)`),
		severity: report.SevCritical,
		category: "insecure-configuration",
		message:  "TLS certificate verification is disabled. This enables man-in-the-middle attacks.",
		fix:      "Enable TLS verification. Remove InsecureSkipVerify or set verify_ssl to true.",
	},
	{
		name:     "Debug mode enabled",
		pattern:  regexp.MustCompile(`(?i)(DEBUG\s*=\s*(true|1|on)|debug\s*[:=]\s*true|APP_DEBUG\s*=\s*true)`),
		severity: report.SevMedium,
		category: "debug-mode-enabled",
		message:  "Debug mode is enabled. This can leak stack traces, environment variables, and internal paths to attackers.",
		fix:      "Set DEBUG=false or APP_DEBUG=false in production.",
	},
	{
		name:     "CORS wildcard origin",
		pattern:  regexp.MustCompile(`(?i)(Access-Control-Allow-Origin\s*[:=]\s*["']?\*|allow_origins\s*[:=]\s*\[?["']\*|CORS_ORIGIN\s*=\s*\*)`),
		severity: report.SevMedium,
		category: "cors-misconfiguration",
		message:  "CORS is configured with wildcard (*) origin. This allows any website to make authenticated requests.",
		fix:      "Specify explicit allowed origins instead of wildcard.",
	},
	{
		name:     "Missing security headers",
		pattern:  regexp.MustCompile(`(?i)(X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|X-XSS-Protection)`),
		severity: report.SevLow,
		category: "missing-security-header",
		message:  "Server config should include security headers (HSTS, X-Frame-Options, etc.).",
		fix:      "Add security headers to your nginx/apache/application config.",
	},
	{
		name:     "Docker running as root",
		pattern:  regexp.MustCompile(`(?i)(USER\s+root|USER\s+0)`),
		severity: report.SevHigh,
		category: "insecure-configuration",
		message:  "Docker container runs as root. If compromised, attacker gets full container privileges.",
		fix:      "Add USER directive with a non-root user.",
	},
	{
		name:     "Exposed Docker daemon socket",
		pattern:  regexp.MustCompile(`(?i)/var/run/docker\.sock`),
		severity: report.SevCritical,
		category: "insecure-configuration",
		message:  "Docker socket is mounted in container. This grants container root access to the host.",
		fix:      "Remove Docker socket mount unless absolutely necessary. Use docker-api-proxy instead.",
	},
	{
		name:     "Database port exposed publicly",
		pattern:  regexp.MustCompile(`(?i)(ports\s*:\s*.*["']?(3306|5432|27017|6379|1521):)`),
		severity: report.SevHigh,
		category: "insecure-configuration",
		message:  "Database port is exposed publicly. Databases should not be directly accessible from the internet.",
		fix:      "Bind database ports to 127.0.0.1 only, or use an internal Docker network.",
	},
	{
		name:     "Unsafe Docker COPY",
		pattern:  regexp.MustCompile(`(?i)COPY\s+\.\s+\.`),
		severity: report.SevLow,
		category: "insecure-configuration",
		message:  "Dockerfile uses COPY . which copies everything including .git, .env, and sensitive files into the image.",
		fix:      "Use .dockerignore file to exclude sensitive files from Docker build context.",
	},
	{
		name:     "S3 bucket public ACL",
		pattern:  regexp.MustCompile(`(?i)(acl\s*=\s*"public-read"|acl\s*=\s*"public-read-write"|acl\s*=\s*"authenticated-read")`),
		severity: report.SevCritical,
		category: "insecure-configuration",
		message:  "S3 bucket or object has public ACL. Data may be accessible to anyone.",
		fix:      "Set ACL to 'private' and use IAM policies for controlled access.",
	},
	{
		name:     "Kubernetes privileged container",
		pattern:  regexp.MustCompile(`(?i)(privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true)`),
		severity: report.SevCritical,
		category: "insecure-configuration",
		message:  "Container runs in privileged mode or allows privilege escalation. Container escape risk.",
		fix:      "Set privileged: false and allowPrivilegeEscalation: false.",
	},
}

func (s *Step6Server) Run(ctx context.Context, target string) ([]report.Finding, error) {
	var findings []report.Finding

	// Regex-based checks (always on, no external deps)
	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		filename := strings.ToLower(filepath.Base(path))
		if !serverConfigFiles[filepath.Base(path)] && !serverConfigFiles[filename] {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		relPath, _ := filepath.Rel(target, path)
		if relPath == "" {
			relPath = path
		}

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, check := range serverChecks {
				if check.pattern.MatchString(line) {
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
						continue
					}

					findings = append(findings, report.Finding{
						Title:         fmt.Sprintf("%s in %s", check.name, filepath.Base(path)),
						Description:   fmt.Sprintf("%s\nFound at line %d: %s", check.message, lineNum, strings.TrimSpace(line)),
						Severity:      check.severity,
						FilePath:      relPath,
						LineNumber:    lineNum,
						CodeSnippet:   fmt.Sprintf("  %d | %s", lineNum, strings.TrimSpace(line)),
						Step:          6,
						Category:      check.category,
						CWE:           mapCategoryToCWE(check.category),
						CVSS:          severityToCVSS(check.severity),
						FixSuggestion: check.fix,
					})
				}
			}
		}
		return nil
	})
	if err != nil {
		return findings, err
	}

	// KICS: Deep IaC scanning (optional, if installed)
	// Covers Terraform, CloudFormation, K8s, Docker, Helm, Ansible, Pulumi, etc.
	// 2400+ built-in queries, Apache 2.0 license
	kicsResult, kicsErr := scanner.RunKICS(target)
	if kicsErr == nil {
		findings = append(findings, kicsResult.ToFindings()...)
	}

	// Nuclei: Config misconfiguration scanning (optional, if installed)
	nucleiResult, nucleiErr := scanner.RunNuclei(target)
	if nucleiErr == nil {
		findings = append(findings, nucleiResult.ToFindings()...)
	}

	return findings, nil
}

func mapCategoryToCWE(cat string) string {
	switch cat {
	case "insecure-configuration":
		return "CWE-16"
	case "debug-mode-enabled":
		return "CWE-489"
	case "cors-misconfiguration":
		return "CWE-942"
	case "missing-security-header":
		return "CWE-693"
	default:
		return "CWE-16"
	}
}
