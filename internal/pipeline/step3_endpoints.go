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
	"github.com/FYFran/ironwall/internal/report"
)

// Step3Endpoints analyzes API route definitions for security issues.
type Step3Endpoints struct {
	aiClient *ai.Client
}

func NewStep3Endpoints(aiClient *ai.Client) *Step3Endpoints {
	return &Step3Endpoints{aiClient: aiClient}
}

func (s *Step3Endpoints) Name() string { return "Step 3: Endpoint Audit" }
func (s *Step3Endpoints) Description() string {
	return "Analyze API routes for auth, access control, and input validation issues"
}
func (s *Step3Endpoints) IsSkippable() bool       { return true }
func (s *Step3Endpoints) RequiredTools() []string { return nil }

// Route pattern matchers for different frameworks.
var routePatterns = []struct {
	framework string
	regex     *regexp.Regexp
}{
	{"Go-chi/stdio", regexp.MustCompile(`\.(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*["']([^"']+)["']`)},
	{"Go-gin", regexp.MustCompile(`\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(\s*["']([^"']+)["']`)},
	{"Go-gorilla", regexp.MustCompile(`\.HandleFunc\s*\(\s*["']([^"']+)["']`)},
	{"Go-stdlib", regexp.MustCompile(`http\.HandleFunc\s*\(\s*["']([^"']+)["']`)},
	{"Python-Flask", regexp.MustCompile(`@app\.route\s*\(\s*["']([^"']+)["']`)},
	{"Python-FastAPI", regexp.MustCompile(`@app\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)},
	{"Node-Express", regexp.MustCompile(`app\.(get|post|put|delete|patch|use)\s*\(\s*["']([^"']+)["']`)},
	{"Node-Express-Router", regexp.MustCompile(`router\.(get|post|put|delete|patch|use)\s*\(\s*["']([^"']+)["']`)},
}

// Auth middleware indicators.
var authIndicators = []string{
	"auth", "Auth", "middleware", "Middleware",
	"jwt", "JWT", "token", "Token",
	"session", "Session", "login_required",
	"loginRequired", "requireAuth", "require_auth",
	"authenticate", "Authenticate",
}

// EndpointExtensions are file types to scan for routes.
var endpointExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true,
	".rb": true, ".java": true, ".kt": true, ".php": true,
	".rs": true, ".cs": true,
}

func (s *Step3Endpoints) Run(ctx context.Context, target string) ([]report.Finding, error) {
	var allRoutes []routeInfo

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		if !endpointExtensions[filepath.Ext(path)] {
			return nil
		}

		routes := extractRoutes(path, target)
		allRoutes = append(allRoutes, routes...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk error: %w", err)
	}

	// Analyze each route
	var findings []report.Finding
	for _, route := range allRoutes {
		findings = append(findings, analyzeRoute(route)...)
	}

	return findings, nil
}

type routeInfo struct {
	File      string
	Line      int
	Method    string
	Path      string
	Framework string
	Source    string
	HasAuth   bool
}

func extractRoutes(path, target string) []routeInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var routes []routeInfo
	relPath, _ := filepath.Rel(target, path)
	if relPath == "" {
		relPath = path
	}

	scanner := bufio.NewScanner(f)
	lineNum := 0
	recentLines := make([]string, 0, 10) // Track recent lines for auth context

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		recentLines = append(recentLines, line)
		if len(recentLines) > 10 {
			recentLines = recentLines[1:]
		}

		for _, pattern := range routePatterns {
			matches := pattern.regex.FindStringSubmatch(line)
			if matches == nil {
				continue
			}

			var method, routePath string
			if len(matches) >= 3 {
				method = matches[1]
				routePath = matches[2]
			} else if len(matches) >= 2 {
				method = "ANY"
				routePath = matches[1]
			} else {
				continue
			}

			// Check if route is protected by auth middleware
			hasAuth := checkRecentLinesForAuth(recentLines) || checkLineForAuth(line)

			routes = append(routes, routeInfo{
				File:      relPath,
				Line:      lineNum,
				Method:    strings.ToUpper(method),
				Path:      routePath,
				Framework: pattern.framework,
				Source:    strings.TrimSpace(line),
				HasAuth:   hasAuth,
			})
		}
	}
	return routes
}

func checkRecentLinesForAuth(lines []string) bool {
	for _, line := range lines {
		if checkLineForAuth(line) {
			return true
		}
	}
	return false
}

func checkLineForAuth(line string) bool {
	for _, indicator := range authIndicators {
		if strings.Contains(line, indicator) {
			return true
		}
	}
	return false
}

func analyzeRoute(route routeInfo) []report.Finding {
	var findings []report.Finding

	// Auth check for sensitive operations
	method := strings.ToUpper(route.Method)
	isWriteOp := method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
	isSensitive := strings.Contains(strings.ToLower(route.Path), "admin") ||
		strings.Contains(strings.ToLower(route.Path), "delete") ||
		strings.Contains(strings.ToLower(route.Path), "payment") ||
		strings.Contains(strings.ToLower(route.Path), "user")

	if !route.HasAuth && (isWriteOp || isSensitive) {
		sev := report.SevHigh
		if strings.Contains(strings.ToLower(route.Path), "admin") {
			sev = report.SevCritical
		}

		findings = append(findings, report.Finding{
			Title:       fmt.Sprintf("Unauthenticated %s endpoint: %s", route.Method, route.Path),
			Description: fmt.Sprintf("The %s %s route has no visible authentication middleware. Sensitive operations should require authentication.", route.Method, route.Path),
			Severity:    sev,
			FilePath:    route.File,
			LineNumber:  route.Line,
			CodeSnippet: fmt.Sprintf("  %d | %s", route.Line, route.Source),
			Step:        3,
			Category:    "missing-auth",
			CWE:         "CWE-306",
			CVSS:        severityToCVSS(sev),
		})
	}

	return findings
}
