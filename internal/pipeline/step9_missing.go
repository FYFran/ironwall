package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/FYFran/ironwall/internal/ai"
	"github.com/FYFran/ironwall/internal/missing"
	"github.com/FYFran/ironwall/internal/report"
)

// Step9Missing detects ABSENT security controls.
// Core competitive moat — no other SAST tool does absence detection.
//
// Brain B adversarial review PASSED (3 attacks resolved):
//   Attack #1 fix: Effectiveness validation (not just presence check)
//   Attack #2 fix: Architecture context for Bear agent (in step10)
//   Attack #3 fix: Framework-aware profiles from go.mod/requirements.txt
type Step9Missing struct {
	engine *ai.Engine
}

func NewStep9Missing(engine *ai.Engine) *Step9Missing {
	return &Step9Missing{engine: engine}
}

func (s *Step9Missing) Name() string        { return "Step 9: MISSING Detection" }
func (s *Step9Missing) Description() string { return "Detect absent security controls: rate limiting, auth, CSRF, input validation, security headers" }
func (s *Step9Missing) IsSkippable() bool   { return true }
func (s *Step9Missing) RequiredTools() []string { return nil }

func (s *Step9Missing) Run(ctx context.Context, target string) ([]report.Finding, error) {
	// Phase A: Detect framework
	profile := missing.DetectFramework(target)
	if profile == nil {
		log.Printf("[step9] No recognized web framework — skipping MISSING detection")
		return nil, nil
	}
	log.Printf("[step9] Framework: %s | builtin:%d recommended:%d",
		profile.Name, len(profile.BuiltinControls), len(profile.RecommendedThirdParty))

	// Extract endpoints from handler files
	endpoints := s.extractEndpoints(target)
	if len(endpoints) == 0 {
		log.Printf("[step9] No endpoints found — skipping")
		return nil, nil
	}
	log.Printf("[step9] %d endpoints to check for missing controls", len(endpoints))

	// Phase B: Presence + Effectiveness check
	checker := &missing.PresenceChecker{
		Profile: profile,
		Target:  target,
	}
	missingFindings := checker.CheckAllEndpoints(endpoints)

	// Phase C: Convert to report.Findings
	var findings []report.Finding
	for _, mf := range missingFindings {
		f := report.Finding{
			Title:         fmt.Sprintf("Missing %s on %s", mf.MissingControl, mf.Endpoint),
			Description:   s.buildDescription(mf, profile),
			Severity:      mf.Severity,
			FilePath:      mf.FilePath,
			LineNumber:    mf.LineNumber,
			Step:          9,
			Category:      "missing-" + mf.Category,
			CWE:           mf.CWE,
			CVSS:          severityToCVSS(mf.Severity),
			FixSuggestion: mf.FixSuggestion,
		}
		if mf.Evidence != "" {
			f.CodeSnippet = "Evidence: " + mf.Evidence
		}
		if mf.Effectiveness != "" {
			f.Description += fmt.Sprintf("\n\nEffectiveness check: %s", mf.Effectiveness)
		}
		findings = append(findings, f)
	}

	// AI verification
	if s.engine != nil && s.engine.Available() && len(findings) > 0 {
		var status ai.AnalysisStatus
		findings, status = s.engine.Analyze(ctx, findings)
		if status.TriageErrors > 0 {
			log.Printf("[step9] AI partial: %d/%d triaged", status.TriageRuns-status.TriageErrors, status.TriageRuns)
		}
	}

	log.Printf("[step9] Complete: %d missing controls found", len(findings))
	return findings, nil
}

// extractEndpoints scans handler files for route definitions.
func (s *Step9Missing) extractEndpoints(target string) []missing.EndpointInfo {
	var endpoints []missing.EndpointInfo

	// Gin/Echo patterns: r.GET("/path", handler)
	goRouteRe := regexp.MustCompile(`(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]+)"\s*,\s*(\w+)`)
	// Flask patterns: @app.route("/path", methods=["GET", "POST"])
	flaskRouteRe := regexp.MustCompile(`@\w+\.route\s*\(\s*"([^"]+)"`)
	flaskMethodsRe := regexp.MustCompile(`methods\s*=\s*\[([^\]]+)\]`)
	// Dart/Flutter patterns: GoRoute(path: '/home', ...), '/route': (context) => Widget()
	dartRouteRe := regexp.MustCompile(`(?:GoRoute|Route)\s*\(\s*path\s*:\s*'([^']+)'`)

	_ = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" ||
				base == "__pycache__" || base == ".venv" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".go" && ext != ".py" && ext != ".dart" {
			return nil
		}

		// Skip test files
		fn := filepath.Base(path)
		if strings.HasPrefix(fn, "test_") || strings.HasSuffix(fn, "_test.go") || strings.HasSuffix(fn, "_test.py") {
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
		scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		lineNum := 0
		var prevLine string

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// Go routes: r.GET("/path", handler)
			if matches := goRouteRe.FindStringSubmatch(line); len(matches) >= 5 {
				routerGroup := matches[1]
				isPublic := strings.Contains(strings.ToLower(line), "public") ||
					strings.Contains(strings.ToLower(line), "noauth") ||
					strings.Contains(strings.ToLower(line), "no_auth") ||
					strings.EqualFold(routerGroup, "public")
				endpoints = append(endpoints, missing.EndpointInfo{
					Method:      strings.ToUpper(matches[2]),
					Path:        matches[3],
					Handler:     matches[4],
					RouterGroup: routerGroup,
					FilePath:   relPath,
					LineNumber: lineNum,
					IsPublic:   isPublic,
				})
			}

			// Flask routes: @app.route("/path", methods=["GET"])
			if strings.Contains(line, "@") && strings.Contains(line, ".route(") {
				routeMatches := flaskRouteRe.FindStringSubmatch(line)
				if len(routeMatches) >= 2 {
					routePath := routeMatches[1]
					methods := []string{"GET"} // default

					// Check current line for methods=
					if mMatches := flaskMethodsRe.FindStringSubmatch(line); len(mMatches) >= 2 {
						methods = parseMethodList(mMatches[1])
					} else if prevLine != "" {
						// Check if methods= is on a continuation line
						if mMatches := flaskMethodsRe.FindStringSubmatch(prevLine); len(mMatches) >= 2 {
							methods = parseMethodList(mMatches[1])
						}
					}

					isPublic := strings.Contains(strings.ToLower(line), "public") ||
						strings.Contains(strings.ToLower(prevLine), "public")

					for _, m := range methods {
						endpoints = append(endpoints, missing.EndpointInfo{
							Method:     m,
							Path:       routePath,
							FilePath:   relPath,
							LineNumber: lineNum,
							IsPublic:   isPublic,
						})
					}
				}
			}
			// Dart/Flutter routes
			if ext == ".dart" {
				if matches := dartRouteRe.FindStringSubmatch(line); len(matches) >= 2 {
					isPublic := strings.Contains(strings.ToLower(line), "public")
					endpoints = append(endpoints, missing.EndpointInfo{
						Method: "GET", Path: matches[1], FilePath: relPath,
						LineNumber: lineNum, IsPublic: isPublic,
					})
				}
			}

			if strings.TrimSpace(line) != "" {
				prevLine = line
			}
		}
		return nil
	})

	return endpoints
}

func parseMethodList(s string) []string {
	var methods []string
	for _, m := range strings.Split(s, ",") {
		m = strings.Trim(strings.TrimSpace(m), "\"'")
		if m != "" {
			methods = append(methods, strings.ToUpper(m))
		}
	}
	return methods
}

func (s *Step9Missing) buildDescription(mf missing.MissingFinding, profile *missing.FrameworkProfile) string {
	desc := fmt.Sprintf("The endpoint `%s` is missing **%s** protection.", mf.Endpoint, mf.MissingControl)

	if profile.IsExplicitlyNotBuiltin(mf.MissingControl) {
		desc += fmt.Sprintf("\n\n**%s does NOT provide %s by default.** You must add it manually.", profile.Name, mf.MissingControl)
	}

	switch mf.Category {
	case "auth":
		desc += "\n\nRisk: Unauthenticated access could expose sensitive data or allow unauthorized actions (CWE-306)."
	case "traffic":
		desc += "\n\nRisk: Without rate limiting, vulnerable to brute-force, credential stuffing, and DoS (CWE-770)."
	case "injection":
		desc += "\n\nRisk: Unvalidated input is the #1 cause of injection attacks — SQLi, XSS, command injection (CWE-20)."
	case "defense":
		desc += "\n\nRisk: Missing security headers weaken defense-in-depth (CWE-693)."
	}

	if mf.Evidence != "" {
		desc += "\n\nEvidence: " + mf.Evidence
	}

	return desc
}
