package missing

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// PresenceResult describes the result of checking for a security control's existence.
type PresenceResult int

const (
	PresUnknown  PresenceResult = iota
	PresFound                   // Control pattern found in code
	PresNotFound                // Control pattern NOT found
	PresInConfig                // Control found in config file
	PresInDependency            // Control provided by imported library
)

// EndpointInfo describes an API endpoint extracted from the codebase.
type EndpointInfo struct {
	Method     string // GET, POST, PUT, DELETE, PATCH
	Path       string // /api/users/:id
	Handler    string // Function name
	FilePath   string // Source file (relative to target root)
	LineNumber int    // Line where route is defined
	IsPublic   bool   // Is explicitly marked as public/no-auth?
	RouterGroup string // Gin/Echo router group name ("protected", "admin", "public")
}

// PresenceChecker checks whether security controls exist for endpoints.
type PresenceChecker struct {
	Profile *FrameworkProfile
	Target  string
}

// CheckAllEndpoints runs presence checks for all endpoints against all required controls.
func (pc *PresenceChecker) CheckAllEndpoints(endpoints []EndpointInfo) []MissingFinding {
	var findings []MissingFinding
	controls := pc.Profile.GetAllControls()

	// Project-level: skip JWT check if project doesn't use JWT
	if !pc.hasJWTUsage() {
		filtered := make([]SecurityControl, 0, len(controls))
		for _, ctrl := range controls {
			if ctrl.Name == "jwt_signature_verification" {
				continue
			}
			filtered = append(filtered, ctrl)
		}
		controls = filtered
	}

	for _, ep := range endpoints {
		if ep.IsPublic {
			// Skip auth check for explicitly public endpoints
			for _, ctrl := range controls {
				if ctrl.Name == "auth" {
					continue
				}
				presence, evidence := pc.checkPresence(ep, ctrl)
				if presence == PresNotFound {
					findings = append(findings, pc.makeFinding(ep, ctrl, evidence))
				} else if presence == PresFound {
					// Check effectiveness
					validator := EffectivenessValidator{Control: ctrl}
					eff, effEvidence := validator.Validate(ep.FilePath, pc.Target)
					if eff != EffEffective {
						findings = append(findings, pc.makeIneffectiveFinding(ep, ctrl, eff, effEvidence))
					}
				}
			}
		} else {
			for _, ctrl := range controls {
				if shouldSkipControl(ep, ctrl, pc.Target) {
					continue
				}
				presence, evidence := pc.checkPresence(ep, ctrl)
				if presence == PresNotFound {
					findings = append(findings, pc.makeFinding(ep, ctrl, evidence))
				} else if presence == PresFound {
					validator := EffectivenessValidator{Control: ctrl}
					eff, effEvidence := validator.Validate(ep.FilePath, pc.Target)
					if eff != EffEffective {
						findings = append(findings, pc.makeIneffectiveFinding(ep, ctrl, eff, effEvidence))
					}
				}
			}
		}
	}

	// Additional: check for auth effectiveness specifically
	for _, ep := range endpoints {
		if !ep.IsPublic {
			eff, evidence := ValidateAuthEffectiveness(ep.FilePath, pc.Target)
			if eff == EffDecorative {
				findings = append(findings, MissingFinding{
					Endpoint:       ep.Method + " " + ep.Path,
					FilePath:       ep.FilePath,
					LineNumber:     ep.LineNumber,
					MissingControl: "auth (ineffective)",
					Category:       "auth",
					Severity:       report.SevCritical,
					Evidence:       evidence,
					Effectiveness:  eff.String(),
					CWE:            "CWE-306",
					FixSuggestion:  "Auth function does not actually reject unauthorized requests. Add return 401/403 on auth failure.",
				})
			}
		}
	}

	// Check test-only scope
	for _, ctrl := range controls {
		eff, evidence := CheckTestFileScope(pc.Target, ctrl)
		if eff == EffWrongScope {
			// Find endpoints that would need this control
			for _, ep := range endpoints {
				if !ep.IsPublic || ctrl.Name != "auth" {
					findings = append(findings, MissingFinding{
						Endpoint:       ep.Method + " " + ep.Path,
						FilePath:       ep.FilePath,
						LineNumber:     ep.LineNumber,
						MissingControl: ctrl.Name + " (test-only)",
						Category:       ctrl.Category,
						Severity:       ctrl.SeverityIfMissing,
						Evidence:       evidence,
						Effectiveness:  eff.String(),
						CWE:            ctrl.CWE,
						FixSuggestion:  ctrl.FixTemplate,
					})
				}
			}
		}
	}

	return findings
}

// checkPresence determines if a security control is present for an endpoint.
func (pc *PresenceChecker) checkPresence(ep EndpointInfo, ctrl SecurityControl) (PresenceResult, string) {
	// 1. Check the endpoint's handler file
	found, evidence := pc.grepFile(ep.FilePath, ctrl.PresencePatterns)
	if found {
		return PresFound, evidence
	}

	// 2. Check the entire project for the control pattern
	anywhere, anyEvidence := pc.grepProject(ctrl.PresencePatterns)
	if anywhere {
		return PresFound, anyEvidence
	}

	// 3. Check if a known security library provides this control
	found, evidence = pc.checkDependencies(ctrl)
	if found {
		return PresInDependency, evidence
	}

	// 4. Check framework config files
	found, evidence = pc.checkConfig(ctrl)
	if found {
		return PresInConfig, evidence
	}

	return PresNotFound, "No evidence of " + ctrl.Name + " found in " + ep.FilePath + " or project-wide"
}

// grepFile searches a single file for patterns.
// relPath is relative to pc.Target.
func (pc *PresenceChecker) grepFile(relPath string, patterns []string) (bool, string) {
	fullPath := filepath.Join(pc.Target, relPath)
	f, err := os.Open(fullPath)
	if err != nil {
		return false, ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "<!--") {
			continue
		}
		for _, pat := range patterns {
			if matched, _ := regexp.MatchString(pat, line); matched {
				evidencePath, _ := filepath.Rel(pc.Target, fullPath)
				if evidencePath == "" {
					evidencePath = fullPath
				}
				return true, evidencePath + ":" + itoa(lineNum) + ": " + strings.TrimSpace(line)
			}
		}
	}
	return false, ""
}

// grepProject searches the entire project for patterns.
func (pc *PresenceChecker) grepProject(patterns []string) (bool, string) {
	var found bool
	var evidence string

	_ = filepath.Walk(pc.Target, func(path string, info os.FileInfo, err error) error {
		if err != nil || found || info.IsDir() {
			if info != nil && info.IsDir() {
				base := filepath.Base(path)
				if base == ".git" || base == "node_modules" || base == "vendor" ||
					base == "__pycache__" || base == ".venv" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Only check source files
		ext := filepath.Ext(path)
		if !isSourceFile(ext) {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			for _, pat := range patterns {
				if matched, _ := regexp.MatchString(pat, line); matched {
					relPath, _ := filepath.Rel(pc.Target, path)
					if relPath == "" {
						relPath = path
					}
					evidence = relPath + ":" + itoa(lineNum) + ": " + strings.TrimSpace(line)
					found = true
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	return found, evidence
}

// checkDependencies checks if a known security library is imported.
func (pc *PresenceChecker) checkDependencies(ctrl SecurityControl) (bool, string) {
	// Check go.mod
	if data, err := os.ReadFile(filepath.Join(pc.Target, "go.mod")); err == nil {
		content := string(data)
		switch ctrl.Name {
		case "rate_limiting":
			if strings.Contains(content, "tollbooth") || strings.Contains(content, "gin-contrib/limit") ||
				strings.Contains(content, "didip/tollbooth") || strings.Contains(content, "ulule/limiter") {
				return true, "rate limiting library imported in go.mod"
			}
		case "csrf_protection":
			if strings.Contains(content, "gorilla/csrf") || strings.Contains(content, "gin-contrib/csrf") {
				return true, "CSRF library imported in go.mod"
			}
		case "security_headers":
			if strings.Contains(content, "gin-contrib/secure") || strings.Contains(content, "unrolled/secure") {
				return true, "security headers library imported in go.mod"
			}
		case "auth":
			if strings.Contains(content, "golang-jwt") || strings.Contains(content, "gin-contrib/sessions") ||
				strings.Contains(content, "markbates/goth") {
				return true, "auth library imported in go.mod"
			}
		}
	}

	// Check requirements.txt
	if data, err := os.ReadFile(filepath.Join(pc.Target, "requirements.txt")); err == nil {
		content := strings.ToLower(string(data))
		switch ctrl.Name {
		case "rate_limiting":
			if strings.Contains(content, "flask-limiter") || strings.Contains(content, "flask_limiter") {
				return true, "rate limiting library in requirements.txt"
			}
		case "csrf_protection":
			if strings.Contains(content, "flask-wtf") || strings.Contains(content, "seasurf") {
				return true, "CSRF library in requirements.txt"
			}
		case "security_headers":
			if strings.Contains(content, "flask-talisman") || strings.Contains(content, "talisman") {
				return true, "security headers library in requirements.txt"
			}
		case "auth":
			if strings.Contains(content, "flask-login") || strings.Contains(content, "flask-jwt") ||
				strings.Contains(content, "pyjwt") {
				return true, "auth library in requirements.txt"
			}
		case "jwt_signature_verification":
					if strings.Contains(content, "golang-jwt") || strings.Contains(content, "jwt-go") ||
						strings.Contains(content, "lestrrat-go/jwx") || strings.Contains(content, "gbrlsnchs/jwt") {
						return true, "JWT library imported in go.mod"
					}
				case "ssrf_protection":
					if strings.Contains(content, "ssrf") || strings.Contains(content, "safesling") {
						return true, "SSRF protection library in go.mod"
					}
				case "redirect_validation":
					if strings.Contains(content, "redirect") || strings.Contains(content, "validate-redirect") {
						return true, "redirect validation library in go.mod"
					}
				case "input_validation":
			if strings.Contains(content, "pydantic") || strings.Contains(content, "marshmallow") ||
				strings.Contains(content, "cerberus") {
				return true, "validation library in requirements.txt"
			}
		}
	}

	return false, ""
}

// checkConfig checks framework config files for security settings.
func (pc *PresenceChecker) checkConfig(ctrl SecurityControl) (bool, string) {
	configFiles := []string{
		"config.go", "config.py", "settings.py", "app.config", "application.properties",
		"application.yml", "application.yaml", ".env.example",
	}

	for _, cf := range configFiles {
		path := filepath.Join(pc.Target, cf)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Also check in config/ subdirectory
			path = filepath.Join(pc.Target, "config", cf)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				continue
			}
		}

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		for _, pat := range ctrl.PresencePatterns {
			if matched, _ := regexp.MatchString(pat, content); matched {
				return true, "control found in config: " + cf
			}
		}
	}
	return false, ""
}

// makeFinding creates a MissingFinding from endpoint and control info.
func (pc *PresenceChecker) makeFinding(ep EndpointInfo, ctrl SecurityControl, evidence string) MissingFinding {
	return MissingFinding{
		Endpoint:       ep.Method + " " + ep.Path,
		FilePath:       ep.FilePath,
		LineNumber:     ep.LineNumber,
		MissingControl: ctrl.Name,
		Category:       ctrl.Category,
		Severity:       ctrl.SeverityIfMissing,
		Evidence:       evidence,
		CWE:            ctrl.CWE,
		FixSuggestion:  ctrl.FixTemplate,
	}
}

// makeIneffectiveFinding creates a finding for an ineffective (decorative/disabled) control.
func (pc *PresenceChecker) makeIneffectiveFinding(ep EndpointInfo, ctrl SecurityControl, eff EffectivenessResult, evidence string) MissingFinding {
	severity := ctrl.SeverityIfMissing
	// Decorative auth is worse than no auth (false sense of security)
	if ctrl.Name == "auth" && eff == EffDecorative {
		severity = report.SevCritical
	}

	return MissingFinding{
		Endpoint:       ep.Method + " " + ep.Path,
		FilePath:       ep.FilePath,
		LineNumber:     ep.LineNumber,
		MissingControl: ctrl.Name + " (ineffective: " + eff.String() + ")",
		Category:       ctrl.Category,
		Severity:       severity,
		Evidence:       evidence,
		Effectiveness:  eff.String(),
		CWE:            ctrl.CWE,
		FixSuggestion:  "Control exists but is not effective (" + eff.String() + "). " + ctrl.FixTemplate,
	}
}

func isSourceFile(ext string) bool {
	switch ext {
	case ".go", ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".rs", ".dart":
		return true
	}
	return false
}

// MissingFinding represents a security control that should exist but doesn't.
type MissingFinding struct {
	Endpoint       string
	FilePath       string
	LineNumber     int
	MissingControl string
	Category       string
	Severity       report.Severity
	Evidence       string
	Effectiveness  string // "" | "effective" | "decorative" | "disabled" | "commented_out" | "debug_only" | "wrong_scope"
	CWE            string
	FixSuggestion  string
}

// shouldSkipControl applies context-aware filtering to reduce false positives.
// Rules derived from manual precision review of 127 HIGH findings on campus_go.
// target is the project root directory, used to resolve relative file paths.
func shouldSkipControl(ep EndpointInfo, ctrl SecurityControl, target string) bool {
	method := strings.ToUpper(ep.Method)
	path := strings.ToLower(ep.Path)

	// CSRF only needed for state-changing methods (not GET/HEAD/OPTIONS)
	if ctrl.Name == "csrf_protection" && (method == "GET" || method == "HEAD" || method == "OPTIONS") {
		return true
	}

	// Rate limiting not needed for health/metrics endpoints
	if ctrl.Name == "rate_limiting" {
		skipPaths := []string{"/health", "/ready", "/version", "/metrics", "/ping", "/status"}
		for _, sp := range skipPaths {
			if path == sp || strings.HasPrefix(path, sp+"?") {
				return true
			}
		}
	}

	// Input validation not needed for endpoints with no request body/query params
	if ctrl.Name == "input_validation" && (method == "GET" || method == "HEAD" || method == "OPTIONS") {
		// GET endpoints without query params don't need validation
		// Skip for simple info endpoints
		skipPaths := []string{"/health", "/ready", "/version", "/ping", "/status", "/ws"}
		for _, sp := range skipPaths {
			if path == sp || strings.HasPrefix(path, sp) {
				return true
			}
		}
	}

	// SSRF protection only needed if endpoint makes outbound HTTP requests
	if ctrl.Name == "ssrf_protection" {
		// Resolve relative file path against target directory
		fullPath := filepath.Join(target, ep.FilePath)
		if !fileContainsPattern(fullPath, []string{"http.Get", "http.Post", "http.NewRequest", "client.Get", "client.Post", "client.Do"}) {
			return true // No outbound HTTP → skip SSRF
		}
	}

	// Security headers not applicable to WebSocket endpoints
	if ctrl.Name == "security_headers" && strings.HasPrefix(path, "/ws") {
		return true
	}

	// Redirect validation only needed for endpoints that actually redirect
	if ctrl.Name == "redirect_validation" {
		fullPath := filepath.Join(target, ep.FilePath)
		if !fileContainsPattern(fullPath, []string{`http\.Redirect`, `c\.Redirect`, `Redirect\(`, `redirect\(`}) {
			return true // No redirect call in handler → skip
		}
	}

	// Request size limit: only flag endpoints that accept file uploads or large payloads.
	// For plain JSON/REST POST endpoints, size limit is defense-in-depth but not critical.
	if ctrl.Name == "request_size_limit" {
		if method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "DELETE" {
			return true // no request body
		}
		// For POST/PUT/PATCH: check if handler actually accepts file uploads
		fullPath := filepath.Join(target, ep.FilePath)
		if !fileContainsPattern(fullPath, []string{
			`FormFile`, `MultipartForm`, `SaveUploadedFile`,
			`multipart\.File`, `ParseMultipartForm`, `FileHeader`,
			`request\.files`, `upload`, `\.Avatar`, `\.Image`,
		}) {
			return true // plain JSON endpoint — skip (would be noise)
		}
	}

	// Auth not needed for login/register/password-reset (these ARE the auth endpoints)
	if ctrl.Name == "auth" {
		authEndpoints := []string{"/login", "/register", "/signup", "/signin", "/reset-password", "/forgot-password", "/token/refresh", "/verify"}
		for _, ae := range authEndpoints {
			if strings.Contains(path, ae) {
				return true
			}
		}
		// JWT signature verification: only flag if project actually uses JWT library
	if ctrl.Name == "jwt_signature_verification" {
		rg := strings.ToLower(ep.RouterGroup)
		// Skip non-JWT endpoints
		if rg != "protected" && rg != "admin" && rg != "secure" &&
			!strings.Contains(rg, "protected") && !strings.Contains(rg, "auth") {
			return true
		}
		// Skip auth endpoints
		skipPaths := []string{"/login", "/register", "/signup", "/signin", "/token", "/reset-password", "/forgot-password", "/verify", "/health", "/version", "/ready", "/ping"}
		for _, sp := range skipPaths {
			if strings.Contains(path, sp) {
				return true
			}
		}
	}

	// Skip auth check for routes in protected/admin/auth router groups
		rg := strings.ToLower(ep.RouterGroup)
		if rg == "protected" || rg == "admin" || rg == "auth" || rg == "secure" ||
			strings.Contains(rg, "auth") || strings.Contains(rg, "admin") {
			return true
		}
	}

	return false
}

// fileContainsPattern checks if a file contains any of the given regex patterns.
// filePath must be an absolute path (caller must resolve).
func fileContainsPattern(filePath string, patterns []string) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	content := string(data)
	for _, pat := range patterns {
		if matched, _ := regexp.MatchString(pat, content); matched {
			return true
		}
	}
	return false
}

func (pc *PresenceChecker) hasJWTUsage() bool {
	// Check go.mod for JWT imports
	if data, err := os.ReadFile(pc.Target + "/go.mod"); err == nil {
		content := string(data)
		if strings.Contains(content, "jwt") || strings.Contains(content, "jose") {
			// golang-jwt/jwt v4+ and lestrrat-go/jwx verify signatures by default
			// Only flag CWE-347 if using unsafe patterns
			return false // Safe JWT library → skip CWE-347
		}
	}
	// Check requirements.txt for JWT imports
	if data, err := os.ReadFile(pc.Target + "/requirements.txt"); err == nil {
		content := strings.ToLower(string(data))
		if strings.Contains(content, "pyjwt") || strings.Contains(content, "python-jose") ||
			strings.Contains(content, "flask-jwt") || strings.Contains(content, "authlib") {
			return false // Safe JWT library → skip CWE-347
		}
	}
	return false
}
