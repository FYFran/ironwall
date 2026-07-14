// Package missing implements "what's NOT written" security control detection.
// Unlike SAST which finds "what's written wrong," MISSING detection finds absent
// security controls: rate limiting, auth, CSRF, input validation, etc.
//
// This is Ironwall's core competitive moat — no other tool does this.
package missing

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// SecurityControl defines a security control that SHOULD exist for an endpoint.
type SecurityControl struct {
	Name             string           // e.g., "rate_limiting"
	Category         string           // e.g., "traffic", "auth", "data"
	SeverityIfMissing report.Severity // Severity when control is absent
	CWE              string           // CWE for missing control
	Description      string           // Human-readable description
	FixTemplate      string           // Language-specific fix code template

	// Detection patterns — both presence and absence indicators
	PresencePatterns  []string // Patterns indicating existence
	DisablePatterns   []string // Patterns indicating explicit disable (.disable(), =False)
	DecorativePatterns []string // Patterns indicating fake/stub implementation
}

// FrameworkProfile maps a framework to its required security controls.
type FrameworkProfile struct {
	Name            string
	DetectFiles     []string // Files indicating this framework (go.mod, requirements.txt, etc.)
	DetectImports   []string // Import paths that confirm this framework
	BuiltinControls []SecurityControl
	RecommendedThirdParty []SecurityControl
	ExplicitlyNotBuiltin []string // Controls the framework does NOT provide (user must add)
}

// Pre-defined framework profiles.
var profiles = []FrameworkProfile{
	{
		Name:          "gin",
		DetectFiles:   []string{"go.mod"},
		DetectImports: []string{"github.com/gin-gonic/gin"},
		BuiltinControls: []SecurityControl{
			{
				Name: "input_validation", Category: "injection",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-20",
				Description: "Gin binding validation (ShouldBindJSON, binding tags)",
				PresencePatterns: []string{`(?i)\.?Bind(JSON|XML|YAML|Query|Uri|Header)\b`, `binding:"`, `(?i)ShouldBind(JSON|XML|YAML|Query|Uri|Header)\b`},
				DisablePatterns:  []string{},
				FixTemplate:      "Use c.ShouldBindJSON(&req) with binding tags on struct fields.",
			},
		},
		RecommendedThirdParty: []SecurityControl{
			{
				Name: "rate_limiting", Category: "traffic",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-770",
				Description: "Rate limiting prevents brute force and DoS attacks",
				PresencePatterns:  []string{`(?i)rate.?limit`, `(?i)limiter`, `(?i)MaxRequestsPerSecond`, `(?i)rate\.NewLimiter`},
				DisablePatterns:   []string{},
				DecorativePatterns: []string{`(?i)rate\.Inf\b`},
				FixTemplate: "Use gin-contrib/limit or tollbooth: limiter := tollbooth.NewLimiter(5, nil)",
			},
			{
				Name: "csrf_protection", Category: "auth",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-352",
				Description: "CSRF tokens protect state-changing endpoints from cross-site request forgery",
				PresencePatterns:  []string{`csrf`, `CSRF`, `xsrf`, `gorilla/csrf`, `gin-contrib/csrf`},
				DisablePatterns:   []string{`csrf\.disable`, `CSRF.*=.*false`, `SkipCSRF`},
				DecorativePatterns: []string{},
				FixTemplate: "Use gin-contrib/csrf middleware: r.Use(csrf.Middleware(...))",
			},
			{
				Name: "security_headers", Category: "defense",
				SeverityIfMissing: report.SevMedium, CWE: "CWE-693",
				Description: "CSP, HSTS, X-Frame-Options, X-Content-Type-Options headers",
				PresencePatterns:  []string{`Content-Security-Policy`, `X-Frame-Options`, `STS`, `gin-contrib/secure`, `helmet`},
				DisablePatterns:   []string{},
				FixTemplate: "Use gin-contrib/secure: r.Use(secure.New(secure.Config{...}))",
			},
			{
				Name: "request_size_limit", Category: "traffic",
				SeverityIfMissing: report.SevMedium, CWE: "CWE-770",
				Description: "MaxBytesReader or request body size limit prevents memory exhaustion",
				PresencePatterns:  []string{`MaxBytesReader`, `maxMultipartMemory`, `request.?size.?limit`},
				DisablePatterns:   []string{},
				FixTemplate: "r.MaxMultipartMemory = 8 << 20 // 8MB limit",
			},
			{
				Name: "jwt_signature_verification", Category: "auth",
				SeverityIfMissing: report.SevCritical, CWE: "CWE-347",
				Description: "JWT tokens must verify signature algorithm (alg=none attack). Must check exp/iat/nbf claims.",
				PresencePatterns:  []string{`jwt\.ParseWithClaims`, `jwt\.SigningMethod`, `ParseWithClaims`, `jwt\.MapClaims`},
				DisablePatterns:   []string{`jwt\.UnsafeAllowNoneSignatureType`, `alg.*none`},
				DecorativePatterns: []string{},
				FixTemplate: "Always use jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) { if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf('unexpected signing method') } return secret, nil })",
			},
			{
				Name: "ssrf_protection", Category: "traffic",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-918",
				Description: "SSRF protection: validate/restrict outbound HTTP requests to prevent internal network access",
				PresencePatterns:  []string{`url\.Parse|http\.Get|http\.Post|http\.NewRequest`, `isInternalIP|isPrivateIP|validate.*url`, `deny.*internal|block.*private`},
				DisablePatterns:   []string{},
				DecorativePatterns: []string{},
				FixTemplate: "Validate URLs against internal IP ranges before making outbound requests. Use net.IP.IsPrivate() or block 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.",
			},
			{
				Name: "redirect_validation", Category: "auth",
				SeverityIfMissing: report.SevMedium, CWE: "CWE-601",
				Description: "Open redirect protection: validate redirect URLs against a whitelist before redirecting",
				PresencePatterns:  []string{`redirect.*whitelist|isSafeRedirect|allowedRedirects|validate.*redirect`},
				DisablePatterns:   []string{},
				DecorativePatterns: []string{},
				FixTemplate: "Maintain a whitelist of allowed redirect domains. Validate `redirect_url` parameter against the whitelist before http.Redirect().",
			},
		},
		ExplicitlyNotBuiltin: []string{"rate_limiting", "csrf_protection", "security_headers", "jwt_signature_verification", "ssrf_protection", "redirect_validation"},
	},
	{
		Name:          "flask",
		DetectFiles:   []string{"requirements.txt", "Pipfile", "pyproject.toml"},
		DetectImports: []string{"flask", "Flask"},
		BuiltinControls: []SecurityControl{},
		RecommendedThirdParty: []SecurityControl{
			{
				Name: "rate_limiting", Category: "traffic",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-770",
				Description: "Rate limiting prevents brute force and DoS attacks",
				PresencePatterns:  []string{`rate.?limit`, `limiter`, `Flask-Limiter`, `flask_limiter`, `Limiter\(`},
				DisablePatterns:   []string{},
				DecorativePatterns: []string{`@limiter\.exempt`},
				FixTemplate: "Use Flask-Limiter: limiter = Limiter(app, default_limits=['100/hour'])",
			},
			{
				Name: "auth", Category: "auth",
				SeverityIfMissing: report.SevCritical, CWE: "CWE-306",
				Description: "Authentication required for non-public endpoints",
				PresencePatterns:  []string{`@login_required`, `@jwt_required`, `flask_login`, `current_user`, `g\.user`},
				DisablePatterns:   []string{`login_exempt`, `@public`, `auth\.disabled`},
				DecorativePatterns: []string{},
				FixTemplate: "Use @login_required decorator or JWT: @jwt_required()",
			},
			{
				Name: "csrf_protection", Category: "auth",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-352",
				Description: "CSRF tokens for state-changing endpoints",
				PresencePatterns:  []string{`csrf`, `CSRF`, `wtforms`, `Flask-WTF`, `SeaSurf`, `CSRFProtect`},
				DisablePatterns:   []string{`WTF_CSRF_ENABLED\s*=\s*False`, `csrf\.exempt`},
				FixTemplate: "Use Flask-WTF CSRFProtect: CSRFProtect(app)",
			},
			{
				Name: "security_headers", Category: "defense",
				SeverityIfMissing: report.SevMedium, CWE: "CWE-693",
				Description: "CSP, HSTS, and other security headers",
				PresencePatterns:  []string{`Talisman`, `flask-talisman`, `Content-Security-Policy`, `SECURITY_HEADERS`},
				FixTemplate: "Use Flask-Talisman: Talisman(app, content_security_policy={...})",
			},
			{
				Name: "input_validation", Category: "injection",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-20",
				Description: "Input validation prevents injection and data corruption",
				PresencePatterns:  []string{`pydantic`, `marshmallow`, `cerberus`, `schema`, `validate`, `@validates`},
				FixTemplate: "Use Pydantic or Marshmallow for request validation.",
			},
		},
		ExplicitlyNotBuiltin: []string{"rate_limiting", "auth", "csrf_protection", "security_headers", "input_validation"},
	},
	{
		Name:          "flutter",
		DetectFiles:   []string{"pubspec.yaml"},
		DetectImports: []string{"flutter", "dart"},
		BuiltinControls: []SecurityControl{
			{Name: "input_validation", Category: "injection", SeverityIfMissing: report.SevHigh, CWE: "CWE-20", Description: "Dart input validation (form validation, type checking)", PresencePatterns: []string{"validator:", "Formz", "validators"}, FixTemplate: "Use TextFormField(validator: ...)"},
		},
		RecommendedThirdParty: []SecurityControl{
			{Name: "auth", Category: "auth", SeverityIfMissing: report.SevCritical, CWE: "CWE-306", Description: "Auth for Flutter app", PresencePatterns: []string{"FirebaseAuth", "SignIn", "OAuth2", "token", "authService"}, FixTemplate: "Use Firebase Auth or JWT-based auth."},
			{Name: "secure_storage", Category: "data", SeverityIfMissing: report.SevHigh, CWE: "CWE-312", Description: "Use FlutterSecureStorage not SharedPreferences for secrets", PresencePatterns: []string{"FlutterSecureStorage", "flutter_secure_storage"}, DisablePatterns: []string{"SharedPreferences.*token", "SharedPreferences.*secret"}, FixTemplate: "Use flutter_secure_storage for tokens/secrets."},
		},
		ExplicitlyNotBuiltin: []string{"auth", "secure_storage"},
	},
}

// GenericProfile returns a framework-agnostic profile for unrecognized web frameworks.
// Basic security controls that apply to any HTTP framework — limited coverage but better than silent skip.
func GenericProfile() *FrameworkProfile {
	return &FrameworkProfile{
		Name: "generic",
		RecommendedThirdParty: []SecurityControl{
			{
				Name: "rate_limiting", Category: "traffic",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-770",
				Description: "Rate limiting prevents brute force and DoS attacks",
				PresencePatterns:  []string{`(?i)rate.?limit`, `(?i)limiter`, `(?i)throttle`, `(?i)MaxRequests`},
				DisablePatterns:   []string{},
				DecorativePatterns: []string{`(?i)rate\.Inf\b`},
				FixTemplate: "Add rate limiting middleware appropriate for your framework.",
			},
			{
				Name: "csrf_protection", Category: "auth",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-352",
				Description: "CSRF tokens for state-changing endpoints",
				PresencePatterns:  []string{`(?i)csrf`, `(?i)xsrf`, `(?i)csrf_token`, `(?i)csrfToken`, `(?i)_csrf`},
				DisablePatterns:   []string{`(?i)csrf\.disable`, `(?i)CSRF.*=.*false`, `(?i)SkipCSRF`},
				FixTemplate: "Add CSRF protection middleware appropriate for your framework.",
			},
			{
				Name: "security_headers", Category: "defense",
				SeverityIfMissing: report.SevMedium, CWE: "CWE-693",
				Description: "CSP, HSTS, X-Frame-Options, X-Content-Type-Options headers",
				PresencePatterns:  []string{`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `(?i)helmet`, `(?i)secure`},
				FixTemplate: "Add security headers middleware appropriate for your framework.",
			},
			{
				Name: "input_validation", Category: "injection",
				SeverityIfMissing: report.SevHigh, CWE: "CWE-20",
				Description: "Input validation prevents injection and data corruption",
				PresencePatterns:  []string{`(?i)validate`, `(?i)sanitize`, `(?i)schema`, `(?i)\.Bind`, `binding:"`},
				FixTemplate: "Add input validation appropriate for your framework.",
			},
			{
				Name: "request_size_limit", Category: "traffic",
				SeverityIfMissing: report.SevMedium, CWE: "CWE-770",
				Description: "Request body size limit prevents memory exhaustion",
				PresencePatterns:  []string{`(?i)MaxBytesReader`, `(?i)maxMultipartMemory`, `(?i)body.?size.?limit`, `(?i)client_max_body_size`, `(?i)upload.?limit`},
				FixTemplate: "Set a maximum request body size in your framework or reverse proxy.",
			},
		},
		ExplicitlyNotBuiltin: []string{"rate_limiting", "csrf_protection", "security_headers", "input_validation"},
	}
}

// DetectFramework identifies the web framework used in the target directory.
func DetectFramework(target string) *FrameworkProfile {
	for i := range profiles {
		p := &profiles[i]
		for _, df := range p.DetectFiles {
			if _, err := os.Stat(filepath.Join(target, df)); err == nil {
				// Verify import presence for Go projects
				if df == "go.mod" {
					data, err := os.ReadFile(filepath.Join(target, df))
					if err != nil {
						continue
					}
					for _, imp := range p.DetectImports {
						if strings.Contains(string(data), imp) {
							return p
						}
					}
					continue
				}
				// For Python projects, check requirements or imports
				if df == "requirements.txt" {
					data, err := os.ReadFile(filepath.Join(target, df))
					if err != nil {
						continue
					}
					for _, imp := range p.DetectImports {
						if strings.Contains(strings.ToLower(string(data)), strings.ToLower(imp)) {
							return p
						}
					}
					continue
				}
				return p
			}
		}
	}
	return nil // No recognized framework
}

// GetAllControls returns all controls (builtin + recommended) for a profile.
func (p *FrameworkProfile) GetAllControls() []SecurityControl {
	all := make([]SecurityControl, 0, len(p.BuiltinControls)+len(p.RecommendedThirdParty))
	all = append(all, p.BuiltinControls...)
	all = append(all, p.RecommendedThirdParty...)
	return all
}

// IsExplicitlyNotBuiltin checks if a control name is explicitly NOT provided by the framework.
func (p *FrameworkProfile) IsExplicitlyNotBuiltin(name string) bool {
	for _, n := range p.ExplicitlyNotBuiltin {
		if n == name {
			return true
		}
	}
	return false
}
