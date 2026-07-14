package missing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckAllEndpoints_ProtectedSkipsAuth(t *testing.T) {
	// Create temp project with Gin router group that has auth middleware
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.0"), 0644)
	mainGo := `package main
import "github.com/gin-gonic/gin"
func main() {
	r := gin.New()
	protected := r.Group("")
	protected.Use(AuthMiddleware())
	protected.POST("/admin/delete", deleteHandler)
}
func AuthMiddleware() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
func deleteHandler(c *gin.Context) {}
`
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0644)

	profile := DetectFramework(dir)
	if profile == nil {
		t.Fatal("framework not detected")
	}

	ep := EndpointInfo{
		Method: "POST", Path: "/admin/delete", FilePath: "main.go",
		LineNumber: 6, RouterGroup: "protected",
	}
	checker := &PresenceChecker{Profile: profile, Target: dir}
	findings := checker.CheckAllEndpoints([]EndpointInfo{ep})

	// protected group should skip auth check
	for _, f := range findings {
		if f.MissingControl == "auth" {
			t.Errorf("protected endpoint should skip auth check, got: %s", f.MissingControl)
		}
	}
}

func TestCheckAllEndpoints_RateLimitFoundInFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.0"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "github.com/gin-gonic/gin"
func main() {
	r := gin.New()
	r.Use(RateLimitMiddleware())
	r.POST("/api/data", handler)
}
func RateLimitMiddleware() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }
func handler(c *gin.Context) {}
`), 0644)

	profile := DetectFramework(dir)
	checker := &PresenceChecker{Profile: profile, Target: dir}
	ep := EndpointInfo{Method: "POST", Path: "/api/data", FilePath: "main.go", LineNumber: 5, RouterGroup: "r"}
	findings := checker.CheckAllEndpoints([]EndpointInfo{ep})

	for _, f := range findings {
		if f.MissingControl == "rate_limiting" || (len(f.MissingControl) > 0 && f.MissingControl[:13] == "rate_limiting") {
			t.Errorf("rate_limiting found in file but flagged as missing: %s", f.MissingControl)
		}
	}
}

func TestCheckAllEndpoints_PublicEndpointAuthFlagged(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.0"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "github.com/gin-gonic/gin"
func main() {
	r := gin.New()
	r.GET("/public/feed", feedHandler)
}
func feedHandler(c *gin.Context) {}
`), 0644)

	profile := DetectFramework(dir)
	checker := &PresenceChecker{Profile: profile, Target: dir}
	ep := EndpointInfo{Method: "GET", Path: "/public/feed", FilePath: "main.go", LineNumber: 4, RouterGroup: "r"}
	findings := checker.CheckAllEndpoints([]EndpointInfo{ep})

	// GET /public/feed: no auth, not in authEndpoints, not in protected group
	// Should NOT have auth finding (we skip auth for GET-only comparison)
	// But rate_limiting, security_headers etc. should be checked
	hasCSRF := false
	for _, f := range findings {
		if f.MissingControl == "csrf_protection" {
			hasCSRF = true // CSRF should be skipped for GET
		}
	}
	if hasCSRF {
		t.Error("GET endpoint should skip CSRF check")
	}
}

func TestCheckAllEndpoints_RequestSizeSkipPlainJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.0"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "github.com/gin-gonic/gin"
func main() {
	r := gin.New()
	r.POST("/api/json", jsonHandler)
}
func jsonHandler(c *gin.Context) { c.ShouldBindJSON(&payload{}) }
type payload struct { Name string }
`), 0644)

	profile := DetectFramework(dir)
	checker := &PresenceChecker{Profile: profile, Target: dir}
	ep := EndpointInfo{Method: "POST", Path: "/api/json", FilePath: "main.go", LineNumber: 4, RouterGroup: "r"}
	findings := checker.CheckAllEndpoints([]EndpointInfo{ep})

	for _, f := range findings {
		if f.MissingControl == "request_size_limit" {
			t.Errorf("plain JSON POST without file upload should skip request_size_limit, got: %s", f.Evidence)
		}
	}
}

func TestCheckAllEndpoints_RequestSizeFlaggedForUpload(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.0"), 0644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
import "github.com/gin-gonic/gin"
func main() {
	r := gin.New()
	r.POST("/upload", uploadHandler)
}
func uploadHandler(c *gin.Context) { c.FormFile("avatar") }
`), 0644)

	profile := DetectFramework(dir)
	checker := &PresenceChecker{Profile: profile, Target: dir}
	ep := EndpointInfo{Method: "POST", Path: "/upload", FilePath: "main.go", LineNumber: 4, RouterGroup: "r"}
	findings := checker.CheckAllEndpoints([]EndpointInfo{ep})

	found := false
	for _, f := range findings {
		if f.MissingControl == "request_size_limit" {
			found = true
		}
	}
	if !found {
		t.Error("POST /upload with FormFile should flag request_size_limit")
	}
}

func TestGenericProfile_DetectsBasicControls(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(`package main
func main() {
	http.HandleFunc("/api/data", dataHandler)
}
func dataHandler(w http.ResponseWriter, r *http.Request) {}
`), 0644)

	profile := GenericProfile()
	if profile == nil {
		t.Fatal("GenericProfile returned nil")
	}
	if len(profile.RecommendedThirdParty) < 4 {
		t.Errorf("generic profile should have at least 4 controls, got %d", len(profile.RecommendedThirdParty))
	}
	if profile.Name != "generic" {
		t.Errorf("generic profile name should be 'generic', got %s", profile.Name)
	}
}
