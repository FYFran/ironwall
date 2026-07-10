package ai

import (
	"strings"
	"testing"

	"github.com/FYFran/ironwall/internal/ai/observe"
)

func TestBuildTraceSummaryWithCG_NilChains(t *testing.T) {
	// Backward compat: nil chains should produce same output as old buildTraceSummary
	sections := []ObservedSection{
		{
			FilePath:    "handlers/auth.go",
			FuncName:    "handleLogin",
			LineStart:   42,
			LineEnd:     60,
			PackageName: "handlers",
			IsHandler:   true,
			HasAuthCheck: false,
			Concerns:    []observe.ConcernType{observe.ConcernHTTPHandler, observe.ConcernSQL},
			CodeSnippet: "func handleLogin(w http.ResponseWriter, r *http.Request) {\n    username := r.FormValue(\"username\")\n    db.Query(\"SELECT * FROM users WHERE name=\" + username)\n}",
		},
	}

	noCG := buildTraceSummaryWithCG(sections, nil)
	oldStyle := buildTraceSummary(sections)

	if noCG != oldStyle {
		t.Errorf("nil chains should produce same output as old buildTraceSummary\n--- with nil CG:\n%s\n--- old style:\n%s", noCG, oldStyle)
	}
}

func TestBuildTraceSummaryWithCG_WithChains(t *testing.T) {
	// When chains are present, the prompt should include cross-file context
	sections := []ObservedSection{
		{
			FilePath:    "handlers/auth.go",
			FuncName:    "handleLogin",
			LineStart:   42,
			LineEnd:     60,
			PackageName: "handlers",
			IsHandler:   true,
			HasAuthCheck: false,
			Concerns:    []observe.ConcernType{observe.ConcernHTTPHandler, observe.ConcernSQL},
			CodeSnippet: "func handleLogin(w http.ResponseWriter, r *http.Request) {\n    username := r.FormValue(\"username\")\n    validateUser(username)\n}",
		},
	}

	chains := []observe.TaintChain{
		{
			Source:   observe.TaintChainEntry{FuncName: "handleLogin", File: "handlers/auth.go", Line: 42},
			Sink:     observe.TaintChainEntry{FuncName: "db.Query", File: "db/user.go", Line: 156},
			Depth:    2,
			SinkType: "sql",
			Hops: []observe.TaintChainEntry{
				{FuncName: "validateUser", File: "db/user.go", Line: 140},
				{FuncName: "db.Query", File: "db/user.go", Line: 156},
			},
		},
	}

	result := buildTraceSummaryWithCG(sections, chains)

	// Should contain the cross-file context header
	if !strings.Contains(result, "Cross-File Taint Chains") {
		t.Error("Expected 'Cross-File Taint Chains' header in prompt with chains")
		t.Logf("Got:\n%s", result)
	}

	// Should contain the chain details
	if !strings.Contains(result, "handleLogin") {
		t.Error("Expected source function name in chain context")
	}
	if !strings.Contains(result, "db.Query") {
		t.Error("Expected sink function name in chain context")
	}
	if !strings.Contains(result, "validateUser") {
		t.Error("Expected intermediate hop in chain context")
	}

	// Should contain the warning about static analysis
	if !strings.Contains(result, "Static analysis only") {
		t.Error("Expected 'Static analysis only' warning for LLM")
	}

	// Should still contain the code snippet
	if !strings.Contains(result, "func handleLogin") {
		t.Error("Expected code snippet in prompt")
	}
}

func TestBuildTraceSummaryWithCG_NoRelevantChains(t *testing.T) {
	// Function that doesn't appear in any chains should get no cross-file context
	sections := []ObservedSection{
		{
			FilePath:    "utils/helper.go",
			FuncName:    "formatTimestamp",
			LineStart:   10,
			LineEnd:     15,
			PackageName: "utils",
			CodeSnippet: "func formatTimestamp(t time.Time) string { return t.Format(time.RFC3339) }",
		},
	}

	chains := []observe.TaintChain{
		{
			Source:   observe.TaintChainEntry{FuncName: "handleLogin", File: "handlers/auth.go", Line: 42},
			Sink:     observe.TaintChainEntry{FuncName: "db.Query", File: "db/user.go", Line: 156},
			Depth:    1,
			SinkType: "sql",
			Hops: []observe.TaintChainEntry{
				{FuncName: "db.Query", File: "db/user.go", Line: 156},
			},
		},
	}

	result := buildTraceSummaryWithCG(sections, chains)

	// formatTimestamp is not in any chain — should NOT get cross-file context
	if strings.Contains(result, "Cross-File Taint Chains") {
		t.Error("formatTimestamp has no relevant chains — should NOT get cross-file context")
	}
}

func TestBuildTraceSummaryWithCG_EmptyChains(t *testing.T) {
	sections := []ObservedSection{
		{
			FilePath:    "handlers/auth.go",
			FuncName:    "handleLogin",
			LineStart:   42,
			LineEnd:     60,
			PackageName: "handlers",
			CodeSnippet: "func handleLogin() {}",
		},
	}

	result := buildTraceSummaryWithCG(sections, []observe.TaintChain{})

	if strings.Contains(result, "Cross-File Taint Chains") {
		t.Error("Empty chains should NOT inject cross-file context")
	}
	// Should still contain the section
	if !strings.Contains(result, "handleLogin") {
		t.Error("Expected function name in output")
	}
}

func TestBuildTraceSummaryWithCG_MultipleSections(t *testing.T) {
	// Sections in the same batch — one with chains, one without
	sections := []ObservedSection{
		{
			FilePath:    "handlers/auth.go",
			FuncName:    "handleLogin",
			LineStart:   42,
			LineEnd:     60,
			PackageName: "handlers",
			IsHandler:   true,
			CodeSnippet: "func handleLogin(w http.ResponseWriter, r *http.Request) { validateUser(r.FormValue(\"username\")) }",
		},
		{
			FilePath:    "handlers/health.go",
			FuncName:    "handleHealth",
			LineStart:   10,
			LineEnd:     12,
			PackageName: "handlers",
			CodeSnippet: "func handleHealth(w http.ResponseWriter, r *http.Request) { w.Write([]byte(\"OK\")) }",
		},
	}

	chains := []observe.TaintChain{
		{
			Source:   observe.TaintChainEntry{FuncName: "handleLogin", File: "handlers/auth.go", Line: 42},
			Sink:     observe.TaintChainEntry{FuncName: "db.Query", File: "db/user.go", Line: 156},
			Depth:    2,
			SinkType: "sql",
			Hops: []observe.TaintChainEntry{
				{FuncName: "validateUser", File: "db/user.go", Line: 140},
				{FuncName: "db.Query", File: "db/user.go", Line: 156},
			},
		},
	}

	result := buildTraceSummaryWithCG(sections, chains)

	// handleLogin should have chains
	if !strings.Contains(result, "Cross-File Taint Chains") {
		t.Error("handleLogin should have cross-file context")
	}

	// handleHealth should still be in output
	if !strings.Contains(result, "handleHealth") {
		t.Error("handleHealth should be in output even without chains")
	}

	// Count occurrences of "Cross-File Taint Chains" — should only appear once (for handleLogin)
	count := strings.Count(result, "Cross-File Taint Chains")
	if count != 1 {
		t.Errorf("Expected 1 'Cross-File Taint Chains' block, got %d", count)
	}
}
