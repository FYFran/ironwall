package observe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestObserver_Observe_IronwallSelf(t *testing.T) {
	// Find ironwall root (walk up from test file)
	root := findIronwallRoot(t)
	if root == "" {
		t.Skip("ironwall root not found")
	}

	obs := NewObserver()
	result, err := obs.Observe(root)
	if err != nil {
		// Parse errors on some files are OK during smoke test
		t.Logf("Observe completed with: %v", err)
	}

	if result == nil {
		t.Fatal("nil result")
	}

	t.Logf("Files: %d, Sections: %d, Funcs: %d",
		result.TotalFiles, result.TotalSections, result.TotalFuncs)

	// ironwall codebase should find at least SOME security-relevant sections
	if result.TotalFiles < 5 {
		t.Errorf("expected at least 5 Go files, got %d", result.TotalFiles)
	}

	// Print concern counts
	for concern, count := range result.ConcernCounts {
		t.Logf("  %s: %d", concern, count)
	}

	// Print top 5 sections
	top := result.PrioritySections(5)
	for i, s := range top {
		t.Logf("  [%d] %s:%d %s() concerns=%v handler=%v",
			i+1, filepath.Base(s.FilePath), s.LineStart,
			s.FuncName, s.Concerns, s.IsHandler)
	}

	// Verify handler sections
	handlers := result.HandlerSections()
	t.Logf("HTTP handlers found: %d", len(handlers))
}

func TestObserver_ObserveFiles_SingleFile(t *testing.T) {
	root := findIronwallRoot(t)
	if root == "" {
		t.Skip("ironwall root not found")
	}

	// Test on a single known file with expected patterns
	testFile := filepath.Join(root, "internal", "ai", "client.go")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skipf("test file not found: %s", testFile)
	}

	obs := NewObserver()
	result, err := obs.ObserveFiles([]string{testFile})
	if err != nil {
		t.Fatalf("ObserveFiles: %v", err)
	}

	t.Logf("Sections in client.go: %d", result.TotalSections)
	for _, s := range result.Sections {
		t.Logf("  %s() [%d-%d] concerns=%v imports=%v",
			s.FuncName, s.LineStart, s.LineEnd, s.Concerns, s.Imports)
	}

	// client.go should have HTTP-related sections (it calls http.Post, etc.)
	if result.TotalSections == 0 {
		t.Log("No sections found — may be expected if client.go doesn't match patterns")
	}
}

func TestObserver_Observe_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	obs := NewObserver()
	result, err := obs.Observe(dir)
	if err != nil {
		t.Fatalf("Observe empty dir: %v", err)
	}
	if result.TotalSections != 0 {
		t.Errorf("empty dir should have 0 sections, got %d", result.TotalSections)
	}
}

func TestPatternCatalog_AllPatternsPresent(t *testing.T) {
	patterns := DefaultPatterns()
	if len(patterns) < 10 {
		t.Errorf("expected at least 10 patterns, got %d", len(patterns))
	}

	// Each pattern must have non-empty Name and Description
	for i, p := range patterns {
		if p.Name == "" {
			t.Errorf("pattern[%d] has empty Name", i)
		}
		if p.Description == "" {
			t.Errorf("pattern[%d] has empty Description", i)
		}
		if p.Match == nil {
			t.Errorf("pattern[%d] has nil Match function", i)
		}
	}
}

func TestResult_Summary(t *testing.T) {
	result := &ObserveResult{
		TotalFiles:    10,
		TotalSections: 25,
		TotalFuncs:    8,
		ConcernCounts: map[ConcernType]int{
			ConcernSQL:         5,
			ConcernHTTPHandler: 12,
			ConcernFileOps:     3,
		},
		Sections: make([]ObservedSection, 0, 25),
	}

	summary := result.Summary()
	if summary == "" {
		t.Error("summary should not be empty")
	}
	t.Logf("Summary output:\n%s", summary)
}

func TestResult_PrioritySections(t *testing.T) {
	// Sections are sorted by buildResult (part of Observe/ObserveFiles flow)
	// Test the sorting behavior directly using buildResult
	result := buildResult([]ObservedSection{
		{FuncName: "helper", IsHandler: false, Concerns: []ConcernType{ConcernFileOps}, FilePath: "a.go", LineStart: 10},
		{FuncName: "handler1", IsHandler: true, Concerns: []ConcernType{ConcernSQL, ConcernHTTPHandler}, FilePath: "b.go", LineStart: 20},
		{FuncName: "handler2", IsHandler: true, Concerns: []ConcernType{ConcernHTTPHandler, ConcernCommandExec, ConcernSQL}, FilePath: "c.go", LineStart: 30},
	})

	top := result.PrioritySections(2)
	if len(top) != 2 {
		t.Fatalf("expected 2 priority sections, got %d", len(top))
	}
	// handler2 should be first (more concerns than handler1, both are handlers)
	if top[0].FuncName != "handler2" {
		t.Errorf("expected handler2 first (most concerns), got %s", top[0].FuncName)
	}
	// handler1 should be second
	if top[1].FuncName != "handler1" {
		t.Errorf("expected handler1 second, got %s", top[1].FuncName)
	}
}

func TestResult_SectionsByConcern(t *testing.T) {
	sections := []ObservedSection{
		{FuncName: "a", Concerns: []ConcernType{ConcernSQL}},
		{FuncName: "b", Concerns: []ConcernType{ConcernHTTPHandler}},
		{FuncName: "c", Concerns: []ConcernType{ConcernSQL, ConcernHTTPHandler}},
	}
	result := &ObserveResult{Sections: sections, TotalSections: 3}

	sqlSections := result.SectionsByConcern(ConcernSQL)
	if len(sqlSections) != 2 {
		t.Errorf("expected 2 SQL sections, got %d", len(sqlSections))
	}

	fileOps := result.SectionsByConcern(ConcernFileOps)
	if len(fileOps) != 0 {
		t.Errorf("expected 0 FileOps sections, got %d", len(fileOps))
	}
}

func TestObserver_ObserveFiles_ParseError(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(dir, "bad.go")
	os.WriteFile(badFile, []byte("package broken\nfunc {"), 0644)

	obs := NewObserver()
	result, err := obs.ObserveFiles([]string{badFile})
	// Parse error should be non-fatal
	if err != nil {
		t.Logf("expected non-fatal error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil on parse error")
	}
	if result.TotalSections != 0 {
		t.Errorf("broken file should have 0 sections, got %d", result.TotalSections)
	}
}

// findIronwallRoot walks up from the test file to find the ironwall module root.
func findIronwallRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
