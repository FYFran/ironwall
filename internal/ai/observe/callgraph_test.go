package observe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildCallGraph_GoTarget(t *testing.T) {
	// Find go_target directory relative to ironwall root
	rootDir := findGoTarget(t)
	if rootDir == "" {
		t.Skip("go_target not found — skipping integration test")
	}

	result, err := BuildCallGraph(rootDir)
	if err != nil {
		t.Fatalf("BuildCallGraph failed: %v", err)
	}

	if result.Index.ModulePath == "" {
		t.Error("module path not detected")
	}
	t.Logf("Module: %s", result.Index.ModulePath)

	if result.TotalFuncs == 0 {
		t.Error("no functions indexed")
	}
	t.Logf("Functions indexed: %d", result.TotalFuncs)
	t.Logf("Call edges: %d", result.TotalEdges)
	t.Logf("Packages: %d", len(result.Index.Packages))

	for pkgPath, pkg := range result.Index.Packages {
		t.Logf("  Package %s: %d funcs, %d methods, %d files",
			pkgPath, len(pkg.Funcs), countMethods(pkg.Methods), len(pkg.Files))
	}

	// Verify JSON serialization
	data, err := result.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("JSON output empty")
	}

	// Check for cross-file edges — the main value of call graph
	crossFileEdges := 0
	for _, pkg := range result.Index.Packages {
		for _, fi := range pkg.Funcs {
			for _, caller := range fi.Callers {
				if filepath.Base(caller.File) != filepath.Base(fi.File) {
					crossFileEdges++
				}
			}
		}
	}
	t.Logf("Cross-file edges: %d", crossFileEdges)
	if crossFileEdges == 0 && result.TotalEdges > 0 {
		t.Log("WARNING: no cross-file edges — all calls are same-file (this may be normal for small targets)")
	}

	// Validate WalkTaint for a known handler
	chains := result.WalkTaint("", "Login", 3)
	t.Logf("Taint chains from Login: %d", len(chains))
	for i, chain := range chains {
		var steps []string
		for _, edge := range chain {
			steps = append(steps, edge.FuncName)
		}
		t.Logf("  Chain %d: %s", i, strings.Join(steps, " → "))
	}
}

func TestBuildCallGraph_Self(t *testing.T) {
	// Test call graph on ironwall's own observe package
	rootDir, err := filepath.Abs("../../../..")
	if err != nil {
		t.Skip("cannot resolve ironwall root")
	}

	result, err := BuildCallGraph(rootDir)
	if err != nil {
		t.Fatalf("BuildCallGraph on self failed: %v", err)
	}

	t.Logf("Self-analysis: %d funcs, %d edges, %d packages",
		result.TotalFuncs, result.TotalEdges, len(result.Index.Packages))

	// Save JSON for inspection
	data, _ := result.ToJSON()
	jsonPath := filepath.Join(os.TempDir(), "ironwall_callgraph_self.json")
	if err := os.WriteFile(jsonPath, data, 0644); err == nil {
		t.Logf("Saved callgraph to %s", jsonPath)
	}

	// Quick sanity
	if result.TotalFuncs < 10 {
		t.Errorf("Expected at least 10 functions in ironwall, got %d", result.TotalFuncs)
	}
}

func findGoTarget(t *testing.T) string {
	// Look for the go_target battle test directory
	candidates := []string{
		"../../../battle_test_candidates/go_target",
		"../../battle_test_candidates/go_target",
	}
	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		if info, err := os.Stat(abs); err == nil && info.IsDir() {
			return abs
		}
	}
	return ""
}

func countMethods(methods map[string]map[string]*FuncInfo) int {
	n := 0
	for _, m := range methods {
		n += len(m)
	}
	return n
}

// TestPythonObserve_Integration runs OBSERVE + call graph on the secure-file-management target.
func TestPythonObserve_Integration(t *testing.T) {
	// Resolve target path relative to ironwall root
	ironwallRoot, _ := filepath.Abs("../../../")
	target := filepath.Join(ironwallRoot, "battle_test_candidates", "secure-file-management")

	// Check if target exists
	if _, err := os.Stat(target); os.IsNotExist(err) {
		t.Skipf("target not found: %s", target)
	}

	// Run Python OBSERVE
	po := NewPythonObserver()
	result, err := po.ObserveDir(target)
	if err != nil {
		t.Fatalf("Python OBSERVE failed: %v", err)
	}

	t.Logf("Python OBSERVE: %d files, %d funcs, %d sections",
		result.TotalFiles, result.TotalFuncs, result.TotalSections)
	t.Logf("Concern counts: %v", result.ConcernCounts)

	// Verify all sections have required fields
	for _, s := range result.Sections {
		if s.FilePath == "" {
			t.Error("section has empty file path")
		}
		if s.FuncName == "" {
			t.Error("section has empty function name")
		}
		if s.CodeSnippet == "" {
			t.Errorf("section %s has empty code snippet", s.FuncName)
		}
	}

	// Verify call graph was built (Python target doesn't have Go code, so CG is nil)
	if result.CallGraph != nil {
		t.Logf("Call graph present: %d funcs, %d edges",
			result.CallGraph.TotalFuncs, result.CallGraph.TotalEdges)
	}

	// Count handlers — these are the targets for MISSING analysis
	handlerCount := 0
	for _, s := range result.Sections {
		if s.IsHandler {
			handlerCount++
			t.Logf("  Handler: [%s:%d] %s() concerns=%v",
				s.FilePath, s.LineStart, s.FuncName, s.Concerns)
		}
	}
	t.Logf("Handlers found: %d", handlerCount)

	if handlerCount < 3 {
		t.Errorf("Expected at least 3 handlers, got %d", handlerCount)
	}
}

// Test marshaling round-trip
func TestCallGraphJSON(t *testing.T) {
	result := &CallGraphResult{
		Index: &CallGraphIndex{
			ModulePath: "test/module",
			Packages: map[string]*PkgInfo{
				"test/module/db": {
					Dir:   "db/",
					Files: []string{"user.go"},
					Funcs: map[string]*FuncInfo{
						"CreateUser": {
							File:     "db/user.go",
							DeclLine: 42,
							PkgPath:  "test/module/db",
							Params:   []ParamInfo{{Name: "req", Type: "*CreateUserRequest"}},
							Callers:  []CallEdge{},
							Callees: []CallEdge{
								{File: "db/validate.go", FuncName: "ValidateInput", Line: 45},
							},
						},
					},
				},
			},
		},
		TotalFuncs: 1,
		TotalEdges: 1,
	}

	data, err := result.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	var decoded CallGraphResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.TotalFuncs != 1 || decoded.TotalEdges != 1 {
		t.Errorf("round-trip mismatch: funcs=%d edges=%d", decoded.TotalFuncs, decoded.TotalEdges)
	}
}
