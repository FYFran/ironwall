package observe

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// PythonObserver runs Python AST analysis via subprocess.
type PythonObserver struct {
	scriptPath string // path to python_observe.py
}

// NewPythonObserver creates a PythonObserver.
// Automatically locates python_observe.py relative to this source file.
func NewPythonObserver() *PythonObserver {
	// Find the script relative to the observe package
	scriptPath := filepath.Join(filepath.Dir(locateSourceFile()), "python_observe.py")
	return &PythonObserver{scriptPath: scriptPath}
}

// locateSourceFile returns the directory of this source file at runtime.
func locateSourceFile() string {
	// Fallback: search from working directory
	if _, err := os.Stat("internal/ai/observe/python_observe.py"); err == nil {
		if abs, err := filepath.Abs("internal/ai/observe/python_observe.py"); err == nil {
			return abs
		}
	}
	// Search from executable path
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidate := filepath.Join(dir, "internal", "ai", "observe", "python_observe.py")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "internal/ai/observe/python_observe.py"
}

// ObserveDir runs Python OBSERVE on a directory and returns parsed sections.
func (po *PythonObserver) ObserveDir(target string) (*ObserveResult, error) {
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("python observe: resolve path: %w", err)
	}

	cmd := exec.Command("python", po.scriptPath, absTarget)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("python observe: %w (stderr may have details)", err)
	}

	return po.parseResult(output)
}

// ObserveFile runs Python OBSERVE on a single file.
func (po *PythonObserver) ObserveFile(filePath string) (*ObserveResult, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("python observe file: %w", err)
	}

	cmd := exec.Command("python", po.scriptPath, absPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("python observe file: %w", err)
	}

	return po.parseResult(output)
}

// parseResult parses the JSON output from python_observe.py.
func (po *PythonObserver) parseResult(output []byte) (*ObserveResult, error) {
	var raw struct {
		Sections []struct {
			FilePath     string   `json:"file_path"`
			FuncName     string   `json:"func_name"`
			LineStart    int      `json:"line_start"`
			LineEnd      int      `json:"line_end"`
			Concerns     []string `json:"concerns"`
			CodeSnippet  string   `json:"code_snippet"`
			Imports      []string `json:"imports"`
			IsHandler    bool     `json:"is_handler"`
			HasAuthCheck bool     `json:"has_auth_check"`
			PackageName  string   `json:"package_name"`
			StructName   string   `json:"struct_name"`
		} `json:"sections"`
		TotalFiles    int            `json:"total_files"`
		TotalSections int            `json:"total_sections"`
		TotalFuncs    int            `json:"total_funcs"`
		ConcernCounts map[string]int `json:"concern_counts"`
	}

	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("python observe: parse JSON: %w", err)
	}

	var sections []ObservedSection
	for _, s := range raw.Sections {
		var concerns []ConcernType
		for _, c := range s.Concerns {
			concerns = append(concerns, ConcernType(c))
		}
		sections = append(sections, ObservedSection{
			FilePath:     s.FilePath,
			FuncName:     s.FuncName,
			LineStart:    s.LineStart,
			LineEnd:      s.LineEnd,
			Concerns:     concerns,
			CodeSnippet:  s.CodeSnippet,
			Imports:      s.Imports,
			IsHandler:    s.IsHandler,
			HasAuthCheck: s.HasAuthCheck,
			PackageName:  s.PackageName,
			StructName:   s.StructName,
		})
	}

	concernCounts := make(map[ConcernType]int)
	for k, v := range raw.ConcernCounts {
		concernCounts[ConcernType(k)] = v
	}

	return &ObserveResult{
		Sections:      sections,
		TotalFiles:    raw.TotalFiles,
		TotalFuncs:    raw.TotalFuncs,
		TotalSections: raw.TotalSections,
		ConcernCounts: concernCounts,
	}, nil
}
