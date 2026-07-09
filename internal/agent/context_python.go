package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PythonContextProvider extracts structured context from Python source files
// by calling extract_ast.py (stdlib ast module) as a subprocess.
//
// Falls back to GenericContextProvider if:
//   - python3/python is not available
//   - extract_ast.py is not found
//   - AST parsing fails (SyntaxError, Python 2 code, etc.)
type PythonContextProvider struct {
	scriptPath   string          // Path to extract_ast.py
	fallback     *GenericContextProvider
	hasPython    bool
	pythonBin    string
}

// pythonASTResponse mirrors the JSON output of extract_ast.py.
type pythonASTResponse struct {
	FilePath        string         `json:"file_path"`
	Language        string         `json:"language"`
	FindingLine     int            `json:"finding_line"`
	FindingSnippet  string         `json:"finding_snippet"`
	Imports         []string       `json:"imports"`
	Variables       []pyVarDef     `json:"variables"`
	SurroundingLines string        `json:"surrounding_lines"`
	EnclosingFunc   *pyFuncInfo    `json:"enclosing_func"`
	FileSummary     string         `json:"file_summary"`
	ParseError      string         `json:"parse_error,omitempty"`
	ParseFailed     bool           `json:"parse_failed,omitempty"`
	Error           string         `json:"error,omitempty"`
}

type pyVarDef struct {
	Name       string      `json:"name"`
	Value      interface{} `json:"value"`
	LineNumber int         `json:"line_number"`
}

type pyFuncInfo struct {
	Name      string `json:"name"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Signature string `json:"signature"`
	Body      string `json:"body,omitempty"`
}

// NewPythonContextProvider creates a Python context provider.
// scriptPath is the absolute or relative path to extract_ast.py.
func NewPythonContextProvider(scriptPath string) *PythonContextProvider {
	p := &PythonContextProvider{
		scriptPath: scriptPath,
		fallback:   NewGenericContextProvider(),
	}

	// Detect Python availability.
	for _, bin := range []string{"python3", "python"} {
		if _, err := exec.LookPath(bin); err == nil {
			p.hasPython = true
			p.pythonBin = bin
			break
		}
	}

	return p
}

func (p *PythonContextProvider) Name() string {
	return "PythonContextProvider"
}

func (p *PythonContextProvider) SupportedExtensions() []string {
	return []string{".py", ".pyw", ".pyi"}
}

// GetContext extracts context from a Python file.
func (p *PythonContextProvider) GetContext(filePath string, lineNumber int) (*FileContext, error) {
	// Fall back to text-based if Python or script is not available.
	if !p.hasPython {
		return p.fallback.GetContext(filePath, lineNumber)
	}

	absScript, err := filepath.Abs(p.scriptPath)
	if err != nil {
		return p.fallback.GetContext(filePath, lineNumber)
	}

	if _, err := os.Stat(absScript); os.IsNotExist(err) {
		return p.fallback.GetContext(filePath, lineNumber)
	}

	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return p.fallback.GetContext(filePath, lineNumber)
	}

	// Run extract_ast.py.
	cmd := exec.Command(p.pythonBin, absScript, absFile, fmt.Sprintf("%d", lineNumber))
	output, err := cmd.Output()
	if err != nil {
		// If Python script fails, try fallback.
		return p.fallback.GetContext(filePath, lineNumber)
	}

	var resp pythonASTResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return p.fallback.GetContext(filePath, lineNumber)
	}

	if resp.Error != "" {
		return p.fallback.GetContext(filePath, lineNumber)
	}

	// Convert to FileContext.
	return p.convert(&resp), nil
}

// convert transforms a pythonASTResponse into a FileContext.
func (p *PythonContextProvider) convert(resp *pythonASTResponse) *FileContext {
	ctx := &FileContext{
		FilePath:         resp.FilePath,
		Language:         LangPython,
		FindingLine:      resp.FindingLine,
		FindingSnippet:   resp.FindingSnippet,
		Imports:          resp.Imports,
		SurroundingLines: resp.SurroundingLines,
		FileSummary:      resp.FileSummary,
	}

	// Convert enclosing function.
	if resp.EnclosingFunc != nil {
		ctx.EnclosingFunc = &FuncInfo{
			Name:      resp.EnclosingFunc.Name,
			Signature: resp.EnclosingFunc.Signature,
			Body:      resp.EnclosingFunc.Body,
			StartLine: resp.EnclosingFunc.StartLine,
			EndLine:   resp.EnclosingFunc.EndLine,
		}
	}

	// Convert variables.
	for _, v := range resp.Variables {
		valStr := ""
		if v.Value != nil {
			valStr = fmt.Sprintf("%v", v.Value)
		}
		ctx.Variables = append(ctx.Variables, VarDef{
			Name:       v.Name,
			Value:      valStr,
			LineNumber: v.LineNumber,
		})
	}

	return ctx
}

// Helper to get the base directory of the ironwall project for script path resolution.
func findScriptPath(fallbackPath string) string {
	// Try relative paths from common working directories.
	candidates := []string{
		fallbackPath,
		filepath.Join("testdata", "agent_bench", "extract_ast.py"),
		filepath.Join("..", "..", "testdata", "agent_bench", "extract_ast.py"),
	}

	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}

	// Return the original — it'll fail and fall back to generic.
	return fallbackPath
}

// Ensure strings imported from context_provider.go.
var _ = strings.TrimSpace
