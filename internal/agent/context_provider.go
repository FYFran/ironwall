// Package agent implements the Ironwall AI Agent Engine.
//
// Context providers extract structured code context around findings
// to feed into the Analyst Agent for informed reasoning.
package agent

import "fmt"

// Language constants.
const (
	LangGo     = "go"
	LangPython = "python"
	LangJS     = "javascript"
	LangYAML   = "yaml"
	LangUnknown = "unknown"
)

// VarDef describes a variable or constant definition found near a finding.
type VarDef struct {
	Name       string `json:"name"`
	Type       string `json:"type,omitempty"`       // Go type or Python type annotation
	Value      string `json:"value,omitempty"`       // Initial value if constant
	LineNumber int    `json:"line_number"`
	IsExported bool   `json:"is_exported"`
}

// FuncInfo describes a function or method containing or near a finding.
type FuncInfo struct {
	Name       string `json:"name"`        // Function name
	Receiver   string `json:"receiver,omitempty"` // Method receiver type (Go)
	Signature  string `json:"signature"`   // Full function signature
	Body       string `json:"body"`        // Complete function body
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	IsExported bool   `json:"is_exported"`
}

// FileContext is the structured context extracted around a finding.
// This is the input to the Analyst Agent's OBSERVE step.
type FileContext struct {
	FilePath         string    `json:"file_path"`
	Language         string    `json:"language"`
	FindingLine      int       `json:"finding_line"`
	FindingSnippet   string    `json:"finding_snippet"`   // The line(s) flagged by the scanner
	EnclosingFunc    *FuncInfo `json:"enclosing_func,omitempty"`
	Imports          []string  `json:"imports,omitempty"`
	Variables        []VarDef  `json:"variables,omitempty"`
	SurroundingLines string    `json:"surrounding_lines"` // ±5 lines around finding
	FileSummary      string    `json:"file_summary"`       // "Package main, 120 lines, 5 functions"
}

// ContextProvider extracts structured code context for a specific file:line.
// Different implementations handle different languages (Go, Python, generic).
type ContextProvider interface {
	// GetContext extracts context around a finding at filePath:lineNumber.
	GetContext(filePath string, lineNumber int) (*FileContext, error)

	// SupportedExtensions returns file extensions this provider handles.
	SupportedExtensions() []string

	// Name returns a human-readable provider name.
	Name() string
}

// ContextProviderRegistry manages multiple ContextProviders and
// dispatches to the correct one based on file extension.
type ContextProviderRegistry struct {
	providers map[string]ContextProvider // ext → provider
	fallback  ContextProvider            // Used when no specific provider matches
}

// NewContextProviderRegistry creates a registry with the given providers
// and a fallback for unsupported file types.
func NewContextProviderRegistry(fallback ContextProvider) *ContextProviderRegistry {
	return &ContextProviderRegistry{
		providers: make(map[string]ContextProvider),
		fallback:  fallback,
	}
}

// Register adds a provider for its supported extensions.
func (r *ContextProviderRegistry) Register(p ContextProvider) {
	for _, ext := range p.SupportedExtensions() {
		r.providers[ext] = p
	}
}

// GetContext dispatches to the correct provider based on file extension.
func (r *ContextProviderRegistry) GetContext(filePath string, lineNumber int) (*FileContext, error) {
	ext := ""
	for i := len(filePath) - 1; i >= 0; i-- {
		if filePath[i] == '.' {
			ext = filePath[i:]
			break
		}
	}
	if ext == "" {
		return nil, fmt.Errorf("cannot determine file type for: %s", filePath)
	}

	provider, ok := r.providers[ext]
	if !ok {
		provider = r.fallback
	}

	return provider.GetContext(filePath, lineNumber)
}
