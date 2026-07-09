package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GenericContextProvider handles non-Go, non-Python files by reading the
// file as text and extracting context based on line numbers and simple
// heuristics (indentation-based function/block detection).
type GenericContextProvider struct{}

// NewGenericContextProvider creates a generic text-based context provider.
func NewGenericContextProvider() *GenericContextProvider {
	return &GenericContextProvider{}
}

func (p *GenericContextProvider) Name() string {
	return "GenericContextProvider"
}

func (p *GenericContextProvider) SupportedExtensions() []string {
	// This is the fallback — it handles everything.
	return []string{
		".py", ".js", ".ts", ".jsx", ".tsx", ".vue",
		".yaml", ".yml", ".json", ".toml", ".xml",
		".rb", ".rs", ".java", ".kt", ".swift",
		".c", ".cpp", ".h", ".hpp",
		".sh", ".bash", ".zsh",
		".dockerfile", ".dockerignore",
		".env", ".cfg", ".conf", ".ini",
		".md", ".txt",
	}
}

// GetContext extracts text-based context from any file.
// For Python files, this falls back to text analysis (context_python.go
// handles AST-based extraction when available).
func (p *GenericContextProvider) GetContext(filePath string, lineNumber int) (*FileContext, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", filePath, err)
	}

	lines := strings.Split(string(src), "\n")
	if lineNumber < 1 || lineNumber > len(lines) {
		return nil, fmt.Errorf("line %d out of range (file has %d lines)", lineNumber, len(lines))
	}

	lang := detectLanguage(filePath)
	ctx := &FileContext{
		FilePath:       filePath,
		Language:       lang,
		FindingLine:    lineNumber,
		FileSummary:    fmt.Sprintf("%s file, %d lines", lang, len(lines)),
	}

	// Finding snippet.
	ctx.FindingSnippet = strings.TrimSpace(lines[lineNumber-1])

	// Surrounding lines: ±5.
	surroundStart := max(0, lineNumber-6)
	surroundEnd := min(len(lines), lineNumber+5)
	ctx.SurroundingLines = strings.Join(lines[surroundStart:surroundEnd], "\n")

	// Find nearest function/block by indentation.
	funcName, startLine, endLine := findNearestBlock(lines, lineNumber)
	if funcName != "" {
		bodyStart := min(startLine, len(lines))
		bodyEnd := min(endLine+1, len(lines))
		ctx.EnclosingFunc = &FuncInfo{
			Name:      funcName,
			StartLine: startLine + 1,
			EndLine:   endLine + 1,
			Body:      strings.Join(lines[bodyStart:bodyEnd], "\n"),
		}
	}

	// Extract variable-like definitions (e.g., `KEY = "value"`, `const x = y`).
	ctx.Variables = extractTextVariables(lines, lineNumber)

	return ctx, nil
}

// detectLanguage guesses the language from file extension.
func detectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".py":
		return LangPython
	case ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs":
		return LangJS
	case ".yaml", ".yml":
		return LangYAML
	case ".go":
		return LangGo
	case ".rs":
		return "rust"
	case ".rb":
		return "ruby"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".swift":
		return "swift"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp":
		return "cpp"
	case ".sh", ".bash":
		return "shell"
	case ".json":
		return "json"
	case ".xml":
		return "xml"
	case ".toml":
		return "toml"
	default:
		return LangUnknown
	}
}

// findNearestBlock finds the nearest function/class/block definition above the target line
// using indentation heuristics. Returns (name, startLine-0based, endLine-0based).
func findNearestBlock(lines []string, targetLine int) (string, int, int) {
	if targetLine < 1 || targetLine > len(lines) {
		return "", 0, 0
	}

	targetIdx := targetLine - 1

	// Search backwards for a block header.
	for i := targetIdx; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Python: def/class
		if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "class ") ||
			strings.HasPrefix(trimmed, "async def ") {
			name := extractDefName(trimmed)
			endLine := findBlockEnd(lines, i)
			return name, i, endLine
		}

		// JavaScript/TypeScript: function/class/const/let
		if strings.Contains(trimmed, "function ") || strings.HasPrefix(trimmed, "class ") ||
			strings.HasPrefix(trimmed, "const ") && strings.Contains(trimmed, "=>") {
			name := extractJSFuncName(trimmed)
			endLine := findBlockEnd(lines, i)
			return name, i, endLine
		}

		// Go: func (already handled by context_go.go, but fallback)
		if strings.HasPrefix(trimmed, "func ") {
			name := extractGoFuncName(trimmed)
			endLine := findBlockEnd(lines, i)
			return name, i, endLine
		}

		// YAML/JSON/Config: key patterns like `key: value`
		// These don't have "blocks" per se — return the key as context.
		if strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "://") {
			parts := strings.SplitN(trimmed, ":", 2)
			key := strings.TrimSpace(parts[0])
			if isValidIdent(key) {
				return key, i, i
			}
		}
	}

	return "", 0, 0
}

// findBlockEnd finds the end of a block by tracking indentation.
func findBlockEnd(lines []string, startIdx int) int {
	if startIdx >= len(lines) {
		return startIdx
	}

	startLine := lines[startIdx]
	baseIndent := countIndent(startLine)

	// The block starts at the next line.
	for i := startIdx + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// If we encounter a line with same or less indentation than the header,
		// the block has ended (unless it's a continuation).
		indent := countIndent(line)
		if indent <= baseIndent {
			return i - 1
		}
	}
	return len(lines) - 1
}

// countIndent counts leading whitespace characters.
func countIndent(line string) int {
	count := 0
	for _, c := range line {
		if c == ' ' || c == '\t' {
			count++
		} else {
			break
		}
	}
	return count
}

// extractDefName extracts function/class name from a Python def/class line.
func extractDefName(line string) string {
	// "def myfunc(arg1, arg2):" → "myfunc"
	// "async def myfunc(arg1):" → "myfunc"
	// "class MyClass:" → "MyClass"
	trimmed := strings.TrimSpace(line)
	parts := strings.Fields(trimmed)
	for i, p := range parts {
		if p == "def" || p == "class" {
			if i+1 < len(parts) {
				name := parts[i+1]
				if idx := strings.Index(name, "("); idx >= 0 {
					name = name[:idx]
				}
				if idx := strings.Index(name, ":"); idx >= 0 {
					name = name[:idx]
				}
				return name
			}
		}
	}
	return ""
}

// extractJSFuncName extracts function name from a JS/TS function-like line.
func extractJSFuncName(line string) string {
	trimmed := strings.TrimSpace(line)
	// "function myFunc() {" → "myFunc"
	// "const myFunc = () => {" → "myFunc"
	// "class MyClass {" → "MyClass"
	parts := strings.Fields(trimmed)
	for i, p := range parts {
		if p == "function" {
			if i+1 < len(parts) {
				name := parts[i+1]
				if idx := strings.Index(name, "("); idx >= 0 {
					return name[:idx]
				}
				return name
			}
		}
		if p == "const" || p == "let" || p == "var" {
			if i+1 < len(parts) {
				name := parts[i+1]
				return strings.TrimSuffix(name, "=")
			}
		}
		if p == "class" {
			if i+1 < len(parts) {
				return strings.TrimRight(parts[i+1], "{")
			}
		}
	}
	return ""
}

// extractGoFuncName extracts function name from a Go func line.
func extractGoFuncName(line string) string {
	trimmed := strings.TrimSpace(line)
	parts := strings.Fields(trimmed)
	// "func myFunc(args) retType {" → "myFunc"
	// "func (r *Receiver) myMethod(args) {" → "myMethod"
	for i, p := range parts {
		if p == "func" {
			// Skip past receiver if present: "(r *Receiver)"
			next := i + 1
			if next < len(parts) && strings.HasPrefix(parts[next], "(") {
				next++
			}
			if next < len(parts) {
				name := parts[next]
				if idx := strings.Index(name, "("); idx >= 0 {
					return name[:idx]
				}
				return name
			}
		}
	}
	return ""
}

// extractTextVariables finds variable-like assignments near the target line.
func extractTextVariables(lines []string, targetLine int) []VarDef {
	var vars []VarDef
	start := max(0, targetLine-10)
	end := min(len(lines), targetLine+10)

	for i := start; i < end; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Pattern: NAME = VALUE (Python, YAML, config)
		if idx := strings.Index(trimmed, "="); idx > 0 {
			name := strings.TrimSpace(trimmed[:idx])
			value := strings.TrimSpace(trimmed[idx+1:])
			if isValidIdent(name) {
				vars = append(vars, VarDef{
					Name:       name,
					Value:      value,
					LineNumber: i + 1,
				})
			}
		}

		// Pattern: KEY: VALUE (YAML, JSON-ish)
		if idx := strings.Index(trimmed, ":"); idx > 0 && !strings.Contains(trimmed, "://") {
			name := strings.TrimSpace(trimmed[:idx])
			value := strings.TrimSpace(trimmed[idx+1:])
			if isValidIdent(name) && len(name) < 50 {
				// Don't duplicate = assignments.
				vars = append(vars, VarDef{
					Name:       name,
					Value:      value,
					LineNumber: i + 1,
				})
			}
		}
	}

	return vars
}

// isValidIdent checks if s looks like a valid identifier.
func isValidIdent(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Must start with letter or underscore.
	if !isLetter(s[0]) && s[0] != '_' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isLetter(s[i]) && !isDigit(s[i]) && s[i] != '_' && s[i] != '-' {
			return false
		}
	}
	return true
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
