package observe

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// Parser walks Go source files and extracts security-relevant code sections.
type Parser struct {
	patterns []SecurityPattern
	fset     *token.FileSet
}

// NewParser creates a Parser with the given security patterns.
func NewParser(patterns []SecurityPattern) *Parser {
	return &Parser{
		patterns: patterns,
		fset:     token.NewFileSet(),
	}
}

// ParseFile parses a single Go source file and returns observed sections.
func (p *Parser) ParseFile(filePath string, src interface{}) ([]ObservedSection, error) {
	file, err := parser.ParseFile(p.fset, filePath, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filePath, err)
	}

	imports := collectImports(file)
	pkgName := file.Name.Name

	var sections []ObservedSection

	// Walk all function declarations
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		section := p.analyzeFunc(fn, file, imports, filePath, pkgName)
		if section != nil {
			sections = append(sections, *section)
		}
	}

	return sections, nil
}

// ParseDir parses all Go files in a directory and returns observed sections.
func (p *Parser) ParseDir(dirPath string) ([]ObservedSection, error) {
	var allSections []ObservedSection

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == ".git" || base == "testdata" || strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		sections, err := p.ParseFile(path, nil)
		if err != nil {
			return nil // skip files with parse errors
		}
		allSections = append(allSections, sections...)
		return nil
	})

	return allSections, err
}

// analyzeFunc checks a function declaration against all security patterns.
// Returns an ObservedSection if any pattern matches, nil otherwise.
func (p *Parser) analyzeFunc(
	fn *ast.FuncDecl,
	file *ast.File,
	imports map[string]string,
	filePath string,
	pkgName string,
) *ObservedSection {
	if fn.Body == nil {
		return nil
	}

	info := &PatternMatchInfo{
		FuncDecl:    fn,
		File:        file,
		Imports:     imports,
		FilePath:    filePath,
		PackageName: pkgName,
	}

	var concerns []ConcernType
	seenConcerns := make(map[ConcernType]bool)

	// Walk the function body looking for pattern matches
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if node == nil {
			return true
		}

		info.CallExpr = nil
		if call, ok := node.(*ast.CallExpr); ok {
			info.CallExpr = call
		}

		for _, pattern := range p.patterns {
			if seenConcerns[pattern.Name] {
				continue
			}
			if pattern.Match(node, info) {
				concerns = append(concerns, pattern.Name)
				seenConcerns[pattern.Name] = true
			}
		}

		return true
	})

	if len(concerns) == 0 {
		return nil
	}

	// Extract code snippet
	codeSnippet := extractCodeSnippet(p.fset, fn)

	// Determine if it's an HTTP handler
	isHandler := isHTTPHandler(fn, file)

	// Check for auth checks in the function body
	hasAuthCheck := detectAuthCheck(fn)

	// Get struct name for methods
	structName := ""
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		structName = receiverTypeName(fn.Recv.List[0].Type)
	}

	// Get relevant imports (only those related to concerns)
	relevantImports := filterRelevantImports(imports, concerns)

	// Get line range
	lineStart := p.fset.Position(fn.Pos()).Line
	lineEnd := p.fset.Position(fn.End()).Line

	return &ObservedSection{
		FilePath:     filePath,
		FuncName:     fn.Name.Name,
		LineStart:    lineStart,
		LineEnd:      lineEnd,
		Concerns:     concerns,
		CodeSnippet:  codeSnippet,
		Imports:      relevantImports,
		IsHandler:    isHandler,
		HasAuthCheck: hasAuthCheck,
		PackageName:  pkgName,
		StructName:   structName,
	}
}

// --- helpers ---

// collectImports builds a map of alias → import path from file imports.
func collectImports(file *ast.File) map[string]string {
	imports := make(map[string]string)
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		alias := ""
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// Use last segment of import path as alias
			parts := strings.Split(path, "/")
			alias = parts[len(parts)-1]
		}
		imports[alias] = path
	}
	return imports
}

// extractCodeSnippet returns the source code of a function declaration.
func extractCodeSnippet(fset *token.FileSet, fn *ast.FuncDecl) string {
	if fn.Body == nil {
		return ""
	}
	start := fset.Position(fn.Pos())
	end := fset.Position(fn.End())

	// Read source from the file
	data, err := os.ReadFile(start.Filename)
	if err != nil {
		// Fallback: return function signature
		var buf bytes.Buffer
		buf.WriteString("func ")
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			buf.WriteString("(" + receiverTypeName(fn.Recv.List[0].Type) + ") ")
		}
		buf.WriteString(fn.Name.Name)
		buf.WriteString("(...) { ... }")
		return buf.String()
	}

	lines := strings.Split(string(data), "\n")
	if start.Line < 1 || end.Line > len(lines) {
		return ""
	}

	// Extract lines with context (+2 lines before, full function body)
	contextStart := start.Line - 1 // 0-indexed
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := end.Line
	if contextEnd > len(lines) {
		contextEnd = len(lines)
	}

	return strings.Join(lines[contextStart:contextEnd], "\n")
}

// isHTTPHandler checks if a function is registered as an HTTP handler.
func isHTTPHandler(fn *ast.FuncDecl, file *ast.File) bool {
	// Check function signature: func(w http.ResponseWriter, r *http.Request)
	if fn.Type.Params != nil && len(fn.Type.Params.List) >= 2 {
		if isResponseWriter(fn.Type.Params.List[0].Type) &&
			isRequest(fn.Type.Params.List[1].Type) {
			return true
		}
	}

	// Check for gin.HandlerFunc, echo.HandlerFunc, etc.
	if fn.Type.Params != nil && len(fn.Type.Params.List) == 1 {
		if isContextParam(fn.Type.Params.List[0].Type) {
			return true
		}
	}

	return false
}

// isResponseWriter checks if a type is http.ResponseWriter.
func isResponseWriter(expr ast.Expr) bool {
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			return ident.Name == "http" && sel.Sel.Name == "ResponseWriter"
		}
	}
	return false
}

// isRequest checks if a type is *http.Request.
func isRequest(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		if sel, ok := star.X.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				return ident.Name == "http" && sel.Sel.Name == "Request"
			}
		}
	}
	return false
}

// isContextParam checks if a type is a framework context (gin.Context, echo.Context, etc.)
func isContextParam(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if sel, ok := expr.(*ast.SelectorExpr); ok {
		return sel.Sel.Name == "Context" || sel.Sel.Name == "Ctx"
	}
	return false
}

// detectAuthCheck looks for authentication/authorization checks in the function body.
func detectAuthCheck(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	authPatterns := []string{
		"auth", "Auth", "token", "Token", "jwt", "JWT",
		"session", "Session", "login", "Login", "permission",
		"Permission", "authorize", "Authorize", "authenticate",
		"Authenticate", "middleware", "Middleware",
		"GetSession", "GetUser", "GetClaims", "ValidateToken",
		"CheckAuth", "RequireAuth", "WithAuth",
	}
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if found {
			return false
		}
		if ident, ok := node.(*ast.Ident); ok {
			for _, ap := range authPatterns {
				if strings.Contains(ident.Name, ap) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// receiverTypeName extracts the receiver type name from an AST expression.
func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return "*" + ident.Name
		}
	}
	return ""
}

// filterRelevantImports returns only imports related to the detected concerns.
func filterRelevantImports(imports map[string]string, concerns []ConcernType) []string {
	relevant := make(map[string]bool)
	for _, c := range concerns {
		for _, path := range concernImports(c) {
			for alias, imp := range imports {
				if strings.Contains(imp, path) {
					relevant[alias+":"+imp] = true
				}
			}
		}
	}
	var result []string
	for k := range relevant {
		result = append(result, k)
	}
	return result
}

// concernImports returns import path fragments relevant to each concern type.
func concernImports(c ConcernType) []string {
	switch c {
	case ConcernSQL:
		return []string{"database/sql", "sqlx", "gorm", "squirrel", "sql"}
	case ConcernCommandExec:
		return []string{"os/exec"}
	case ConcernFileOps:
		return []string{"os", "io/ioutil", "path/filepath"}
	case ConcernCrypto:
		return []string{"crypto/", "math/rand"}
	case ConcernHTTPHandler:
		return []string{"net/http", "gin", "echo", "chi", "mux", "gorilla"}
	case ConcernSerialization:
		return []string{"encoding/json", "encoding/xml", "yaml"}
	case ConcernTemplate:
		return []string{"html/template", "text/template"}
	case ConcernNetwork:
		return []string{"net\"", "net/", "net/http", "websocket", "redis"}
	case ConcernReflection:
		return []string{"reflect", "unsafe"}
	case ConcernSSRF:
		return []string{"net/http"}
	default:
		return nil
	}
}
