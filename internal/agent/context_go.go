package agent

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// GoContextProvider extracts structured context from Go source files
// using the standard library go/parser and go/ast packages.
//
// For each finding, it extracts:
//   - The enclosing function/method (full body + signature)
//   - All imports in the file
//   - Variable/constant definitions in scope
//   - Surrounding code (±5 lines)
//   - File-level summary (package, line count, function list)
type GoContextProvider struct{}

// NewGoContextProvider creates a Go source context provider.
func NewGoContextProvider() *GoContextProvider {
	return &GoContextProvider{}
}

func (p *GoContextProvider) Name() string {
	return "GoContextProvider"
}

func (p *GoContextProvider) SupportedExtensions() []string {
	return []string{".go"}
}

// GetContext parses a Go file and extracts context around the given line.
func (p *GoContextProvider) GetContext(filePath string, lineNumber int) (*FileContext, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read Go file %s: %w", filePath, err)
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filePath, src, parser.ParseComments)
	if err != nil {
		// If parsing fails (e.g., cgo, build tags), fall back to text-based extraction.
		return p.fallbackContext(filePath, lineNumber, src)
	}

	ctx := &FileContext{
		FilePath:       filePath,
		Language:       LangGo,
		FindingLine:    lineNumber,
		FileSummary:    buildGoFileSummary(f, filePath, len(src)),
	}

	// Extract the finding line snippet and surrounding lines.
	ctx.FindingSnippet, ctx.SurroundingLines = extractLines(src, lineNumber, 1, 5)

	// Find enclosing function.
	ctx.EnclosingFunc = findEnclosingFunc(f, fset, lineNumber, src)

	// Collect imports.
	ctx.Imports = collectGoImports(f)

	// Collect variables/constants.
	ctx.Variables = collectGoVariables(f, fset, lineNumber)

	return ctx, nil
}

// fallbackContext provides basic text-based context when AST parsing fails.
func (p *GoContextProvider) fallbackContext(filePath string, lineNumber int, src []byte) (*FileContext, error) {
	lines := strings.Split(string(src), "\n")
	findingSnippet := ""
	if lineNumber > 0 && lineNumber <= len(lines) {
		findingSnippet = strings.TrimSpace(lines[lineNumber-1])
	}

	// Find nearest function-like pattern.
	funcName := findNearestFuncByText(lines, lineNumber)

	surroundingStart := max(0, lineNumber-6)
	surroundingEnd := min(len(lines), lineNumber+5)
	surrounding := strings.Join(lines[surroundingStart:surroundingEnd], "\n")

	ctx := &FileContext{
		FilePath:         filePath,
		Language:         LangGo,
		FindingLine:      lineNumber,
		FindingSnippet:   findingSnippet,
		SurroundingLines: surrounding,
		FileSummary:      fmt.Sprintf("Go file, %d lines (AST parse failed — text-based context only)", len(lines)),
	}

	if funcName != "" {
		ctx.EnclosingFunc = &FuncInfo{
			Name: funcName,
		}
	}

	return ctx, nil
}

// buildGoFileSummary creates a one-line summary of a Go file.
func buildGoFileSummary(f *ast.File, filePath string, byteLen int) string {
	funcCount := 0
	methodCount := 0
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok {
			if fd.Recv != nil {
				methodCount++
			} else {
				funcCount++
			}
		}
	}
	return fmt.Sprintf("package %s, %s, %d functions + %d methods",
		f.Name.Name, filepath.Base(filePath), funcCount, methodCount)
}

// findEnclosingFunc finds the function/method that contains the given line.
func findEnclosingFunc(f *ast.File, fset *token.FileSet, targetLine int, src []byte) *FuncInfo {
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}

		startPos := fset.Position(fd.Pos())
		endPos := fset.Position(fd.End())

		if targetLine >= startPos.Line && targetLine <= endPos.Line {
			return extractFuncInfo(fd, fset, src)
		}
	}
	return nil
}

// extractFuncInfo builds a FuncInfo from an ast.FuncDecl.
func extractFuncInfo(fd *ast.FuncDecl, fset *token.FileSet, src []byte) *FuncInfo {
	info := &FuncInfo{
		Name:       fd.Name.Name,
		IsExported: ast.IsExported(fd.Name.Name),
	}

	// Build signature.
	var sigParts []string
	sigParts = append(sigParts, "func")

	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		// Method receiver.
		recvType := typeToString(fd.Recv.List[0].Type)
		info.Receiver = recvType
		sigParts = append(sigParts, fmt.Sprintf("(%s)", recvType))
	}

	sigParts = append(sigParts, fd.Name.Name)

	// Parameters.
	if fd.Type.Params != nil {
		params := make([]string, 0, len(fd.Type.Params.List))
		for _, p := range fd.Type.Params.List {
			paramType := typeToString(p.Type)
			for _, name := range p.Names {
				params = append(params, fmt.Sprintf("%s %s", name.Name, paramType))
			}
		}
		sigParts = append(sigParts, fmt.Sprintf("(%s)", strings.Join(params, ", ")))
	}

	// Return types.
	if fd.Type.Results != nil && len(fd.Type.Results.List) > 0 {
		results := make([]string, 0, len(fd.Type.Results.List))
		for _, r := range fd.Type.Results.List {
			results = append(results, typeToString(r.Type))
		}
		if len(results) == 1 {
			sigParts = append(sigParts, results[0])
		} else {
			sigParts = append(sigParts, fmt.Sprintf("(%s)", strings.Join(results, ", ")))
		}
	}

	info.Signature = strings.Join(sigParts, " ")

	// Extract body from source.
	startPos := fset.Position(fd.Body.Pos())
	endPos := fset.Position(fd.Body.End())

	if startPos.IsValid() && endPos.IsValid() && startPos.Line <= endPos.Line {
		lines := strings.Split(string(src), "\n")
		if startPos.Line > 0 && endPos.Line <= len(lines) {
			info.Body = strings.Join(lines[startPos.Line-1:endPos.Line], "\n")
		}
	}

	info.StartLine = startPos.Line
	info.EndLine = endPos.Line

	return info
}

// typeToString converts an ast.Expr type node to a string representation.
func typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeToString(t.X)
	case *ast.SelectorExpr:
		return typeToString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeToString(t.Elt)
		}
		return "[...]" + typeToString(t.Elt)
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", typeToString(t.Key), typeToString(t.Value))
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func(...)"
	case *ast.ChanType:
		return "chan " + typeToString(t.Value)
	case *ast.Ellipsis:
		return "..." + typeToString(t.Elt)
	default:
		return fmt.Sprintf("<%T>", expr)
	}
}

// collectGoImports extracts all import paths from a Go file.
func collectGoImports(f *ast.File) []string {
	var imports []string
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil {
			imports = append(imports, fmt.Sprintf("%s %q", imp.Name.Name, path))
		} else {
			imports = append(imports, fmt.Sprintf("%q", path))
		}
	}
	return imports
}

// collectGoVariables extracts variable and constant definitions near the target line.
func collectGoVariables(f *ast.File, fset *token.FileSet, targetLine int) []VarDef {
	var vars []VarDef

	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		// Only var and const declarations.
		if gd.Tok != token.VAR && gd.Tok != token.CONST {
			continue
		}

		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			typeStr := ""
			if vs.Type != nil {
				typeStr = typeToString(vs.Type)
			}

			for i, name := range vs.Names {
				pos := fset.Position(name.Pos())
				// Include all package-level vars/consts — they're all in scope.
				vd := VarDef{
					Name:       name.Name,
					Type:       typeStr,
					LineNumber: pos.Line,
					IsExported: ast.IsExported(name.Name),
				}

				// Extract value if this is a const or initialized var.
				if i < len(vs.Values) {
					vd.Value = fmt.Sprintf("%v", vs.Values[i])
				}

				vars = append(vars, vd)
			}
		}
	}

	return vars
}

// extractLines extracts a snippet around the target line.
// centerLines is how many lines to grab for the snippet.
// surroundLines is how many lines above/below for context.
func extractLines(src []byte, targetLine, centerLines, surroundLines int) (string, string) {
	lines := strings.Split(string(src), "\n")
	if targetLine < 1 || targetLine > len(lines) {
		return "", ""
	}

	// Center snippet: target line.
	centerStart := max(0, targetLine-1)
	centerEnd := min(len(lines), targetLine-1+centerLines)
	snippet := strings.Join(lines[centerStart:centerEnd], "\n")

	// Surrounding: ±surroundLines.
	surroundStart := max(0, targetLine-1-surroundLines)
	surroundEnd := min(len(lines), targetLine+surroundLines)
	surround := strings.Join(lines[surroundStart:surroundEnd], "\n")

	return snippet, surround
}

// findNearestFuncByText uses text-based heuristics to find the nearest function
// when AST parsing fails. Looks for "func " declarations above the target line.
func findNearestFuncByText(lines []string, targetLine int) string {
	if targetLine < 1 || targetLine > len(lines) {
		return ""
	}

	// Search backwards from target line for "func " or "func(".
	for i := targetLine - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "func ") || strings.HasPrefix(trimmed, "func(") {
			// Extract function name.
			parts := strings.Fields(trimmed)
			for j, p := range parts {
				if (p == "func" || strings.HasPrefix(p, "func(")) && j+1 < len(parts) {
					name := parts[j+1]
					// Strip trailing '(' if present.
					if idx := strings.Index(name, "("); idx >= 0 {
						name = name[:idx]
					}
					return name
				}
			}
		}
	}
	return ""
}
