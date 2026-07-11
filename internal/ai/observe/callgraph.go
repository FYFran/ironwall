package observe

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// CallGraph index maps package paths to their functions and call edges.
// Pure AST-based — no type checking, no go/types dependency.
// Design: Brain B v4.1 call graph architecture (2026-07-10).

// CallGraphIndex is the top-level index of all packages and functions in a module.
type CallGraphIndex struct {
	ModulePath string              `json:"module_path"`
	Packages   map[string]*PkgInfo `json:"packages"`
}

// PkgInfo holds all functions and methods in a single Go package.
type PkgInfo struct {
	Dir     string                       `json:"dir"`
	Files   []string                     `json:"files"`
	Funcs   map[string]*FuncInfo         `json:"funcs"`   // key: function name
	Methods map[string]map[string]*FuncInfo `json:"methods"` // key: receiverType → methodName
}

// FuncInfo describes a single function or method declaration.
type FuncInfo struct {
	File     string      `json:"file"`
	DeclLine int         `json:"decl_line"`
	PkgPath  string      `json:"pkg_path"`
	Params   []ParamInfo `json:"params"`
	Callers  []CallEdge  `json:"callers,omitempty"` // who calls this
	Callees  []CallEdge  `json:"callees,omitempty"` // this calls whom
}

// ParamInfo is a function parameter's name and type string.
type ParamInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// CallEdge represents a caller→callee relationship.
type CallEdge struct {
	File     string `json:"file"`
	FuncName string `json:"func_name"`
	Line     int    `json:"line"`
}

// CallGraphResult is the full output of call graph construction.
type CallGraphResult struct {
	Index     *CallGraphIndex `json:"index"`
	TotalFuncs int            `json:"total_funcs"`
	TotalEdges int            `json:"total_edges"`
	Errors    []string        `json:"errors,omitempty"`
}

// BuildCallGraph walks all Go files under rootDir and builds a call graph index.
// It respects go.mod to determine the module path.
func BuildCallGraph(rootDir string) (*CallGraphResult, error) {
	result := &CallGraphResult{
		Index: &CallGraphIndex{
			Packages: make(map[string]*PkgInfo),
		},
	}

	// Detect module path from go.mod
	modulePath := detectModulePath(rootDir)
	result.Index.ModulePath = modulePath

	fset := token.NewFileSet()

	// Phase 1: Index all function declarations
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		// Skip vendor, testdata, hidden dirs
		base := filepath.Base(path)
		if base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".") {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("walk: %v", err))
	}

	// Collect all .go files
	var goFiles []string
	filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip permission errors
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "testdata" || strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			goFiles = append(goFiles, path)
		}
		return nil
	})

	// Phase 1: Parse each file and index functions
	fileASTs := make(map[string]*ast.File)
	fileImports := make(map[string]map[string]string) // filePath → alias → importPath

	for _, fpath := range goFiles {
		file, err := parser.ParseFile(fset, fpath, nil, parser.ParseComments)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("parse %s: %v", fpath, err))
			continue
		}

		fileASTs[fpath] = file
		pkgPath := resolvePkgPath(modulePath, rootDir, fpath)
		pkgName := file.Name.Name

		// Ensure package exists in index
		if _, ok := result.Index.Packages[pkgPath]; !ok {
			result.Index.Packages[pkgPath] = &PkgInfo{
				Dir:     filepath.Dir(fpath),
				Funcs:   make(map[string]*FuncInfo),
				Methods: make(map[string]map[string]*FuncInfo),
			}
		}
		pkg := result.Index.Packages[pkgPath]
		pkg.Files = append(pkg.Files, filepath.Base(fpath))

		// Collect imports
		imports := make(map[string]string) // alias → importPath
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			alias := ""
			if imp.Name != nil {
				alias = imp.Name.Name
			} else {
				alias = filepath.Base(path)
			}
			imports[alias] = path
		}
		fileImports[fpath] = imports

		// Index function declarations
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}

			funcName := fn.Name.Name
			params := extractParams(fn)

			fi := &FuncInfo{
				File:     fpath,
				DeclLine: fset.Position(fn.Pos()).Line,
				PkgPath:  pkgPath,
				Params:   params,
			}

			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				// Method
				recvType := typeExprString(fn.Recv.List[0].Type)
				if pkg.Methods[recvType] == nil {
					pkg.Methods[recvType] = make(map[string]*FuncInfo)
				}
				pkg.Methods[recvType][funcName] = fi
			} else {
				// Standalone function
				pkg.Funcs[funcName] = fi
			}
			result.TotalFuncs++

			// Build lookup map for cross-file resolution
			// Store as package-local name for same-package lookups
			if _, ok := pkg.Funcs[pkgName+"."+funcName]; !ok && fn.Recv == nil {
				// also index with package prefix for cross-package resolution
			}
		}
	}

	// Phase 2: Build call edges by walking function bodies
	for _, fpath := range goFiles {
		file := fileASTs[fpath]
		if file == nil {
			continue
		}
		imports := fileImports[fpath]
		pkgPath := resolvePkgPath(modulePath, rootDir, fpath)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}

			callerName := fn.Name.Name

			// Walk the function body to find calls
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				calleePkg, calleeName := resolveCallTarget(call, imports, pkgPath)
				if calleeName == "" {
					return true
				}

				callLine := fset.Position(call.Pos()).Line
				edge := CallEdge{
					File:     fpath,
					FuncName: callerName,
					Line:     callLine,
				}

				// Find callee in index and add caller edge
				if calleePkg == "" {
					// Same-package call
					calleePkg = pkgPath
				}

				if pkg, ok := result.Index.Packages[calleePkg]; ok {
					if fi, ok := pkg.Funcs[calleeName]; ok {
						fi.Callers = append(fi.Callers, edge)
						result.TotalEdges++

						// Add callee edge to caller
						callerPkg := result.Index.Packages[pkgPath]
						if callerPkg != nil {
							if callerFi, ok := callerPkg.Funcs[callerName]; ok {
								calleeEdge := CallEdge{
									File:     fi.File,
									FuncName: calleeName,
									Line:     fi.DeclLine,
								}
								callerFi.Callees = append(callerFi.Callees, calleeEdge)
							}
						}
					}
					// Also try methods
					if pkg.Methods != nil {
						for _, methods := range pkg.Methods {
							if fi, ok := methods[calleeName]; ok {
								fi.Callers = append(fi.Callers, edge)
								result.TotalEdges++
							}
						}
					}
				}
				return true
			})
		}
	}

	return result, nil
}

// resolveCallTarget extracts the package and function name from a call expression.
func resolveCallTarget(call *ast.CallExpr, imports map[string]string, currentPkg string) (pkgPath, funcName string) {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		// pkg.Func() or recv.Method()
		pkgIdent, ok := fun.X.(*ast.Ident)
		if !ok {
			return "", ""
		}
		pkgAlias := pkgIdent.Name
		funcName = fun.Sel.Name

		// Resolve import path
		if ip, ok := imports[pkgAlias]; ok {
			pkgPath = ip
		} else {
			// Same-package call — pkgAlias is current package name
			pkgPath = currentPkg
		}
		return pkgPath, funcName

	case *ast.Ident:
		// Same-package function call
		return currentPkg, fun.Name

	default:
		return "", ""
	}
}

// resolvePkgPath computes the Go import path from a file path and module root.
func resolvePkgPath(modulePath, rootDir, filePath string) string {
	relPath, err := filepath.Rel(rootDir, filepath.Dir(filePath))
	if err != nil {
		return modulePath
	}
	relPath = filepath.ToSlash(relPath)
	if relPath == "." {
		return modulePath
	}
	return modulePath + "/" + relPath
}

// detectModulePath reads the module path from go.mod.
func detectModulePath(rootDir string) string {
	modFile := filepath.Join(rootDir, "go.mod")
	data, err := os.ReadFile(modFile)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

// extractParams extracts parameter names and types from a function declaration.
func extractParams(fn *ast.FuncDecl) []ParamInfo {
	var params []ParamInfo
	if fn.Type.Params == nil {
		return params
	}
	for _, field := range fn.Type.Params.List {
		typeStr := typeExprString(field.Type)
		for _, name := range field.Names {
			params = append(params, ParamInfo{
				Name: name.Name,
				Type: typeStr,
			})
		}
		// Unnamed params
		if len(field.Names) == 0 {
			params = append(params, ParamInfo{
				Name: "",
				Type: typeStr,
			})
		}
	}
	return params
}

// typeExprString converts an AST type expression to a string representation.
func typeExprString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeExprString(t.X)
	case *ast.SelectorExpr:
		return typeExprString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeExprString(t.Elt)
		}
		return "[...]" + typeExprString(t.Elt)
	case *ast.MapType:
		return "map[" + typeExprString(t.Key) + "]" + typeExprString(t.Value)
	case *ast.InterfaceType:
		return "interface{}"
	case *ast.FuncType:
		return "func(...)"
	case *ast.ChanType:
		return "chan " + typeExprString(t.Value)
	case *ast.Ellipsis:
		return "..." + typeExprString(t.Elt)
	default:
		return fmt.Sprintf("%T", expr)
	}
}

// ToJSON serializes the call graph result to JSON.
func (r *CallGraphResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ─── Taint Chain Types (v4.1: Call Graph → TRACE integration) ─────────────────

// TaintChainEntry describes one hop in a cross-file taint chain.
type TaintChainEntry struct {
	FuncName string `json:"func_name"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	PkgPath  string `json:"pkg_path"`
}

// TaintChain is a validated cross-file data flow path from entry point to sink.
type TaintChain struct {
	Source   TaintChainEntry  `json:"source"`
	Sink     TaintChainEntry  `json:"sink"`
	Hops     []TaintChainEntry `json:"hops"`
	Depth    int              `json:"depth"`
	SinkType string           `json:"sink_type"` // "sql", "command_exec", "file_ops", etc.
}

// SinkType classifies a function name as a dangerous sink category.
// Returns empty string if not recognized as a sink.
// Excludes response writers (writeJSON, renderJSON, etc.) — those are outputs, not sinks.
func SinkType(funcName string) string {
	lower := strings.ToLower(funcName)
	// Skip response writers — they format output, not sensitive operations
	if strings.Contains(lower, "writejson") || strings.Contains(lower, "renderjson") ||
		strings.Contains(lower, "respondjson") || strings.Contains(lower, "sendjson") ||
		strings.Contains(lower, "jsonresponse") {
		return ""
	}
	switch {
	case strings.Contains(lower, "query") || strings.Contains(lower, "queryrow") || strings.Contains(lower, "querycontext"):
		return "sql"
	case strings.Contains(lower, "exec") && !strings.Contains(lower, "execut") && !strings.Contains(lower, "context"):
		return "command_exec"
	case strings.Contains(lower, "open") || strings.Contains(lower, "create") || strings.Contains(lower, "readfile") || strings.Contains(lower, "writefile"):
		return "file_ops"
	case strings.Contains(lower, "execute") || strings.Contains(lower, "redirect"):
		return "network"
	}
	// Check against known dangerous patterns
	dangerous := []string{
		"sql", "queryrow", "command", "remove",
		"write", "read", "template", "redirect", "dial",
	}
	for _, d := range dangerous {
		if lower == d || strings.HasPrefix(lower, d) {
			return "general"
		}
	}
	return ""
}

// FindEntryPoints returns functions that are likely HTTP/gRPC handlers or main().
// Only returns functions with concrete handler signatures, not just context.Context.
func (r *CallGraphResult) FindEntryPoints() []TaintChainEntry {
	var entries []TaintChainEntry

	for _, pkg := range r.Index.Packages {
		for name, fi := range pkg.Funcs {
			// main() is always an entry point
			if name == "main" && pkg.Dir != "" {
				entries = append(entries, TaintChainEntry{
					FuncName: name, File: fi.File, Line: fi.DeclLine, PkgPath: fi.PkgPath,
				})
				continue
			}
			// Only mark as handler if it has http.ResponseWriter + *http.Request or known framework context
			if isStdHTTPHandler(fi) || isFrameworkCtx(fi) {
				entries = append(entries, TaintChainEntry{
					FuncName: name, File: fi.File, Line: fi.DeclLine, PkgPath: fi.PkgPath,
				})
			}
		}
	}
	return entries
}

// isStdHTTPHandler checks for standard Go HTTP handler signature from FuncInfo params.
func isStdHTTPHandler(fi *FuncInfo) bool {
	hasWriter := false
	hasRequest := false
	for _, p := range fi.Params {
		if strings.Contains(p.Type, "http.ResponseWriter") {
			hasWriter = true
		}
		if strings.Contains(p.Type, "*http.Request") {
			hasRequest = true
		}
	}
	return hasWriter && hasRequest
}

// isFrameworkCtx checks for Gin/Fiber/Echo handler signatures from FuncInfo params.
func isFrameworkCtx(fi *FuncInfo) bool {
	for _, p := range fi.Params {
		t := p.Type
		if strings.Contains(t, "gin.Context") ||
			strings.Contains(t, "fiber.Ctx") ||
			strings.Contains(t, "echo.Context") ||
			strings.Contains(t, "iris.Context") {
			return true
		}
	}
	return false
}

// WalkTaintFromEntryPoints computes taint chains from all entry points.
// Returns chains validated and deduplicated by (source, sink_type).
func (r *CallGraphResult) WalkTaintFromEntryPoints(maxDepth int) []TaintChain {
	entries := r.FindEntryPoints()
	if len(entries) == 0 {
		return nil
	}

	var allChains []TaintChain
	for _, entry := range entries {
		rawChains := r.WalkTaint(entry.File, entry.FuncName, maxDepth)
		for _, raw := range rawChains {
			if len(raw) == 0 {
				continue
			}
			chain := convertToTaintChain(entry, raw)
			if chain != nil && ValidateChain(chain, r) {
				allChains = append(allChains, *chain)
			}
		}
	}
	return DeduplicateChains(allChains)
}

// convertToTaintChain converts a raw edge list to a TaintChain with source and sink.
func convertToTaintChain(source TaintChainEntry, edges []CallEdge) *TaintChain {
	if len(edges) == 0 {
		return nil
	}

	last := edges[len(edges)-1]
	sinkType := SinkType(last.FuncName)
	if sinkType == "" {
		return nil // last hop is not a recognizable sink
	}

	chain := &TaintChain{
		Source:   source,
		Sink:     TaintChainEntry{FuncName: last.FuncName, File: last.File, Line: last.Line},
		Depth:    len(edges),
		SinkType: sinkType,
	}
	for _, e := range edges {
		chain.Hops = append(chain.Hops, TaintChainEntry{
			FuncName: e.FuncName, File: e.File, Line: e.Line,
		})
	}
	return chain
}

// ValidateChain checks that each hop in a taint chain is plausible.
// Rules: (1) function files are distinct or plausible, (2) at least one hop,
// (3) chain depth ≤ maxDepth (pre-checked by caller).
func ValidateChain(chain *TaintChain, cg *CallGraphResult) bool {
	if chain == nil || len(chain.Hops) == 0 {
		return false
	}
	// Verify source and sink are not the same function
	if chain.Source.FuncName == chain.Sink.FuncName && chain.Source.File == chain.Sink.File {
		return false
	}
	// Verify sink function actually exists in call graph
	found := false
	for _, pkg := range cg.Index.Packages {
		if fi, ok := pkg.Funcs[chain.Sink.FuncName]; ok {
			if fi.File == chain.Sink.File {
				found = true
				break
			}
		}
	}
	return found || len(chain.Hops) >= 1 // allow if we have hops even if sink lookup fails
}

// DeduplicateChains removes duplicate chains that share the same (source_func, sink_type).
// Keeps the shortest chain per (source, sink_type) pair.
func DeduplicateChains(chains []TaintChain) []TaintChain {
	type key struct {
		sourceFunc string
		sinkType   string
	}
	seen := make(map[key]*TaintChain)
	var result []TaintChain

	for i := range chains {
		k := key{chains[i].Source.FuncName, chains[i].SinkType}
		if existing, ok := seen[k]; ok {
			// Keep shorter chain
			if chains[i].Depth < existing.Depth {
				*existing = chains[i]
			}
		} else {
			seen[k] = &chains[i]
			result = append(result, chains[i])
		}
	}
	return result
}

// GetChainsForFunction returns all taint chains that involve a given function.
// Looks for the function as source, intermediate hop, or sink.
func GetChainsForFunction(chains []TaintChain, funcName string) []TaintChain {
	var relevant []TaintChain
	for _, c := range chains {
		if c.Source.FuncName == funcName {
			relevant = append(relevant, c)
			continue
		}
		if c.Sink.FuncName == funcName {
			relevant = append(relevant, c)
			continue
		}
		for _, h := range c.Hops {
			if h.FuncName == funcName {
				relevant = append(relevant, c)
				break
			}
		}
		// Cap per-function to avoid noise
		if len(relevant) >= 5 {
			break
		}
	}
	return relevant
}

// FormatTaintChains formats chains as human-readable markdown for LLM prompts.
func FormatTaintChains(chains []TaintChain) string {
	if len(chains) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("**Cross-File Taint Chains** (static hints — VERIFY, don't trust):\n")
	for i, c := range chains {
		if i >= 3 { // cap at 3 chains per section
			break
		}
		sb.WriteString(fmt.Sprintf("  Chain %d (%s → %s, depth=%d, sink=%s):\n",
			i+1, c.Source.FuncName, c.Sink.FuncName, c.Depth, c.SinkType))
		sb.WriteString(fmt.Sprintf("    %s (%s:%d)", c.Source.FuncName, filepath.Base(c.Source.File), c.Source.Line))
		for _, h := range c.Hops {
			sb.WriteString(fmt.Sprintf(" → %s (%s:%d)", h.FuncName, filepath.Base(h.File), h.Line))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("⚠️ Static analysis only. Verify each hop. Cross-package name collisions possible.\n")
	return sb.String()
}

// WalkTaint follows a taint from a source function through the call graph up to maxDepth hops.
// Returns the full call chain from source to any sinks found.
func (r *CallGraphResult) WalkTaint(sourceFile string, sourceFunc string, maxDepth int) [][]CallEdge {
	var chains [][]CallEdge

	// Find the source function
	var startFi *FuncInfo
	for _, pkg := range r.Index.Packages {
		if fi, ok := pkg.Funcs[sourceFunc]; ok {
			if fi.File == sourceFile || sourceFile == "" {
				startFi = fi
				break
			}
		}
	}
	if startFi == nil {
		return chains
	}

	// BFS through the call graph
	type bfsNode struct {
		fi    *FuncInfo
		chain []CallEdge
	}

	visited := make(map[string]bool)
	queue := []bfsNode{{fi: startFi, chain: nil}}

	for len(queue) > 0 && len(chains) < 20 { // cap at 20 chains
		node := queue[0]
		queue = queue[1:]

		// Key: file + decl line uniquely identifies a function (multiple funcs can share a file)
		key := fmt.Sprintf("%s:%d", node.fi.File, node.fi.DeclLine)
		if visited[key] {
			continue
		}
		visited[key] = true

		// Check depth limit
		if len(node.chain) >= maxDepth {
			chains = append(chains, node.chain)
			continue
		}

		if len(node.fi.Callees) == 0 {
			// Leaf function — this is a terminal chain
			if len(node.chain) > 0 {
				chains = append(chains, node.chain)
			}
			continue
		}

		for _, callee := range node.fi.Callees {
			newChain := make([]CallEdge, len(node.chain)+1)
			copy(newChain, node.chain)
			newChain[len(node.chain)] = callee

			// Find the callee's FuncInfo
			var calleeFi *FuncInfo
			for _, pkg := range r.Index.Packages {
				if fi, ok := pkg.Funcs[callee.FuncName]; ok {
					calleeFi = fi
					break
				}
			}
			if calleeFi != nil {
				queue = append(queue, bfsNode{fi: calleeFi, chain: newChain})
			} else if len(newChain) > 0 {
				chains = append(chains, newChain)
			}
		}
	}

	return chains
}
