package observe

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// pythonCallGraphScript is the name of the Python script that builds call graphs.
const pythonCallGraphScript = "python_callgraph.py"

// BuildPythonCallGraph runs the Python call graph builder on a target directory.
// Returns a CallGraphResult in the same format as the Go call graph builder,
// enabling unified cross-file taint tracking in the TRACE pipeline.
func BuildPythonCallGraph(targetDir string) (*CallGraphResult, error) {
	scriptPath := findPythonCallGraphScript()
	if scriptPath == "" {
		return nil, fmt.Errorf("python_callgraph.py not found")
	}

	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("python callgraph: resolve path: %w", err)
	}

	cmd := exec.Command("python", scriptPath, absTarget)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("python callgraph: %w (stderr may have details)", err)
	}

	return parsePythonCallGraph(output)
}

// findPythonCallGraphScript locates python_callgraph.py relative to this source file.
func findPythonCallGraphScript() string {
	// Try same directory as this source file (production)
	scriptDir := filepath.Dir(locateSourceFile())
	candidate := filepath.Join(scriptDir, pythonCallGraphScript)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	// Try relative to working directory (test/dev)
	if wd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(wd, "internal", "ai", "observe", pythonCallGraphScript)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// Walk up from working directory to find ironwall root
	if wd, err := os.Getwd(); err == nil {
		for dir := wd; dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
			candidate := filepath.Join(dir, "internal", "ai", "observe", pythonCallGraphScript)
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
			// Stop at filesystem root or when we find go.mod (ironwall root)
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				// Found ironwall root, try relative path
				candidate := filepath.Join(dir, "internal", "ai", "observe", pythonCallGraphScript)
				if _, err := os.Stat(candidate); err == nil {
					return candidate
				}
				break
			}
		}
	}

	return ""
}

// parsePythonCallGraph parses the JSON output from python_callgraph.py
// and converts it to the Go CallGraphResult format.
func parsePythonCallGraph(output []byte) (*CallGraphResult, error) {
	var raw struct {
		ModulePath string              `json:"module_path"`
		Packages   map[string]struct {
			Dir     string                       `json:"dir"`
			Files   []string                     `json:"files"`
			Funcs   map[string]pythonFuncInfo    `json:"funcs"`
			Methods map[string]map[string]pythonFuncInfo `json:"methods"`
		} `json:"packages"`
		TotalFuncs int      `json:"total_funcs"`
		TotalEdges int      `json:"total_edges"`
		Errors     []string `json:"errors"`
	}

	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("python callgraph: parse JSON: %w", err)
	}

	result := &CallGraphResult{
		Index: &CallGraphIndex{
			ModulePath: raw.ModulePath,
			Packages:   make(map[string]*PkgInfo),
		},
		TotalFuncs: raw.TotalFuncs,
		TotalEdges: raw.TotalEdges,
		Errors:     raw.Errors,
	}

	for pkgPath, rawPkg := range raw.Packages {
		pkg := &PkgInfo{
			Dir:     rawPkg.Dir,
			Files:   rawPkg.Files,
			Funcs:   make(map[string]*FuncInfo),
			Methods: make(map[string]map[string]*FuncInfo),
		}

		for funcName, rawFi := range rawPkg.Funcs {
			fi := convertPythonFuncInfo(rawFi)
			pkg.Funcs[funcName] = fi
		}

		for recvType, methods := range rawPkg.Methods {
			pkg.Methods[recvType] = make(map[string]*FuncInfo)
			for methodName, rawFi := range methods {
				pkg.Methods[recvType][methodName] = convertPythonFuncInfo(rawFi)
			}
		}

		result.Index.Packages[pkgPath] = pkg
	}

	return result, nil
}

// pythonFuncInfo mirrors the JSON structure from python_callgraph.py.
type pythonFuncInfo struct {
	File         string       `json:"file"`
	DeclLine     int          `json:"decl_line"`
	PkgPath      string       `json:"pkg_path"`
	Params       []ParamInfo  `json:"params"`
	Callers      []CallEdge   `json:"callers"`
	Callees      []CallEdge   `json:"callees"`
	IsHandler    bool         `json:"is_handler"`
	HasAuthCheck bool         `json:"has_auth_check"`
}

func convertPythonFuncInfo(raw pythonFuncInfo) *FuncInfo {
	fi := &FuncInfo{
		File:     raw.File,
		DeclLine: raw.DeclLine,
		PkgPath:  raw.PkgPath,
		Params:   raw.Params,
		Callers:  raw.Callers,
		Callees:  raw.Callees, // Keep all callees for handler + sink detection
	}
	return fi
}

// isStdlibCall returns true if a function call looks like a Python stdlib or framework call.
// Sink-significant calls (os.remove, subprocess.run, etc.) are NOT filtered — they're needed for sink detection.
func isStdlibCall(name string) bool {
	clean := strings.TrimPrefix(name, ".")

	// Sink-significant calls — keep these for taint tracking
	sinkCalls := []string{
		"os.remove", "os.unlink", "os.rmdir", "os.system", "os.popen",
		"subprocess.run", "subprocess.call", "subprocess.Popen",
		"open", "exec", "eval", "compile",
		"requests.get", "requests.post", "urllib.request.urlopen",
	}
	for _, s := range sinkCalls {
		if clean == s || strings.HasPrefix(clean, s+"(") {
			return false // keep it
		}
	}

	stdlibPrefixes := []string{
		"os.", "sys.", "re.", "json.", "datetime.", "secrets.", "hashlib.",
		"pathlib.", "io.", "logging.", "urllib.", "http.", "sqlalchemy.",
		"flask.", "werkzeug.", "jinja2.",
		"len(", "int(", "str(", "float(", "bool(", "list(", "dict(",
		"flash", "redirect", "render_template", "url_for", "send_file",
		"BytesIO", "secure_filename", "login_user", "logout_user",
		"current_app", "request.", "db.session", "db.init_app",
		"Fernet", "RotatingFileHandler",
	}
	for _, prefix := range stdlibPrefixes {
		if strings.HasPrefix(clean, prefix) || clean == strings.TrimSuffix(prefix, ".") {
			return true
		}
	}
	return false
}
