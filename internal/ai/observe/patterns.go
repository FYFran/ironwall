package observe

import (
	"go/ast"
	"strings"
)

// DefaultPatterns returns all built-in security patterns for Go code analysis.
// Each pattern focuses on one category of security concern.
// Patterns are designed to cast a wide net — false positives are fine here;
// downstream TRACE+VERIFY phases will filter.
func DefaultPatterns() []SecurityPattern {
	return []SecurityPattern{
		sqlPattern(),
		commandExecPattern(),
		fileOpsPattern(),
		cryptoPattern(),
		httpHandlerPattern(),
		serializationPattern(),
		templatePattern(),
		networkPattern(),
		reflectionPattern(),
		ssrfPattern(),
		hardcodedSecretPattern(),
		inputHandlingPattern(),
	}
}

// sqlPattern detects database query calls (database/sql, ORM, etc.)
func sqlPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernSQL,
		Description: "SQL query construction — potential SQL injection",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			// database/sql patterns
			sqlFuncs := []string{
				"Query", "QueryRow", "QueryContext", "QueryRowContext",
				"Exec", "ExecContext", "Prepare", "PrepareContext",
				"Select", "Get", "NamedExec", "MustExec",
			}
			for _, sf := range sqlFuncs {
				if fn == sf {
					// Check import includes database/sql, sqlx, or ORM
					for _, imp := range info.Imports {
						switch {
						case strings.Contains(imp, "database/sql"):
							return true
						case strings.Contains(imp, "github.com/jmoiron/sqlx"):
							return true
						case strings.Contains(imp, "github.com/jinzhu/gorm"):
							return true
						case strings.Contains(imp, "gorm.io/gorm"):
							return true
						case strings.Contains(imp, "github.com/Masterminds/squirrel"):
							return true
						}
					}
				}
			}
			// Raw SQL string functions
			rawSQL := []string{"Raw", "ToSQL", "SqlFor", "BuildSQL"}
			for _, rf := range rawSQL {
				if fn == rf {
					return true
				}
			}
			// db.Raw(), db.Exec() — any method on a DB-like object
			if isDBMethod(fn) {
				return true
			}
			return false
		},
	}
}

// commandExecPattern detects OS command execution calls.
func commandExecPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernCommandExec,
		Description: "OS command execution — potential command injection",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			execFuncs := []string{
				"Command", "CommandContext",
				"Start", "Run", "Output", "CombinedOutput",
				"Shell", "ShellCommand",
				"System", "Popen", "Subprocess",
			}
			for _, ef := range execFuncs {
				if fn == ef {
					for _, imp := range info.Imports {
						if strings.Contains(imp, "os/exec") {
							return true
						}
					}
				}
			}
			// exec.Command() selector
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok {
					if ident.Name == "exec" && (fn == "Command" || fn == "CommandContext") {
						return true
					}
				}
			}
			return false
		},
	}
}

// fileOpsPattern detects file operations that could lead to path traversal.
func fileOpsPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernFileOps,
		Description: "File system operations — potential path traversal",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			fileFuncs := []string{
				"Open", "OpenFile", "Create", "ReadFile", "WriteFile",
				"ReadDir", "Remove", "RemoveAll", "Mkdir", "MkdirAll",
				"Chmod", "Chown", "Symlink", "Readlink",
				"Stat", "Lstat", "Readdir", "Readdirnames",
			}
			for _, ff := range fileFuncs {
				if fn == ff {
					for _, imp := range info.Imports {
						if strings.Contains(imp, "os") || strings.Contains(imp, "io/ioutil") {
							return true
						}
					}
				}
			}
			// path.Join / filepath.Join with variable args → traversal concern
			if fn == "Join" {
				for _, imp := range info.Imports {
					if strings.Contains(imp, "path/filepath") || strings.Contains(imp, "path\"") {
						// Check if any arg is not a string literal
						for _, arg := range call.Args {
							if _, isLit := arg.(*ast.BasicLit); !isLit {
								return true
							}
						}
					}
				}
			}
			return false
		},
	}
}

// cryptoPattern detects weak cryptographic algorithms.
func cryptoPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernCrypto,
		Description: "Cryptographic operations — potential weak algorithm usage",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			weakCrypto := []string{
				"md5", "NewMD5", "MD5",
				"sha1", "NewSHA1", "SHA1",
				"des", "NewDES", "NewTripleDESCipher",
				"rc4", "NewRC4",
				"NewCBCDecrypter", "NewCBCEncrypter",
				"NewCFBDecrypter", "NewCFBEncrypter",
			}
			for _, wc := range weakCrypto {
				if strings.EqualFold(fn, wc) {
					return true
				}
			}
			// Check for crypto package usage with weak configs
			for _, imp := range info.Imports {
				if strings.Contains(imp, "crypto/md5") ||
					strings.Contains(imp, "crypto/sha1") ||
					strings.Contains(imp, "crypto/des") ||
					strings.Contains(imp, "crypto/rc4") {
					return true
				}
			}
			// math/rand instead of crypto/rand
			if fn == "Intn" || fn == "Int" || fn == "Seed" || fn == "NewSource" {
				for _, imp := range info.Imports {
					if strings.Contains(imp, "math/rand") {
						return true
					}
				}
			}
			return false
		},
	}
}

// httpHandlerPattern detects HTTP route handler registrations.
func httpHandlerPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernHTTPHandler,
		Description: "HTTP handler — potential missing auth/input validation",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			handlerFuncs := []string{
				"Handle", "HandleFunc", "HandleRequest",
				"GET", "POST", "PUT", "DELETE", "PATCH",
				"Group", "Route", "Add", "Register",
				"NewServeMux", "ListenAndServe",
				"Use", // middleware registration
			}
			for _, hf := range handlerFuncs {
				if fn == hf {
					return true
				}
			}
			// http.HandleFunc, mux.HandleFunc patterns
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok {
					routerVars := []string{"mux", "router", "r", "m", "http", "srv", "server", "e", "g", "app"}
					for _, rv := range routerVars {
						if strings.EqualFold(x.Name, rv) && isHandlerMethod(fn) {
							return true
						}
					}
				}
			}
			return false
		},
	}
}

// serializationPattern detects serialization/deserialization operations.
func serializationPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernSerialization,
		Description: "Serialization — potential injection/deserialization issues",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			serFuncs := []string{
				"Marshal", "Unmarshal", "NewDecoder", "NewEncoder",
				"Decode", "Encode", "MarshalIndent", "UnmarshalStrict",
				"MarshalXML", "UnmarshalXML", "MarshalYAML", "UnmarshalYAML",
			}
			for _, sf := range serFuncs {
				if fn == sf {
					for _, imp := range info.Imports {
						if strings.Contains(imp, "encoding/json") ||
							strings.Contains(imp, "encoding/xml") ||
							strings.Contains(imp, "encoding/gob") ||
							strings.Contains(imp, "gopkg.in/yaml") ||
							strings.Contains(imp, "github.com/go-yaml") {
							return true
						}
					}
				}
			}
			return false
		},
	}
}

// templatePattern detects HTML/template rendering.
func templatePattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernTemplate,
		Description: "Template rendering — potential XSS/server-side injection",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			tmplFuncs := []string{
				"Execute", "ExecuteTemplate", "New", "Parse", "ParseFiles",
				"ParseGlob", "Render", "HTML",
			}
			for _, tf := range tmplFuncs {
				if fn == tf {
					for _, imp := range info.Imports {
						if strings.Contains(imp, "html/template") ||
							strings.Contains(imp, "text/template") {
							return true
						}
					}
				}
			}
			return false
		},
	}
}

// networkPattern detects network connection calls (potential SSRF/egress issues).
func networkPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernNetwork,
		Description: "Network operations — potential SSRF or data exfiltration",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			netFuncs := []string{
				"Dial", "DialContext", "DialTimeout", "DialIP", "DialTCP", "DialUDP",
				"Listen", "ListenPacket", "Dialer",
				"Get", "Post", "PostForm", "Head", "NewRequest",
				"Do", "NewRequestWithContext",
				"Connect", "NewConnection",
			}
			for _, nf := range netFuncs {
				if fn == nf {
					// Check for net, net/http, or websocket imports
					for _, imp := range info.Imports {
						if strings.Contains(imp, "net\"") ||
							strings.Contains(imp, "net/") ||
							strings.Contains(imp, "net/http") ||
							strings.Contains(imp, "gorilla/websocket") ||
							strings.Contains(imp, "nhooyr.io/websocket") ||
							strings.Contains(imp, "github.com/go-redis") {
							return true
						}
					}
				}
			}
			return false
		},
	}
}

// reflectionPattern detects reflect and unsafe package usage.
func reflectionPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernReflection,
		Description: "Reflection/unsafe operations — potential type confusion/memory issues",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			reflectFuncs := []string{
				"ValueOf", "TypeOf", "New", "NewAt", "Zero",
				"Pointer", "UnsafeAddr", "SliceHeader", "StringHeader",
				"Sizeof", "Offsetof", "Alignof",
				"Call", "CallSlice", "MapIndex", "Set",
			}
			for _, rf := range reflectFuncs {
				if fn == rf {
					for _, imp := range info.Imports {
						if strings.Contains(imp, "reflect") ||
							strings.Contains(imp, "unsafe") {
							return true
						}
					}
				}
			}
			// unsafe.Pointer usage
			if fn == "Pointer" {
				for _, imp := range info.Imports {
					if strings.Contains(imp, "unsafe") {
						return true
					}
				}
			}
			return false
		},
	}
}

// ssrfPattern detects URL fetches with non-constant URLs (SSRF concern).
func ssrfPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernSSRF,
		Description: "URL fetch with variable input — potential SSRF",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			httpCallFuncs := []string{
				"Get", "Post", "PostForm", "Head",
				"NewRequest", "NewRequestWithContext", "Do",
				"Open", "fetch",
			}
			for _, hf := range httpCallFuncs {
				if fn == hf {
					// Check if first argument is NOT a string literal
					if len(call.Args) > 0 {
						if _, isLit := call.Args[0].(*ast.BasicLit); !isLit {
							for _, imp := range info.Imports {
								if strings.Contains(imp, "net/http") {
									return true
								}
							}
						}
					}
				}
			}
			return false
		},
	}
}

// hardcodedSecretPattern detects potential hardcoded secrets in code.
func hardcodedSecretPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernSecrets,
		Description: "Potential hardcoded secret — API key, token, password",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok {
				return false
			}
			secretKeyPatterns := []string{
				"password", "passwd", "pass", "pwd",
				"secret", "token", "api_key", "apikey", "api_secret",
				"private_key", "privatekey", "secret_key", "secretkey",
				"access_key", "accesskey", "auth_token", "authtoken",
				"jwt_secret", "jwt_key", "signing_key",
				"db_password", "db_pass", "database_url",
				"redis_password", "aws_secret", "s3_secret",
				"smtp_password", "mail_password",
			}
			for _, expr := range assign.Lhs {
				if ident, ok := expr.(*ast.Ident); ok {
					name := strings.ToLower(ident.Name)
					for _, pattern := range secretKeyPatterns {
						if strings.Contains(name, pattern) {
							// Check RHS is a non-empty string literal
							for _, rhs := range assign.Rhs {
								if lit, ok := rhs.(*ast.BasicLit); ok {
									if lit.Kind.String() == "STRING" && lit.Value != `""` {
										return true
									}
								}
							}
						}
					}
				}
			}
			return false
		},
	}
}

// inputHandlingPattern detects form value / query param reads without visible validation.
func inputHandlingPattern() SecurityPattern {
	return SecurityPattern{
		Name:        ConcernInput,
		Description: "User input handling — potential missing validation",
		Match: func(node ast.Node, info *PatternMatchInfo) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return false
			}
			fn := funcName(call)
			inputFuncs := []string{
				"FormValue", "PostFormValue", "QueryParam", "Param",
				"Query", "URLQuery", "Form",
				"ReadBody", "BodyParser", "Bind", "ShouldBind",
				"ShouldBindJSON", "ShouldBindXML", "ShouldBindQuery",
				"ReadJSON", "ReadXML",
				"Context", "Next", // general middleware
			}
			for _, inf := range inputFuncs {
				if fn == inf {
					return true
				}
			}
			return false
		},
	}
}

// --- helpers ---

// funcName returns the function name from a CallExpr, handling
// both direct calls and selector expressions (pkg.Func / obj.Method).
func funcName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	default:
		return ""
	}
}

// isHandlerMethod checks if a function name looks like an HTTP route handler method.
func isHandlerMethod(name string) bool {
	handlerMethods := []string{
		"Handle", "HandleFunc", "GET", "POST", "PUT", "DELETE", "PATCH",
		"HEAD", "OPTIONS", "CONNECT", "TRACE",
		"Group", "Route", "Use", "Add", "Register",
	}
	for _, hm := range handlerMethods {
		if strings.EqualFold(name, hm) {
			return true
		}
	}
	return false
}

// isDBMethod checks if a function name looks like a database operation method.
func isDBMethod(name string) bool {
	dbMethods := []string{
		"Exec", "Query", "QueryRow", "Select", "Get",
		"Insert", "Update", "Delete", "Upsert", "Replace",
		"Where", "Raw", "First", "Last", "Find",
		"Create", "Save", "Model", "Table",
	}
	for _, dm := range dbMethods {
		if strings.EqualFold(name, dm) {
			return true
		}
	}
	return false
}
