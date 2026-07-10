// Package observe implements Phase 1 of the AI audit engine: OBSERVE.
//
// OBSERVE walks source code using AST parsing, identifies security-relevant
// code sections, and extracts structured context for downstream AI analysis.
// It is purely local — no API calls, no network.
//
// Output feeds into Phase 2 (TRACE) where an LLM traces data flow through
// each observed section.

package observe

import "go/ast"

// ConcernType classifies the security concern for an observed code section.
type ConcernType string

const (
	ConcernSQL           ConcernType = "sql"            // Database query construction
	ConcernCommandExec   ConcernType = "command_exec"   // OS command execution
	ConcernFileOps       ConcernType = "file_ops"       // File open/read/write
	ConcernCrypto        ConcernType = "crypto"         // Cryptographic operations
	ConcernHTTPHandler   ConcernType = "http_handler"   // HTTP route handler
	ConcernAuth          ConcernType = "auth"           // Authentication/authorization
	ConcernSerialization ConcernType = "serialization"  // JSON/XML/YAML marshal/unmarshal
	ConcernTemplate      ConcernType = "template"       // HTML template rendering
	ConcernSecrets       ConcernType = "secrets"        // Potential hardcoded secrets
	ConcernInput         ConcernType = "input"          // User input handling
	ConcernNetwork       ConcernType = "network"        // Network connections
	ConcernReflection    ConcernType = "reflection"     // Reflect/unsafe operations
	ConcernSSRF          ConcernType = "ssrf"           // URL fetch from user input
	ConcernGeneral       ConcernType = "general"        // General security interest
)

// ObservedSection represents a security-relevant code section found during OBSERVE.
type ObservedSection struct {
	FilePath    string      `json:"file_path"`    // Relative file path
	FuncName    string      `json:"func_name"`    // Function/method name
	LineStart   int         `json:"line_start"`   // Start line (1-based)
	LineEnd     int         `json:"line_end"`     // End line (1-based)
	Concerns    []ConcernType `json:"concerns"`   // Detected security concerns
	CodeSnippet string      `json:"code_snippet"` // Full function body + signature
	Imports     []string    `json:"imports"`      // Relevant import paths
	IsHandler   bool        `json:"is_handler"`   // Is this an HTTP/gRPC handler?
	HasAuthCheck bool       `json:"has_auth_check"` // Does this function check auth?
	PackageName string      `json:"package_name"` // Package name
	StructName  string      `json:"struct_name"`  // Receiver struct name (methods only)
}

// SecurityPattern matches a security-relevant code pattern in the AST.
type SecurityPattern struct {
	Name        ConcernType
	Description string
	// Match returns true if the given AST node matches this pattern.
	// extra is populated with additional context (e.g. the package import path).
	Match func(node ast.Node, info *PatternMatchInfo) bool
}

// PatternMatchInfo carries context collected during AST walking.
type PatternMatchInfo struct {
	FuncDecl    *ast.FuncDecl   // Current function declaration
	File        *ast.File       // Current file AST
	Imports     map[string]string // alias → import path
	FilePath    string          // Current file path
	CallExpr    *ast.CallExpr   // Current call expression (if applicable)
	PackageName string          // Package name
}

// ObserveResult holds the complete output of the OBSERVE phase.
type ObserveResult struct {
	Sections      []ObservedSection `json:"sections"`
	TotalFiles    int               `json:"total_files"`
	TotalFuncs    int               `json:"total_funcs"`
	TotalSections int               `json:"total_sections"`
	ConcernCounts map[ConcernType]int `json:"concern_counts"`
}
