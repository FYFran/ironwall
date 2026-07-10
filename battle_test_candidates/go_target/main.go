// go_target — deliberately vulnerable Go web application
// Used as ground truth for Ironwall Phase B battle testing.
// DO NOT DEPLOY. For security testing only.
//
// Contains 12 real vulnerabilities across 8 CWE categories.
// Ground truth documented in GROUND_TRUTH.md

package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// GT-001: Hardcoded database password (CWE-798, line 33)
const dbPassword = "admin123!@#Secret"

// GT-002: Hardcoded API key (CWE-798, line 36)
const apiKey = "sk-abc123def456ghi789jkl012mno345pqr678stu"

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./app.db?"+dbPassword)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	http.HandleFunc("/api/login", handleLogin)           // GT-003: SQL injection
	http.HandleFunc("/api/search", handleSearch)          // GT-004: XSS
	http.HandleFunc("/api/exec", handleExec)              // GT-005: Command injection
	http.HandleFunc("/api/files", handleFiles)            // GT-006: Path traversal
	http.HandleFunc("/api/proxy", handleProxy)            // GT-007: SSRF
	http.HandleFunc("/api/admin/users", handleAdminUsers) // GT-008: Missing auth
	http.HandleFunc("/api/hash", handleHash)              // GT-009: Weak crypto (MD5)
	http.HandleFunc("/api/health", handleHealth)          // safe endpoint (control)
	http.HandleFunc("/", handleIndex)                     // safe endpoint (control)

	log.Println("Vulnerable app listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handleIndex renders the home page.
func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := `<html><body><h1>Go Test App</h1><p>API running.</p></body></html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(tmpl))
}

// GT-003: SQL Injection (CWE-89)
// User input 'username' concatenated directly into SQL query.
// Exploit: POST /api/login with username="admin' OR '1'='1" password="x"
func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// VULNERABLE: string concatenation into SQL query
	query := "SELECT id, username, role FROM users WHERE username='" + username + "' AND password='" + password + "'"
	row := db.QueryRow(query)

	var id int
	var user, role string
	err := row.Scan(&id, &user, &role)
	if err != nil {
		http.Error(w, "Login failed", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%d,"username":"%s","role":"%s"}`, id, user, role)
}

// GT-004: Cross-Site Scripting (CWE-79)
// User input 'query' reflected directly into HTML without escaping.
// Exploit: GET /api/search?query=<script>alert(1)</script>
func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")

	// VULNERABLE: user input reflected without escaping
	html := `<html><body>
		<h1>Search Results</h1>
		<p>You searched for: ` + query + `</p>
		<p>No results found.</p>
	</body></html>`

	w.Header().Set("Content-Type", "text/html")
	// Using template here would be safe — raw Write is not
	w.Write([]byte(html))
}

// GT-005: Command Injection (CWE-78)
// User input 'cmd' passed directly to OS command shell.
// Exploit: GET /api/exec?cmd=cat%20/etc/passwd
func handleExec(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if cmd == "" {
		http.Error(w, "Missing 'cmd' parameter", http.StatusBadRequest)
		return
	}

	// VULNERABLE: user input to shell command via bash -c
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		http.Error(w, fmt.Sprintf("Command failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(out)
}

// GT-006: Path Traversal (CWE-22)
// User input 'filename' used directly in file path without sanitization.
// Exploit: GET /api/files?filename=../../../etc/passwd
func handleFiles(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "Missing 'filename' parameter", http.StatusBadRequest)
		return
	}

	// VULNERABLE: user-controlled path without validation
	filepath := "./files/" + filename
	data, err := os.ReadFile(filepath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

// GT-007: Server-Side Request Forgery (CWE-918)
// User input 'url' used directly in HTTP GET without validation.
// Exploit: GET /api/proxy?url=http://169.254.169.254/latest/meta-data/
func handleProxy(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "Missing 'url' parameter", http.StatusBadRequest)
		return
	}

	// VULNERABLE: user-controlled URL, no allowlist
	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Write(body)
}

// GT-008: Missing Authentication (CWE-306)
// Admin endpoint with no auth check.
// Anyone can access: GET /api/admin/users
func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: no authentication check
	rows, err := db.Query("SELECT id, username, role FROM users")
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"users":[`))
	first := true
	for rows.Next() {
		var id int
		var username, role string
		rows.Scan(&id, &username, &role)
		if !first {
			w.Write([]byte(","))
		}
		fmt.Fprintf(w, `{"id":%d,"username":"%s","role":"%s"}`, id, username, role)
		first = false
	}
	w.Write([]byte(`]}`))
}

// GT-009: Weak Cryptography (CWE-328)
// MD5 used for password hashing — should be bcrypt/argon2.
func handleHash(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("input")
	if input == "" {
		input = "default"
	}

	// VULNERABLE: MD5 is cryptographically broken
	hash := md5.Sum([]byte(input))
	hexHash := fmt.Sprintf("%x", hash)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"algorithm":"md5","input":"%s","hash":"%s"}`, input, hexHash)
}

// handleHealth is a safe health check endpoint (control — no vulns expected).
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// unusedTemplate is imported but not used directly — template package
// is imported for the html/template import.
var _ = template.New
var _ = strings.Contains
