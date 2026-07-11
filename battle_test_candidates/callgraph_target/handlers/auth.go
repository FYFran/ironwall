// Package handlers contains HTTP handlers for the call graph test target.
// These are the ENTRY POINTS that call graph should detect.
package handlers

import (
	"callgraph_target/db"
	"net/http"
)

// LoginHandler handles user login. Has SQL injection via cross-file call to db.QueryUser.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Cross-file call: handlers → db
	user, err := db.QueryUser(username, password)
	if err != nil {
		http.Error(w, "login failed", 500)
		return
	}

	w.Write([]byte("Welcome " + user))
}

// FileHandler handles file operations. Calls os.Open with user input via helper.
func FileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// Cross-file call: handlers → db
	data, err := db.ReadFile(filename)
	if err != nil {
		http.Error(w, "file not found", 404)
		return
	}

	w.Write(data)
}

// HealthHandler is a safe handler — no dangerous operations.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

// SafeHelper is an internal helper — not an HTTP handler (no ResponseWriter).
func SafeHelper(input string) string {
	return "sanitized: " + input
}
