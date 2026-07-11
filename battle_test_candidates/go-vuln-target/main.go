// go-vuln-target — deliberately vulnerable Go HTTP server for Ironwall CG ablation.
// Multi-file: handlers → db/auth/file/utils cross-package calls with tainted data.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"go-vuln-target/auth"
	"go-vuln-target/db"
	"go-vuln-target/file"
	"go-vuln-target/utils"
)

func main() {
	db.InitDB()
	mux := http.NewServeMux()

	// VULN-1 (SQLi): user search — raw SQL concatenation in db/db.go
	mux.HandleFunc("/api/users", handleUserSearch)

	// VULN-2 (Auth bypass): admin panel — missing auth check
	mux.HandleFunc("/api/admin/stats", handleAdminStats)

	// VULN-3 (Path traversal): file download — path traversal in file/file.go
	mux.HandleFunc("/download", handleFileDownload)

	// VULN-4 (SSRF): URL fetch — unrestricted HTTP client
	mux.HandleFunc("/api/fetch", handleFetchURL)

	// VULN-5 (Command injection): ping — shell command injection in utils/utils.go
	mux.HandleFunc("/api/ping", handlePing)

	// VULN-6 (Weak crypto): password hash — MD5 in auth/auth.go
	mux.HandleFunc("/api/login", handleLogin)

	// VULN-7 (IDOR): user detail — no ownership check, passes userID to db
	mux.HandleFunc("/api/users/", handleUserDetail)

	log.Println("Vulnerable server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// VULN-1: SQLi handler — passes raw query param to db.SearchUsers
func handleUserSearch(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// username flows: handler → db.SearchUsers → raw SQL concatenation
	users, err := db.SearchUsers(username)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(users)
}

// VULN-2: Admin stats — no auth check, calls db.GetStats (cross-package)
func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	// VULN: no auth check — anyone can access admin stats
	stats, err := db.GetStats()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(stats)
}

// VULN-3: File download — user filename flows to file.ReadFile (path traversal)
func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// filename flows: handler → file.ReadFile → os.ReadFile with path join
	data, err := file.ReadFile(filename)
	if err != nil {
		http.Error(w, "file not found", 404)
		return
	}
	w.Write(data)
}

// VULN-4: SSRF — user URL flows to utils.FetchURL
func handleFetchURL(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// url flows: handler → utils.FetchURL → http.Get with no validation
	body, status, err := utils.FetchURL(url)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(status)
	w.Write([]byte(body))
}

// VULN-5: Command injection — user host flows to utils.Ping
func handlePing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}
	// host flows: handler → utils.Ping → exec.Command with shell
	output, err := utils.Ping(host)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write([]byte(output))
}

// VULN-6: Login with weak hash — password flows to auth.CheckLogin (MD5)
func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	// password flows: handler → auth.CheckLogin → MD5 comparison
	user, ok := auth.CheckLogin(username, password)
	if !ok {
		http.Error(w, "invalid credentials", 401)
		return
	}
	json.NewEncoder(w).Encode(user)
}

// VULN-7: IDOR — user ID from URL path, no ownership check
func handleUserDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len("/api/users/"):]
	userID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid id", 400)
		return
	}
	// userID flows: handler → db.GetUserByID → raw SQL query
	user, err := db.GetUserByID(userID)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	json.NewEncoder(w).Encode(user)
}
