// CVE-2023-XXXX: Log injection / sensitive data in logs
// Real pattern: logging raw user input without sanitization, logging credentials
// CWE-117: Log injection, CWE-532: Sensitive data in logs
package main

import (
	"log"
	"net/http"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	// VULNERABLE: logging password in plaintext (CWE-532)
	log.Printf("Login attempt: user=%s password=%s", username, password)

	// VULNERABLE: log injection via newline characters in user input (CWE-117)
	// Attacker: ?username=admin\r\nLogin succeeded for admin
	log.Printf("Processing: %s", username)

	if password == "admin123" {
		w.Write([]byte("ok"))
	}
}

func debugHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-API-Token")
	body := r.URL.Query().Get("body")

	// VULNERABLE: logging API token (CWE-532)
	log.Printf("Request with token: %s, body: %s", token, body)
	w.Write([]byte("debugged"))
}
