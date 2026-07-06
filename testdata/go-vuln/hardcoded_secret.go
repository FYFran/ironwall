package main

// This file contains intentionally vulnerable code for testing ironwall's detection.
// DO NOT USE IN PRODUCTION.

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

// HARDCODED SECRET — should be detected by gitleaks (Step 1).
var apiKey = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"

// HARDCODED PASSWORD — should be detected by gitleaks (Step 1).
const dbPassword = "admin123!@#SuperSecret"

// JWT Secret hardcoded — should be detected.
var jwtSecret = []byte("my-very-secret-jwt-signing-key-2024")

// AWS credentials pattern — should be detected.
const awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

// SQL Injection vulnerability — for Step 2 (semgrep).
func getUserByName(db *sql.DB, name string) (string, error) {
	query := "SELECT email FROM users WHERE name = '" + name + "'"
	var email string
	err := db.QueryRow(query).Scan(&email)
	return email, err
}

// XSS vulnerability — unsanitized user input in response.
func handleGreeting(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello, %s!</h1>", name)
}

// Command injection vulnerability.
func pingHost(host string) string {
	cmd := fmt.Sprintf("ping -c 1 %s", host)
	// In real code this would be exec.Command("sh", "-c", cmd)
	return cmd
}

// Hardcoded port — informational.
func getServerAddr() string {
	return ":8080" // Should this be configurable?
}

// Disabled TLS verification — should be flagged.
func insecureHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: nil, // In real code: InsecureSkipVerify: true
		},
	}
}

func main() {
	fmt.Println("This is test vulnerability code for ironwall")

	// Unauthenticated admin route — should be detected by Step 3
	http.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"users": [{"id": 1, "role": "admin"}]}`)
	})

	// Unauthenticated write endpoint — should be detected by Step 3
	http.HandleFunc("/api/delete-user", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status": "deleted"}`)
	})

	fmt.Printf("API Key: %s\n", apiKey[:4]+"***")
	fmt.Printf("DB Password: %s\n", dbPassword[:4]+"***")
	_ = jwtSecret
	_ = awsSecret
	_ = os.Getenv("NOT_A_SECRET")

	// Below are additional patterns for Step 4 hardcoded detection:

	// DB connection string with credentials (Step 4 regex)
	_ = "mysql://admin:SuperSecret123!@localhost:3306/mydb"

	// Hex-encoded secret 32+ chars (Step 4 regex)
	_ = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

	// OAuth client_secret pattern (Step 4 regex)
	_ = `{"client_secret": "GOCSPX-abcdefghijklmnopqrstuvwxyz"}`

	// Internal URL with embedded credentials (Step 4 regex)
	_ = "https://admin:password123@internal-api.company.com/v1"

	// FTP password (Step 4 regex)
	_ = "ftp_password = \"frp_secret_2024!\""

	// Encryption key hardcoded (Step 4 regex)
	_ = "encryption_key = \"my-32-byte-aes-encryption-key!!\""
}
