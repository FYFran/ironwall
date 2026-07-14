// CVE-2019-XXXX: Hardcoded credentials and API keys in source code
// Real pattern: AWS keys, JWT secrets, database passwords in source
// Thousands of real CVEs from leaked credentials
package main

import (
	"fmt"
	"net/http"
)

const (
	// VULNERABLE: hardcoded API key
	AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
	// VULNERABLE: hardcoded secret key
	AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	// VULNERABLE: hardcoded JWT signing key
	JWT_SECRET = "my-super-secret-jwt-key-2023"
	// VULNERABLE: hardcoded database password
	DB_PASSWORD = "admin123!"
)

var (
	// VULNERABLE: hardcoded token in variable
	apiToken = "ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s"
	// VULNERABLE: hardcoded private key header
	privateKey = "-----BEGIN RSA PRIVATE KEY-----"
)

func initDB() {
	// VULNERABLE: hardcoded connection string with credentials
	connStr := "postgres://admin:SuperSecret123@localhost:5432/mydb?sslmode=disable"
	fmt.Println("connecting to:", connStr)
}

func getAuthHeader(r *http.Request) string {
	// VULNERABLE: hardcoded API key in code
	return "Bearer sk-abc123def456ghi789jkl"
}
