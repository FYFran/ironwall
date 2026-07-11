// Package db simulates database operations.
// Contains DANGEROUS SINKS that call graph taint chains should reach.
package db

import (
	"database/sql"
	"os"
)

// QueryUser is a DANGEROUS SINK — concatenates user input into SQL query.
func QueryUser(username, password string) (string, error) {
	// VULN: SQL injection — user input concatenated into query
	query := "SELECT * FROM users WHERE name='" + username + "' AND password='" + password + "'"
	row := sqlQuery(query)
	return row, nil
}

// ReadFile is a DANGEROUS SINK — opens file from user-controlled path.
func ReadFile(filename string) ([]byte, error) {
	// VULN: Path traversal — user-controlled filename
	return os.ReadFile(filename)
}

// sqlQuery is a low-level SQL executor (not an entry point, not directly called from handlers).
func sqlQuery(query string) string {
	// This would execute the query in a real app
	return "user_data"
}

// Helper is a safe function — same name as admin.Helper but different package.
// This tests the call graph's ability to distinguish same-named functions.
func Helper() string {
	return "db helper"
}
