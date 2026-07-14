// CVE-2020-XXXX: SQL Injection via string concatenation
// Real pattern: database/sql with fmt.Sprintf building WHERE clause from user input
// Many Go CRUD apps exhibit this pattern
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

func searchUsers(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	// VULNERABLE: SQL injection via string concatenation
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "OK: %v", rows)
}

func getUserByID(db *sql.DB, id string) error {
	// VULNERABLE: string concatenation with integer field
	query := fmt.Sprintf("SELECT name, email FROM users WHERE id = %s", id)
	_, err := db.Exec(query)
	return err
}
