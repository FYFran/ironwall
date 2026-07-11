package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var database *sql.DB

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Stats struct {
	TotalUsers  int `json:"total_users"`
	TotalLogins int `json:"total_logins"`
}

func InitDB() {
	var err error
	database, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	database.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)`)
	database.Exec(`INSERT INTO users VALUES (1, 'admin', '21232f297a57a5a743894a0e4a801fc3', 'admin')`)
	database.Exec(`INSERT INTO users VALUES (2, 'user1', '5f4dcc3b5aa765d61d8327deb882cf99', 'user')`)
}

// VULN-1: SQL Injection — raw fmt.Sprintf concatenation
func SearchUsers(username string) ([]User, error) {
	// VULN: user input directly concatenated into SQL
	query := fmt.Sprintf("SELECT id, username, role FROM users WHERE username LIKE '%%%s%%'", username)
	rows, err := database.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Username, &u.Role)
		users = append(users, u)
	}
	return users, nil
}

// VULN-7 helper: GetUserByID with raw SQL
func GetUserByID(userID int) (*User, error) {
	// VULN: int concatenated into SQL — still vulnerable to numeric SQLi
	query := fmt.Sprintf("SELECT id, username, role FROM users WHERE id = %d", userID)
	row := database.QueryRow(query)
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Role)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetStats returns system statistics — called from admin handler with no auth
func GetStats() (*Stats, error) {
	var s Stats
	database.QueryRow("SELECT COUNT(*) FROM users").Scan(&s.TotalUsers)
	s.TotalLogins = 1337 // hardcoded for demo
	return &s, nil
}
