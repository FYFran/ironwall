package auth

import (
	"crypto/md5"
	"fmt"

	"go-vuln-target/db"
)

// VULN-6: Weak crypto — MD5 for password hashing
func CheckLogin(username, password string) (*db.User, error) {
	// VULN: MD5 hash — fast, rainbow-table vulnerable
	hash := fmt.Sprintf("%x", md5.Sum([]byte(password)))

	// Cross-package call: auth → db.SearchUsers
	users, err := db.SearchUsers(username)
	if err != nil {
		return nil, err
	}

	for _, u := range users {
		// VULN: direct password hash comparison — no constant-time compare
		if u.Password == hash {
			return &u, nil
		}
	}
	return nil, fmt.Errorf("invalid credentials")
}
