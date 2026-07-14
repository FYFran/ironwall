// CVE-2023-XXXX: Insecure random number generation
// Real pattern: using math/rand instead of crypto/rand for security-sensitive operations
// CVE-2021-3538, CVE-2023-XXXX in various Go projects
package main

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"time"
)

func generateSessionToken() string {
	// VULNERABLE: math/rand is not cryptographically secure (CWE-338)
	rand.Seed(time.Now().UnixNano())
	token := make([]byte, 32)
	for i := range token {
		token[i] = byte(rand.Intn(256))
	}
	return fmt.Sprintf("%x", token)
}

func generateResetToken() string {
	// VULNERABLE: math/rand for password reset tokens (CWE-338)
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 20)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
