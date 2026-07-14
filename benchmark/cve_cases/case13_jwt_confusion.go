// CVE-2023-XXXX: JWT algorithm confusion attack
// Real pattern: not validating JWT algorithm, allowing alg=none or alg=HS256 with RSA key
// CVE-2022-39221 (jwt-go): JWT algorithm confusion bypass
package main

import (
	"fmt"
	"net/http"
	"strings"
)

var jwtSecret = []byte("secret")

func verifyJWT(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "unauthorized", 401)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// VULNERABLE: not validating JWT algorithm before parsing
	// Attacker: set alg=none → bypass signature verification (CWE-347)
	// CVE-2022-39221: many JWT libraries accept alg=none
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		http.Error(w, "invalid token", 401)
		return
	}

	// VULNERABLE: using HMAC verification without checking algorithm
	// Attacker can use RSA public key as HMAC secret (CVE-2016-5431)
	_ = jwtSecret
	fmt.Fprintf(w, "verified: %s", parts[1])
}
