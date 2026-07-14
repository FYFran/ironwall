// CVE-2022-XXXX: NoSQL Injection in MongoDB driver for Go
// Real pattern: building bson.M filter from user input without validation
// CVE-2021-20329 (mongo-go-driver): improper input validation
package main

import (
	"context"
	"fmt"
	"net/http"
)

func searchDocuments(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")

	// VULNERABLE: NoSQL injection via user-controlled filter keys
	// Attacker: ?username[$ne]=&password[$ne]= → bypasses auth
	filter := fmt.Sprintf(`{"username": "%s", "password": "%s"}`, username, password)

	// VULNERABLE: building bson directly from user input
	// Attacker can inject MongoDB operators like $gt, $ne, $regex
	query := map[string]interface{}{
		"username": username,
		"password": password,
	}

	_ = filter
	_ = query
	_ = context.Background()
	fmt.Fprintf(w, "searched")
}

func adminQuery(w http.ResponseWriter, r *http.Request) {
	role := r.URL.Query().Get("role")

	// VULNERABLE: user input in MongoDB $where clause (CWE-943)
	whereClause := fmt.Sprintf("this.role == '%s'", role)

	// VULNERABLE: aggregation pipeline with user input
	pipeline := fmt.Sprintf(`[{"$match": {"role": "%s"}}]`, role)

	_ = whereClause
	_ = pipeline
	fmt.Fprintf(w, "ok")
}
