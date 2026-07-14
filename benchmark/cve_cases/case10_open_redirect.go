// CVE-2023-XXXX: Open redirect vulnerability
// Real pattern: redirecting to user-supplied URL without validation
// CVE-2022-32189, CVE-2023-XXXX multiple Go web framework CVEs
package main

import (
	"net/http"
)

func loginRedirect(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("redirect")

	// VULNERABLE: open redirect (CWE-601)
	// Attacker: ?redirect=https://evil.com/phishing
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func oauthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	// VULNERABLE: redirect_uri not validated against whitelist
	http.Redirect(w, r, redirectURI+"?state="+state, http.StatusTemporaryRedirect)
}

func logoutRedirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")

	// VULNERABLE: any URL accepted for post-logout redirect
	if next != "" {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
