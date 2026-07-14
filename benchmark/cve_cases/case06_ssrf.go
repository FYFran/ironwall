// CVE-2021-XXXX: Server-Side Request Forgery (SSRF)
// Real pattern: CVE-2023-XXXX multiple SSRF CVEs in Go web apps, proxies
// Applications that fetch URLs from user input without validation
package main

import (
	"fmt"
	"io"
	"net/http"
)

func fetchURL(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")

	// VULNERABLE: SSRF - user-controlled URL fetched directly
	// Attacker: ?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	w.Write(body)
}

func proxyRequest(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")

	// VULNERABLE: SSRF via proxy - no URL validation
	// Attacker: ?target=http://internal-admin.local/admin
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	req.Header.Set("X-Forwarded-For", r.RemoteAddr)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(w, "Proxied response: %s", string(body))
}
