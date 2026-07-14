// CVE-2023-24536: Resource exhaustion via multipart form parsing
// Real pattern: no size limit on multipart form uploads (Go stdlib)
// CVE-2023-24534: HTTP request smuggling via ambiguous Content-Length
package main

import (
	"io"
	"net/http"
)

func uploadFile(w http.ResponseWriter, r *http.Request) {
	// VULNERABLE: no MaxBytesReader or size limit on multipart form
	// Attacker can upload unlimited data, causing OOM (CWE-770)
	err := r.ParseMultipartForm(0) // 0 = no limit
	if err != nil {
		http.Error(w, "parse error", 400)
		return
	}

	file, _, err := r.FormFile("upload")
	if err != nil {
		http.Error(w, "file error", 400)
		return
	}
	defer file.Close()

	// VULNERABLE: reading unlimited file into memory
	data, _ := io.ReadAll(file)
	w.Write(data)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	// VULNERABLE: Content-Length not validated, request smuggling possible
	// CVE-2023-24534: Transfer-Encoding + Content-Length ambiguity
	w.Header().Set("Content-Length", r.Header.Get("Content-Length"))
	w.Write(body)
}
