// CVE-2023-45283: filepath.Clean path traversal on Windows
// CVE-2022-XXXX: Path traversal via unsanitized user input in file operations
// Real pattern: using user-supplied filename directly with os.Open
package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func downloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// VULNERABLE: path traversal - no validation of filename
	// Attacker: ?file=../../../etc/passwd
	filePath := filepath.Join("/var/www/uploads", filename)
	f, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()
	io.Copy(w, f)
}

func readConfig(w http.ResponseWriter, r *http.Request) {
	template := r.URL.Query().Get("template")

	// VULNERABLE: direct file read with user-controlled path
	data, err := os.ReadFile(template)
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	w.Write(data)
}
