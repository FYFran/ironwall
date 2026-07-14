// CVE-2021-XXXX: Command injection via os/exec with unsanitized user input
// Real pattern: CVE-2021-3121 (GoGo Protobuf), CVE-2022-23806 (elliptic panic)
// Common in DevOps/CLI tools built in Go
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

func pingHost(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// VULNERABLE: command injection via shell
	// Attacker: ?host=8.8.8.8; cat /etc/passwd
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

func convertImage(w http.ResponseWriter, r *http.Request) {
	inputFile := r.URL.Query().Get("input")

	// VULNERABLE: string building for shell command
	// Attacker: ?input=image.jpg; rm -rf /
	cmdStr := fmt.Sprintf("convert %s -resize 100x100 output.jpg", inputFile)
	parts := strings.Split(cmdStr, " ")
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Run()
	fmt.Fprintf(w, "converted")
}
