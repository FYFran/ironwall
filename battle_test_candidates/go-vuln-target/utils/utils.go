package utils

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"time"
)

// VULN-4: SSRF — unrestricted HTTP GET to user-supplied URL
func FetchURL(url string) (string, int, error) {
	// VULN: no URL validation — can hit internal services
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(body), resp.StatusCode, nil
}

// VULN-5: Command injection — shell command with user input
func Ping(host string) (string, error) {
	// VULN: shell command concatenation — ; rm -rf / or $(whoami)
	cmd := fmt.Sprintf("ping -c 1 %s", host)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return string(out), err
}
