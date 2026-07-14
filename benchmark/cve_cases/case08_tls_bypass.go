// CVE-2021-XXXX: TLS certificate verification bypass
// Real pattern: InsecureSkipVerify=true in production code
// CVEs: CVE-2022-XXXX multiple TLS bypass CVEs in Go clients
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

func fetchSecureData(apiURL string) (string, error) {
	// VULNERABLE: TLS certificate verification disabled (CWE-295)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // VULNERABLE
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(apiURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func createInsecureClient() *http.Client {
	// VULNERABLE: custom TLS config with MinVersion too low
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS10, // VULNERABLE: TLS 1.0
		InsecureSkipVerify: true,             // VULNERABLE
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

func makeRequest(url string) {
	client := createInsecureClient()
	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("request succeeded")
}
