package main

import (
	"fmt"
	"os"
)

func main() {
	// NOTE: This file is intentionally minimal.
	// The real entry point is cmd/ironwall/main.go.
	// This file exists at the module root so `go run .` works directly.
	fmt.Fprintln(os.Stderr, "ironwall: use cmd/ironwall/main.go as the entry point")
	fmt.Fprintln(os.Stderr, "run: go run ./cmd/ironwall scan .")
	os.Exit(1)
}
