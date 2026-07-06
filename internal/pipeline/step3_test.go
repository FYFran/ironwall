package pipeline

import (
	"context"
	"fmt"
	"testing"
)

func TestStep3Endpoints_Run(t *testing.T) {
	s := NewStep3Endpoints(nil)
	findings, err := s.Run(context.Background(), "../../testdata/go-vuln")

	if err != nil {
		t.Logf("Step3 error: %v", err)
	}
	t.Logf("Step3 found %d findings", len(findings))
	for _, f := range findings {
		t.Logf("  - %s (%s:%d)", f.Title, f.FilePath, f.LineNumber)
	}
}

func TestStep3_RouteExtraction(t *testing.T) {
	routes := extractRoutes("../../testdata/go-vuln/hardcoded_secret.go", "../../testdata/go-vuln")
	fmt.Printf("extractRoutes returned %d routes\n", len(routes))
	for _, r := range routes {
		t.Logf("Route: %s %s (file=%s:%d, auth=%v, framework=%s)",
			r.Method, r.Path, r.File, r.Line, r.HasAuth, r.Framework)
	}
}
