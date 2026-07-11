package ai

import (
	"testing"
)

func TestDeduplicateMissingControls_Empty(t *testing.T) {
	result := deduplicateMissingControls(nil)
	if len(result) != 0 {
		t.Errorf("expected 0, got %d", len(result))
	}
}

func TestDeduplicateMissingControls_Single(t *testing.T) {
	controls := []MissingControl{
		{Section: ObservedSection{FilePath: "a.go", FuncName: "foo", LineStart: 10}, ControlType: "rate_limiting", Severity: "MEDIUM", Description: "missing rate limit", Title: "Rate Limit Missing"},
	}
	result := deduplicateMissingControls(controls)
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].ControlType != "rate_limiting" {
		t.Errorf("expected 'rate_limiting', got '%s'", result[0].ControlType)
	}
}

func TestDeduplicateMissingControls_MergeSameHandler(t *testing.T) {
	controls := []MissingControl{
		{Section: ObservedSection{FilePath: "a.go", FuncName: "handler", LineStart: 10}, ControlType: "rate_limiting", Severity: "MEDIUM", Description: "no rate limit", FixHint: "add rate limiter"},
		{Section: ObservedSection{FilePath: "a.go", FuncName: "handler", LineStart: 10}, ControlType: "csrf", Severity: "HIGH", Description: "no CSRF token", FixHint: "add CSRF"},
		{Section: ObservedSection{FilePath: "a.go", FuncName: "handler", LineStart: 10}, ControlType: "authentication", Severity: "CRITICAL", Description: "no auth check", FixHint: "add auth middleware"},
	}
	result := deduplicateMissingControls(controls)
	if len(result) != 1 {
		t.Fatalf("expected 1 merged, got %d", len(result))
	}
	r := result[0]
	if r.ControlType != "rate_limiting+csrf+authentication" {
		t.Errorf("expected merged control type, got '%s'", r.ControlType)
	}
	if r.Severity != "CRITICAL" {
		t.Errorf("expected max severity CRITICAL, got '%s'", r.Severity)
	}
	if r.Title != "Missing 3 security controls in handler" {
		t.Errorf("expected merged title, got '%s'", r.Title)
	}
}

func TestDeduplicateMissingControls_DifferentHandlers(t *testing.T) {
	controls := []MissingControl{
		{Section: ObservedSection{FilePath: "a.go", FuncName: "foo", LineStart: 10}, ControlType: "rate_limiting", Severity: "MEDIUM", Description: "no rate limit"},
		{Section: ObservedSection{FilePath: "a.go", FuncName: "bar", LineStart: 50}, ControlType: "rate_limiting", Severity: "MEDIUM", Description: "no rate limit"},
		{Section: ObservedSection{FilePath: "b.go", FuncName: "baz", LineStart: 1}, ControlType: "csrf", Severity: "HIGH", Description: "no CSRF"},
	}
	result := deduplicateMissingControls(controls)
	if len(result) != 3 {
		t.Fatalf("different handlers should not merge, expected 3, got %d", len(result))
	}
}

func TestDeduplicateMissingControls_SameNameDiffFile(t *testing.T) {
	controls := []MissingControl{
		{Section: ObservedSection{FilePath: "a.go", FuncName: "handler", LineStart: 10}, ControlType: "rate_limiting", Severity: "MEDIUM", Description: "no rate limit"},
		{Section: ObservedSection{FilePath: "b.go", FuncName: "handler", LineStart: 10}, ControlType: "csrf", Severity: "HIGH", Description: "no CSRF"},
	}
	result := deduplicateMissingControls(controls)
	if len(result) != 2 {
		t.Fatalf("different files should not merge, expected 2, got %d", len(result))
	}
}
