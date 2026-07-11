package ai

import (
	"testing"
)

func TestFilterMissingControls_DropLowSeverity(t *testing.T) {
	controls := []MissingControl{
		{Section: ObservedSection{FuncName: "handleLogin"}, ControlType: "rate_limiting", Severity: "LOW", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "handleLogin"}, ControlType: "auth", Severity: "CRITICAL", Confidence: 0.95},
	}
	result := filterMissingControls(controls)
	if len(result) != 1 {
		t.Fatalf("expected 1 after dropping LOW, got %d", len(result))
	}
	if result[0].ControlType != "auth" {
		t.Errorf("expected 'auth' kept, got '%s'", result[0].ControlType)
	}
}

func TestFilterMissingControls_DropRateLimitOnHealth(t *testing.T) {
	controls := []MissingControl{
		{Section: ObservedSection{FuncName: "healthCheck"}, ControlType: "rate_limiting", Severity: "MEDIUM", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "handlePing"}, ControlType: "rate_limiting", Severity: "MEDIUM", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "indexHandler"}, ControlType: "rate_limiting", Severity: "MEDIUM", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "handleLogin"}, ControlType: "rate_limiting", Severity: "MEDIUM", Confidence: 0.9},
	}
	result := filterMissingControls(controls)
	if len(result) != 1 {
		t.Fatalf("expected 1 (only login kept), got %d", len(result))
	}
	if result[0].Section.FuncName != "handleLogin" {
		t.Errorf("expected handleLogin kept, got '%s'", result[0].Section.FuncName)
	}
}

func TestFilterMissingControls_DropCSRFOnGetters(t *testing.T) {
	controls := []MissingControl{
		{Section: ObservedSection{FuncName: "getUser"}, ControlType: "csrf", Severity: "HIGH", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "listProducts"}, ControlType: "csrf", Severity: "HIGH", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "showDashboard"}, ControlType: "csrf", Severity: "HIGH", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "viewReport"}, ControlType: "csrf", Severity: "HIGH", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "handleDelete"}, ControlType: "csrf", Severity: "HIGH", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "createUser"}, ControlType: "csrf", Severity: "HIGH", Confidence: 0.9},
	}
	result := filterMissingControls(controls)
	if len(result) != 2 {
		t.Fatalf("expected 2 (only delete+create POST kept), got %d", len(result))
	}
	for _, r := range result {
		fn := r.Section.FuncName
		if fn != "handleDelete" && fn != "createUser" {
			t.Errorf("unexpected handler kept: %s", fn)
		}
	}
}

func TestFilterMissingControls_KeepHighValue(t *testing.T) {
	controls := []MissingControl{
		{Section: ObservedSection{FuncName: "handleLogin"}, ControlType: "auth", Severity: "CRITICAL", Confidence: 0.95},
		{Section: ObservedSection{FuncName: "handleUpload"}, ControlType: "input_validation", Severity: "HIGH", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "getHealth"}, ControlType: "auth", Severity: "HIGH", Confidence: 0.85}, // auth on health? keep — might be real
	}
	result := filterMissingControls(controls)
	if len(result) != 3 {
		t.Fatalf("expected all 3 kept (high value), got %d", len(result))
	}
}

func TestFilterMissingControls_EndToEnd(t *testing.T) {
	// Simulate realistic scan: 13 handlers, each with 1-3 missing controls
	// After dedup: 13 findings. After filter: should be much fewer.
	controls := []MissingControl{
		{Section: ObservedSection{FuncName: "healthCheck"}, ControlType: "rate_limiting", Severity: "LOW", Confidence: 0.6},
		{Section: ObservedSection{FuncName: "handleLogin"}, ControlType: "rate_limiting+csrf+auth", Severity: "CRITICAL", Confidence: 0.95},
		{Section: ObservedSection{FuncName: "handleRegister"}, ControlType: "rate_limiting+csrf", Severity: "HIGH", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "getDashboard"}, ControlType: "csrf+rate_limiting", Severity: "MEDIUM", Confidence: 0.8},
		{Section: ObservedSection{FuncName: "listUsers"}, ControlType: "auth+rate_limiting", Severity: "CRITICAL", Confidence: 0.95},
		{Section: ObservedSection{FuncName: "handleDelete"}, ControlType: "csrf+auth", Severity: "CRITICAL", Confidence: 0.95},
		{Section: ObservedSection{FuncName: "handleUpload"}, ControlType: "input_validation+content_type", Severity: "HIGH", Confidence: 0.9},
		{Section: ObservedSection{FuncName: "viewReport"}, ControlType: "rate_limiting", Severity: "LOW", Confidence: 0.5},
		{Section: ObservedSection{FuncName: "pingEndpoint"}, ControlType: "rate_limiting", Severity: "LOW", Confidence: 0.4},
		{Section: ObservedSection{FuncName: "getHealth"}, ControlType: "rate_limiting+csrf", Severity: "LOW", Confidence: 0.5},
		{Section: ObservedSection{FuncName: "indexPage"}, ControlType: "rate_limiting", Severity: "LOW", Confidence: 0.3},
		{Section: ObservedSection{FuncName: "handleLogout"}, ControlType: "csrf", Severity: "MEDIUM", Confidence: 0.85},
		{Section: ObservedSection{FuncName: "handleSettings"}, ControlType: "csrf+input_validation", Severity: "HIGH", Confidence: 0.9},
	}
	result := filterMissingControls(controls)
	// Expected drop: healthCheck(LOW), getDashboard(csrf on GET), viewReport(LOW), pingEndpoint(LOW), getHealth(LOW+csrf on GET), indexPage(LOW)
	// Expected keep: handleLogin, handleRegister, listUsers, handleDelete, handleUpload, handleLogout, handleSettings
	if len(result) < 6 || len(result) > 8 {
		t.Fatalf("expected 6-8 actionable findings, got %d: %v", len(result), result)
	}
	// Verify all kept findings have severity >= MEDIUM
	for _, r := range result {
		if r.Severity == "LOW" {
			t.Errorf("LOW severity should be filtered: %s on %s", r.ControlType, r.Section.FuncName)
		}
	}
	t.Logf("Noise reduction: %d → %d findings (%.0f%%)", len(controls), len(result), 100*float64(len(result))/float64(len(controls)))
}
