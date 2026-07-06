package classify

import (
	"github.com/FYFran/ironwall/internal/ai"
	"github.com/FYFran/ironwall/internal/report"
)

// Verifier checks if a security finding represents a real attack scenario.
// It delegates to the AI Engine's multi-stage analysis pipeline.
type Verifier struct {
	engine *ai.Engine
}

// NewVerifier creates a new attack scenario verifier backed by the AI Engine.
func NewVerifier(engine *ai.Engine) *Verifier {
	return &Verifier{engine: engine}
}

// Verify runs the multi-stage AI verification on a single finding.
// Falls back to heuristic analysis if AI is unavailable.
func (v *Verifier) Verify(f *report.Finding) *report.AttackTest {
	if v.engine == nil || !v.engine.Available() {
		return HeuristicAttackTest(f)
	}
	return v.engine.VerifySingle(nil, f)
}

// VerifyBatch runs batch verification on multiple findings.
func (v *Verifier) VerifyBatch(findings []report.Finding) []report.Finding {
	if v.engine == nil || !v.engine.Available() {
		return findings
	}
	return v.engine.Analyze(nil, findings)
}

// HeuristicAttackTest provides rule-based attack assessment when AI is unavailable.
// Exported for use by pipeline steps that need fallback verification.
func HeuristicAttackTest(f *report.Finding) *report.AttackTest {
	at := &report.AttackTest{IsReal: true}

	switch f.Category {
	case "secret-detected", "hardcoded-secret", "hardcoded-credentials":
		at.Actor = "Anyone with access to the source code"
		at.Path = "Read the file, extract the credential, use it to access the target service"
		at.Impact = "Unauthorized access to the protected service"
		at.Explanation = "Hardcoded secrets are accessible to anyone who can read the source code."
	case "sql-injection", "injection":
		at.Actor = "User with access to the vulnerable endpoint"
		at.Path = "Craft malicious input to inject SQL/commands"
		at.Impact = "Database compromise or code execution"
		at.Explanation = "Injection occurs when unsanitized input reaches an interpreter."
	case "missing-auth":
		at.Actor = "Unauthenticated remote attacker"
		at.Path = "Directly access the unprotected endpoint"
		at.Impact = "Unauthorized access to sensitive functionality"
		at.Explanation = "Missing authentication allows anyone to access protected resources."
	default:
		at.Actor = "Depends on context"
		at.Path = "Requires manual analysis"
		at.Impact = "Requires manual assessment"
		at.Explanation = "Heuristic assessment — manual review recommended."
	}

	return at
}
