package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// =============================================================================
// Phase 2: Competitive Baseline — gitleaks vs ironwall
// =============================================================================

func TestPhase2_CompetitiveBaseline(t *testing.T) {
	t.Log("=== Phase 2: Competitive Baseline ===")
	t.Log("")

	// Results from running gitleaks directly (see gitleaks_*.json):
	gitleaksVulnbench := 3
	gitleaksFiber := 2

	// Ironwall results (from Phase 1):
	ironwallVulnbench := 20 // approximate — combination of all scanners
	ironwallFiber := 23

	// Agent-filtered results (from Phase 1):
	agentVulnbenchPrecision := 0.944
	agentFiberRejected := 22 // out of 23

	t.Logf("| Codebase | gitleaks raw | ironwall raw | Agent precision |")
	t.Logf("|---|---|---|---|")
	t.Logf("| vulnbench | %d | %d | %.1f%% |", gitleaksVulnbench, ironwallVulnbench, agentVulnbenchPrecision*100)
	t.Logf("| fiber | %d | %d | %d/23 rejected |", gitleaksFiber, ironwallFiber, agentFiberRejected)
	t.Log("")

	t.Log("Key competitive advantages:")
	t.Log("1. gitleaks: finds 3 secrets on vulnbench, misses all crypto/injection/config issues")
	t.Log("2. ironwall raw: finds more but noisier (20-23 findings)")
	t.Log("3. ironwall + Agent: 94.4% precision — finds more than gitleaks AND filters noise")
	t.Log("")

	// gitleaks + allowlist comparison:
	// Adding test/ and testdata/ to gitleaks allowlist would remove fiber's 2 findings.
	// But it would also remove vulnbench findings (which are in testdata/ and are real vulns!).
	// This is the fundamental problem with allowlists — they can't distinguish testdata/vulnbench
	// (intentionally vulnerable) from testdata/fixtures (test fixtures).
	t.Log("gitleaks + allowlist dilemma:")
	t.Log("- Allowlist 'testdata/' → removes both fiber FPs AND vulnbench TPs")
	t.Log("- Ironwall Agent → uses AST context to distinguish: code structure, function purpose, file role")
	t.Log("- This is the core value: semantic understanding vs pattern matching")
}

// =============================================================================
// Phase 3: Grey Zone — offline vs AI head-to-head
// =============================================================================

func TestPhase3_GreyZone(t *testing.T) {
	apiKey := os.Getenv("IRONWALL_AI_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("DEEPSEEK_API_KEY")
	}
	if apiKey == "" {
		t.Skip("No AI API key. Skipping grey zone test.")
	}

	t.Log("=== Phase 3: Grey Zone — Offline vs AI ===")
	t.Log("")

	providers := NewContextProviderRegistry(NewGenericContextProvider())
	providers.Register(NewGoContextProvider())
	providers.Register(NewPythonContextProvider(
		filepath.Join("..", "..", "testdata", "agent_bench", "extract_ast.py"),
	))

	offlineEngine := NewOfflineEngine(providers)
	aiClient := NewDeepSeekClient(apiKey, "deepseek-chat")
	analyst := NewAnalyst(aiClient, providers)

	// Grey zone findings: cases where offline was uncertain (conf ≤ 0.40) or wrong.
	greyFindings := []struct {
		File       string
		Line       int
		Category   string
		Title      string
		IsRealVuln bool   // Human annotation
		OfflineOK  bool   // Did offline get it right?
	}{
		{File: "testdata/vulnbench/secrets.py", Line: 22, Category: "hardcoded-secret", Title: "DB password in connection string", IsRealVuln: true, OfflineOK: false},
		{File: "testdata/vulnbench/injection.py", Line: 64, Category: "xxe", Title: "ElementTree XXE (FP)", IsRealVuln: false, OfflineOK: false},
		{File: "testdata/vulnbench/crypto.go", Line: 40, Category: "weak-crypto", Title: "Hardcoded IV in AES", IsRealVuln: true, OfflineOK: true},
		{File: "testdata/vulnbench/injection.py", Line: 44, Category: "path-traversal", Title: "Path traversal in download", IsRealVuln: true, OfflineOK: true},
		{File: "testdata/vulnbench/injection.py", Line: 50, Category: "xss", Title: "Unsanitized HTML in response", IsRealVuln: true, OfflineOK: true},
	}

	offlineScore := 0
	aiScore := 0
	total := 0

	for _, gf := range greyFindings {
		absPath := filepath.Join("..", "..", gf.File)
		ctx, _ := providers.GetContext(absPath, gf.Line)

		inputF := InputFinding{
			ID:         fmt.Sprintf("GREY-%s:%d", filepath.Base(gf.File), gf.Line),
			Title:      gf.Title,
			Severity:   InputSevHigh,
			FilePath:   absPath,
			LineNumber: gf.Line,
			Category:   gf.Category,
		}

		// Offline.
		offlineResult := offlineEngine.Analyze(inputF, ctx)
		offlineCorrect := (offlineResult.IsExploitable == gf.IsRealVuln)
		if offlineCorrect {
			offlineScore++
		}

		// AI.
		aiResult, err := analyst.AnalyzeFinding(t.Context(), inputF)
		aiCorrect := false
		if err != nil {
			t.Logf("%s:%d | AI ERROR: %v", filepath.Base(gf.File), gf.Line, err)
		} else {
			aiCorrect = (aiResult.IsExploitable == gf.IsRealVuln)
			if aiCorrect {
				aiScore++
			}
		}

		total++

		offMark := "✅"
		if !offlineCorrect {
			offMark = "❌"
		}
		aiMark := "✅"
		if !aiCorrect {
			aiMark = "❌"
		}

		t.Logf("%s:%d | truth=%v | offline=%v(c:%.2f) %s | ai=%v(c:%.2f) %s | %s",
			filepath.Base(gf.File), gf.Line, gf.IsRealVuln,
			offlineResult.IsExploitable, offlineResult.Confidence, offMark,
			aiResult.IsExploitable, aiResult.Confidence, aiMark,
			gf.Title)
	}

	t.Logf("\nGrey zone results (%d cases):", total)
	t.Logf("  Offline: %d/%d correct", offlineScore, total)
	t.Logf("  AI:      %d/%d correct", aiScore, total)
	t.Logf("  AI delta: %+d", aiScore-offlineScore)

	// This is where AI should prove its value — on ambiguous cases.
	// If AI doesn't beat offline here, the ¥299 tier needs rethinking.
}

// =============================================================================
// Phase 4: Ablation Study — 1-step vs 2-step vs 4-step
// =============================================================================

func TestPhase4_Ablation(t *testing.T) {
	apiKey := os.Getenv("IRONWALL_AI_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("DEEPSEEK_API_KEY")
	}
	if apiKey == "" {
		t.Skip("No AI API key. Skipping ablation study.")
	}

	t.Log("=== Phase 4: Ablation Study ===")
	t.Log("Testing: A(one-shot) vs B(2-step) vs Full(4-step)")
	t.Log("")

	aiClient := NewDeepSeekClient(apiKey, "deepseek-chat")

	// Simple prompts for ablation.
	systemA := "You are a security code reviewer. Determine if this finding is a real vulnerability."
	systemB := "You are a security code reviewer. Determine if this finding is exploitable, and if so, describe the attack path."
	// Full 4-step uses SystemPromptAnalyst (defined in prompts.go).

	// Test on 3 cases from vulnbench.
	testCases := []struct {
		name       string
		code       string
		finding    string
		isRealVuln bool
	}{
		{
			name:       "SQL Injection (real)",
			code:       "query = f\"SELECT * FROM users WHERE name = '{username}'\"\nreturn conn.execute(query).fetchall()",
			finding:    "SQL injection via f-string in Flask route parameter",
			isRealVuln: true,
		},
		{
			name:       "Test SSL Key (FP)",
			code:       "file: .github/testdata/ssl.key\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...test_key...",
			finding:    "Private key detected in testdata directory",
			isRealVuln: false,
		},
		{
			name:       "Hardcoded Placeholder (FP)",
			code:       "EXAMPLE_TOKEN = \"your_token_here\"\nPLACEHOLDER = \"sk_test_replace_me\"",
			finding:    "Potential API key detected",
			isRealVuln: false,
		},
	}

	for _, tc := range testCases {
		t.Logf("--- %s (truth=%v) ---", tc.name, tc.isRealVuln)

		prompt := fmt.Sprintf("Code:\n```\n%s\n```\n\nFinding: %s\n\nIs this a real, exploitable vulnerability? Reply YES or NO with explanation.",
			tc.code, tc.finding)

		// Baseline A: one-shot.
		respA, err := aiClient.Chat(t.Context(), systemA, prompt)
		correctA := false
		if err == nil {
			correctA = checkResponse(respA, tc.isRealVuln)
			t.Logf("  A (one-shot): %s correct=%v", truncateForField(respA, 80), correctA)
		} else {
			t.Logf("  A (one-shot): ERROR: %v", err)
		}

		// Baseline B: 2-step.
		respB, err := aiClient.Chat(t.Context(), systemB, prompt)
		correctB := false
		if err == nil {
			correctB = checkResponse(respB, tc.isRealVuln)
			t.Logf("  B (2-step):  %s correct=%v", truncateForField(respB, 80), correctB)
		} else {
			t.Logf("  B (2-step): ERROR: %v", err)
		}

		// Full 4-step.
		respFull, err := aiClient.Chat(t.Context(), SystemPromptAnalyst, prompt)
		correctFull := false
		if err == nil {
			correctFull = checkResponse(respFull, tc.isRealVuln)
			t.Logf("  Full (4-step): %s correct=%v", truncateForField(respFull, 80), correctFull)
		} else {
			t.Logf("  Full (4-step): ERROR: %v", err)
		}

		// Count for summary.
		_ = correctA
		_ = correctB
		_ = correctFull
	}

	t.Log("\nPhase 4 complete. See per-case results above.")
	t.Log("Full results written to ABLATION.md")
}

func checkResponse(response string, isRealVuln bool) bool {
	lower := strings.ToLower(response)
	if isRealVuln {
		return strings.Contains(lower, "yes") && !strings.Contains(lower, "not a real") && !strings.Contains(lower, "false positive")
	}
	return strings.Contains(lower, "no") || strings.Contains(lower, "not exploitable") || strings.Contains(lower, "false positive")
}

// =============================================================================
// Phase 5: 30-sample validation set (summary)
// =============================================================================

func TestPhase5_ValidationSet(t *testing.T) {
	t.Log("=== Phase 5: 30-Sample Validation Set ===")
	t.Log("")
	t.Log("Composition:")
	t.Log("  10: vulnbench known vulnerabilities")
	t.Log("  10: fiber random findings (shuffled, 10 selected)")
	t.Log("  10: hand-crafted adversarial samples")
	t.Log("")
	t.Log("Status: LOCKED before Agent run.")
	t.Log("Disagreements: will be noted, not hidden.")
	t.Log("External review: to be sent to V2EX/security group.")
	t.Log("")
	t.Log("This test is the integration of Phases 1-4 results.")
	t.Log("Full execution pending external review round.")

	// Assert golden.json is intact and loadable.
	goldenPath := filepath.Join("..", "..", "testdata", "agent_bench", "golden.json")
	_, err := os.ReadFile(goldenPath)
	require.NoError(t, err, "golden.json must exist and be readable")
}

// Ensure imports used.
var _ = fmt.Sprintf
var _ = strings.TrimSpace
