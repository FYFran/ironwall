package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type aiTestResult struct {
	id              string
	expectedConfirm bool
	expectedReject  bool
	actualExploit   bool
	confidence      float64
	narrative       string
	hadError        bool
}

// TestBaseline_AI_OnGolden runs the AI-powered Analyst against golden.json.
// Requires IRONWALL_AI_KEY or DEEPSEEK_API_KEY env var. Skips gracefully if absent.
func TestBaseline_AI_OnGolden(t *testing.T) {
	apiKey := os.Getenv("IRONWALL_AI_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("DEEPSEEK_API_KEY")
	}
	if apiKey == "" {
		t.Skip("No AI API key set (IRONWALL_AI_KEY or DEEPSEEK_API_KEY). Skipping AI baseline.")
	}

	goldenPath := filepath.Join("..", "..", "testdata", "agent_bench", "golden.json")
	data, err := os.ReadFile(goldenPath)
	require.NoError(t, err)

	var golden GoldenSet
	err = json.Unmarshal(data, &golden)
	require.NoError(t, err)

	providers := NewContextProviderRegistry(NewGenericContextProvider())
	providers.Register(NewGoContextProvider())
	providers.Register(NewPythonContextProvider(
		filepath.Join("..", "..", "testdata", "agent_bench", "extract_ast.py"),
	))

	llmClient := NewDeepSeekClient(apiKey, "deepseek-chat")
	analyst := NewAnalyst(llmClient, providers)
	builder := NewReportBuilder()
	engine := NewEngine(builder, providers, WithAI(analyst))
	ctx := context.Background()

	t.Logf("=== AI Analyst Baseline (deepseek-chat) ===")

	var results []aiTestResult
	tp, fp, tn, fn := 0, 0, 0, 0

	for i, ge := range golden.Findings {
		f := InputFinding{
			ID:          ge.ID,
			Title:       ge.Title,
			Description: ge.Description,
			Severity:    severityStringToInput(ge.Severity),
			FilePath:    filepath.Join("..", "..", ge.FilePath),
			LineNumber:  ge.LineNumber,
			CodeSnippet: ge.CodeSnippet,
			Category:    ge.Category,
			CWE:         ge.CWE,
			CVSS:        ge.CVSS,
		}

		ar, err := engine.AnalyzeSingle(ctx, f)

		r := aiTestResult{
			id:              ge.ID,
			expectedConfirm: ge.AIShouldConfirm,
			expectedReject:  ge.AIShouldReject,
		}

		if err != nil {
			r.hadError = true
			r.narrative = fmt.Sprintf("ERROR: %v", err)
			results = append(results, r)
			fn++ // Default: treat errors as missed confirmations.
			t.Logf("[%d/%d] %s | ERROR: %v", i+1, len(golden.Findings), ge.ID, err)
			continue
		}

		r.actualExploit = ar.IsExploitable
		r.confidence = ar.Confidence
		r.narrative = truncateForField(ar.Narrative, 100)
		results = append(results, r)

		if ge.AIShouldConfirm && ar.IsExploitable {
			tp++
		} else if ge.AIShouldReject && ar.IsExploitable {
			fp++
		} else if ge.AIShouldReject && !ar.IsExploitable {
			tn++
		} else if ge.AIShouldConfirm && !ar.IsExploitable {
			fn++
		}

		t.Logf("[%d/%d] %s | exp_ok=%v exp_rej=%v | exploit=%v conf=%.2f | %s",
			i+1, len(golden.Findings), ge.ID, ge.AIShouldConfirm, ge.AIShouldReject,
			ar.IsExploitable, ar.Confidence, r.narrative)
	}

	precision := safeDivF(float64(tp), float64(tp+fp))
	recall := safeDivF(float64(tp), float64(tp+fn))
	f1 := safeDivF(2*precision*recall, precision+recall)

	t.Logf("\n=== AI BASELINE SCORES ===")
	t.Logf("TP=%d FP=%d TN=%d FN=%d", tp, fp, tn, fn)
	t.Logf("Precision: %.3f | Recall: %.3f | F1: %.3f", precision, recall, f1)

	// Write AI baseline report.
	report := buildAIReport(tp, fp, tn, fn, precision, recall, f1, results)
	outPath := filepath.Join("..", "..", "testdata", "agent_bench", "AI_BASELINE.md")
	err = os.WriteFile(outPath, []byte(report), 0644)
	require.NoError(t, err)
	t.Logf("AI baseline → %s", outPath)

	// Update main BASELINE.md.
	appendToBaseline(tp, fp, tn, fn, precision, recall, f1)
}

func safeDivF(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func buildAIReport(tp, fp, tn, fn int, precision, recall, f1 float64, results []aiTestResult) string {
	var buf strings.Builder

	buf.WriteString("# Ironwall Agent Engine — AI Baseline Scores\n\n")
	buf.WriteString("> **Model:** DeepSeek V3 (deepseek-chat)  \n")
	buf.WriteString("> **Validation Set:** golden.json (10 findings)  \n")
	buf.WriteString("> **Date:** 2026-07-09\n\n")

	buf.WriteString("## Confusion Matrix\n\n")
	buf.WriteString("|  | Predicted + | Predicted - |\n")
	buf.WriteString("|---|---|---|\n")
	buf.WriteString(fmt.Sprintf("| **Actual +** | TP=%d | FN=%d |\n", tp, fn))
	buf.WriteString(fmt.Sprintf("| **Actual -** | FP=%d | TN=%d |\n\n", fp, tn))

	buf.WriteString("## Metrics\n\n")
	buf.WriteString("| Metric | AI (DeepSeek V3) | Offline (Rules) | Delta |\n")
	buf.WriteString("|---|---|---|---|\n")
	buf.WriteString(fmt.Sprintf("| Precision | %.3f | 1.000 | %+.3f |\n", precision, precision-1.0))
	buf.WriteString(fmt.Sprintf("| Recall | %.3f | 1.000 | %+.3f |\n", recall, recall-1.0))
	buf.WriteString(fmt.Sprintf("| F1 | %.3f | 1.000 | %+.3f |\n\n", f1, f1-1.0))

	buf.WriteString("## Per-Finding Comparison\n\n")
	buf.WriteString("| ID | Expected | AI Verdict | AI Conf | Offline | AI |\n")
	buf.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range results {
		exp := "confirm"
		if r.expectedReject {
			exp = "reject"
		}
		verdict := "exploit"
		if !r.actualExploit {
			verdict = "NOT"
		}
		if r.hadError {
			verdict = "ERROR"
		}
		aiMark := "❌"
		if (r.expectedConfirm && r.actualExploit) || (r.expectedReject && !r.actualExploit) {
			aiMark = "✅"
		}
		buf.WriteString(fmt.Sprintf("| %s | %s | %s | %.2f | ✅ | %s |\n",
			r.id, exp, verdict, r.confidence, aiMark))
	}

	buf.WriteString("\n## Analysis\n\n")
	if f1 >= 0.9 {
		buf.WriteString("✅ **AI engine performs excellently.** On par with or better than offline rules.\n\n")
	} else if f1 >= 0.7 {
		buf.WriteString("⚠️ **AI needs prompt tuning.** Below offline baseline but above minimum threshold.\n\n")
	} else {
		buf.WriteString("🔴 **AI significantly below offline.** Investigate: prompt quality, model temperature, JSON parsing.\n\n")
	}

	buf.WriteString("### Key Takeaways\n\n")
	buf.WriteString("- **Offline** (rules): 100% F1, <100ms, $0 cost, deterministic\n")
	buf.WriteString("- **AI** (DeepSeek V3): see above, 2-5s/finding, ~$0.01/finding, non-deterministic\n")
	buf.WriteString("- **Best strategy:** Offline pre-filter → AI deep-dive on CRITICAL/HIGH only\n")
	buf.WriteString("- AI adds value via: natural language narratives, novel pattern detection, attack path synthesis\n\n")

	buf.WriteString("### Recommendations\n\n")
	buf.WriteString("1. If F1 < 0.8: add few-shot examples to SystemPromptAnalyst\n")
	buf.WriteString("2. Try deepseek-reasoner (R1) for complex reasoning tasks\n")
	buf.WriteString("3. Run 3 trials for statistical significance\n")
	buf.WriteString("4. Expand golden.json to 20+ samples\n")

	return buf.String()
}

func appendToBaseline(tp, fp, tn, fn int, precision, recall, f1 float64) {
	path := filepath.Join("..", "..", "testdata", "agent_bench", "BASELINE.md")
	existing, err := os.ReadFile(path)
	if err != nil {
		return
	}

	section := fmt.Sprintf(`

---
## AI Engine Baseline (DeepSeek V3, 2026-07-09)

| Metric | AI | Offline | Delta |
|---|---|---|---|
| Precision | %.3f | 1.000 | %+.3f |
| Recall | %.3f | 1.000 | %+.3f |
| F1 | %.3f | 1.000 | %+.3f |

TP=%d FP=%d TN=%d FN=%d

See AI_BASELINE.md for per-finding breakdown.
`, precision, precision-1.0, recall, recall-1.0, f1, f1-1.0, tp, fp, tn, fn)

	_ = os.WriteFile(path, append(existing, []byte(section)...), 0644)
}

// Ensure context import is used.
var _ = context.Background
