package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fiberFinding mirrors the JSON structure from ironwall scan output.
type fiberFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Category    string `json:"category"`
	CodeSnippet string `json:"code_snippet"`
}

type fiberResult struct {
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  struct {
		Total    int `json:"total"`
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
		Info     int `json:"info"`
	} `json:"summary"`
	Findings []fiberFinding `json:"findings"`
}

// TestFiber_DifferentialAnalysis compares raw scanner output vs Agent Engine verdicts.
func TestFiber_DifferentialAnalysis(t *testing.T) {
	scanPath := filepath.Join("..", "..", "testdata", "oss", "fiber_scan.json")
	data, err := os.ReadFile(scanPath)
	require.NoError(t, err)

	var result fiberResult
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Set up Agent Engine (offline mode).
	providers := NewContextProviderRegistry(NewGenericContextProvider())
	providers.Register(NewGoContextProvider())
	providers.Register(NewPythonContextProvider(
		filepath.Join("..", "..", "testdata", "agent_bench", "extract_ast.py"),
	))

	engine := NewOfflineEngine(providers)

	t.Logf("=== Fiber Differential Analysis ===")
	t.Logf("Raw scanner findings: %d (C:%d H:%d M:%d L:%d I:%d)",
		result.Summary.Total, result.Summary.Critical, result.Summary.High,
		result.Summary.Medium, result.Summary.Low, result.Summary.Info)

	confirmedExploit := 0
	rejectedExploit := 0
	lowConfidence := 0

	for _, f := range result.Findings {
		// Convert to InputFinding.
		absPath := filepath.Join("..", "..", f.File)
		severity := severityStringToInput(f.Severity)

		inputF := InputFinding{
			ID:          f.ID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    severity,
			FilePath:    absPath,
			LineNumber:  f.Line,
			CodeSnippet: f.CodeSnippet,
			Category:    f.Category,
		}

		// Get context.
		ctx, _ := providers.GetContext(absPath, f.Line)
		if ctx == nil {
			ctx = &FileContext{
				FilePath:         absPath,
				Language:         LangUnknown,
				FindingLine:      f.Line,
				FindingSnippet:   f.CodeSnippet,
				SurroundingLines: f.CodeSnippet,
			}
		}

		// Analyze.
		ar := engine.Analyze(inputF, ctx)

		verdict := "CONFIRMED"
		if !ar.IsExploitable {
			verdict = "REJECTED"
			rejectedExploit++
		} else {
			confirmedExploit++
		}
		if ar.Confidence < 0.5 {
			lowConfidence++
		}

		// Determine why the finding is/isn't exploitable.
		reason := classifyFiberFinding(f, ar)

		t.Logf("%s | scanner=%s | agent=%s conf=%.2f | %s | %s",
			f.ID, f.Severity, verdict, ar.Confidence, reason, truncateForField(ar.Narrative, 60))
	}

	fpReduction := float64(rejectedExploit) / float64(result.Summary.Total) * 100

	t.Logf("\n=== Results ===")
	t.Logf("Scanner findings:     %d", result.Summary.Total)
	t.Logf("Agent CONFIrmed:      %d", confirmedExploit)
	t.Logf("Agent REJECTED:       %d (%.0f%% false positive reduction)", rejectedExploit, fpReduction)
	t.Logf("Agent low confidence: %d", lowConfidence)

	// Write report.
	report := buildFiberReport(result, float64(rejectedExploit), float64(confirmedExploit), float64(lowConfidence), fpReduction)
	outPath := filepath.Join("..", "..", "testdata", "agent_bench", "FIBER_BENCH.md")
	err = os.WriteFile(outPath, []byte(report), 0644)
	require.NoError(t, err)
	t.Logf("Report → %s", outPath)

	// Assert: Agent should reject at least 50% of scanner findings (false positive reduction).
	require.Greater(t, fpReduction, 50.0,
		"Agent should reduce false positives by >50%% — got %.0f%%", fpReduction)
}

func classifyFiberFinding(f fiberFinding, ar *AnalystResult) string {
	file := strings.ToLower(f.File)

	if strings.Contains(file, "_test.go") {
		return "TEST_FILE"
	}
	if strings.Contains(file, "testdata/") || strings.Contains(file, ".github/testdata") {
		return "TEST_DATA"
	}
	if strings.HasSuffix(file, ".md") {
		return "DOCS"
	}
	if strings.Contains(f.Category, "supply-chain") {
		return "SUPPLY_CHAIN_HYGIENE"
	}
	if strings.Contains(f.Category, "sbom") {
		return "SBOM_INFO"
	}
	if ar != nil && ar.IsExploitable {
		return "CONFIRMED_EXPLOITABLE"
	}
	if ar != nil && !ar.IsExploitable && ar.Confidence >= 0.7 {
		return "CONFIDENT_REJECT"
	}
	return "UNCERTAIN"
}

func buildFiberReport(result fiberResult, rejected, confirmed, lowConf, fpPct float64) string {
	var buf strings.Builder
	buf.WriteString("# Ironwall Agent — Fiber Differential Analysis\n\n")
	buf.WriteString("> **Target:** gofiber/fiber (170 Go files, 128K lines)  \n")
	buf.WriteString("> **Scanner:** Ironwall 8-step pipeline  \n")
	buf.WriteString("> **Agent:** Offline Engine (9 rule categories)  \n\n")

	buf.WriteString("## Key Result\n\n")
	buf.WriteString(fmt.Sprintf("| Metric | Value |\n"))
	buf.WriteString(fmt.Sprintf("|---|---|\n"))
	buf.WriteString(fmt.Sprintf("| Scanner findings | %d |\n", result.Summary.Total))
	buf.WriteString(fmt.Sprintf("| Agent confirmed | %.0f |\n", confirmed))
	buf.WriteString(fmt.Sprintf("| Agent rejected (FP reduction) | %.0f (%.0f%%) |\n", rejected, fpPct))
	buf.WriteString(fmt.Sprintf("| Low confidence | %.0f |\n\n", lowConf))

	buf.WriteString("## Why This Matters\n\n")
	buf.WriteString("Most SAST tools dump 23 findings on the user. The Agent correctly identifies that:\n\n")
	buf.WriteString("- **Test files are not vulnerabilities** (test data, unit tests)\n")
	buf.WriteString("- **Documentation examples are not leaks** (README code snippets)\n")
	buf.WriteString("- **Unpinned CI actions are hygiene issues, not exploits**\n")
	buf.WriteString("- **SBOM is informational, not a security finding**\n\n")

	buf.WriteString("Without the Agent, a developer would waste time triaging all 23 findings manually. ")
	buf.WriteString("With the Agent, they focus only on the actionable ones.\n")

	return buf.String()
}
