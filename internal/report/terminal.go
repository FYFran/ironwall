package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/FYFran/ironwall/internal/config"
)

// PrintTerminal prints a human-readable colored report to stdout.
func PrintTerminal(result *ScanResult, cfg *config.Config) {
	c := color.New()
	if cfg.NoColor {
		c.DisableColor()
	}

	// Header
	bold := color.New(color.Bold)
	bold.Fprintf(os.Stdout, "\n🔍 ironwall v%s — 8-Step Security Audit\n", result.Version)
	fmt.Println(strings.Repeat("━", 60))
	fmt.Printf("Target:    %s\n", result.Target)
	fmt.Printf("Started:   %s\n", result.StartedAt)
	fmt.Printf("Duration:  %s\n", result.Duration)
	fmt.Println(strings.Repeat("━", 60))
	fmt.Println()

	// Step-wise summary (group findings by step)
	stepFindings := groupByStep(result.Findings)
	for step := 1; step <= 7; step++ {
		fs, ok := stepFindings[step]
		if !ok {
			// Check if skipped
			skipped := false
			for _, s := range result.SkippedSteps {
				if strings.Contains(s, config.StepNames[step]) || (step == 1 && strings.Contains(s, "Secret Scanning")) {
					skipped = true
					break
				}
			}
			name := config.StepNames[step]
			emoji := config.StepEmoji[step]
			if skipped {
				fmt.Printf("  %s %-45s SKIP\n", emoji, name+" ")
			} else {
				fmt.Printf("  %s %-45s 0 found\n", emoji, name+" ")
			}
			continue
		}
		name := config.StepNames[step]
		emoji := config.StepEmoji[step]
		count := len(fs)
		fmt.Printf("  %s %-45s %d found\n", emoji, name+" ", count)
	}

	// Summary
	fmt.Println()
	fmt.Println(strings.Repeat("━", 60))
	bold.Fprintf(os.Stdout, "📊 SUMMARY\n")
	fmt.Printf("  🔴 CRITICAL: %-3d 🟠 HIGH: %-3d 🟡 MEDIUM: %-3d 🟢 LOW: %-3d\n",
		result.Summary.Critical, result.Summary.High, result.Summary.Medium, result.Summary.Low)

	// Report file note
	if cfg.OutputFile != "" {
		fmt.Printf("  📄 Full report: %s\n", cfg.OutputFile)
	} else if len(result.Findings) > 0 {
		fmt.Printf("  💡 Run with --format markdown for a detailed report file.\n")
	}

	fmt.Println(strings.Repeat("━", 60))
	fmt.Println()

	// Print findings detail if not too many
	if len(result.Findings) <= 20 {
		printFindingsDetail(result.Findings, cfg.NoColor)
	} else if len(result.Findings) > 0 {
		fmt.Printf("  ⚠ %d findings. Use --format markdown for full details.\n", len(result.Findings))
	}
}

// groupByStep groups findings by their step number.
func groupByStep(findings []Finding) map[int][]Finding {
	m := make(map[int][]Finding)
	for _, f := range findings {
		m[f.Step] = append(m[f.Step], f)
	}
	return m
}

// printFindingsDetail prints each finding to stdout.
func printFindingsDetail(findings []Finding, noColor bool) {
	for _, f := range findings {
		prefix := f.Severity.Emoji()
		if noColor {
			prefix = fmt.Sprintf("[%s]", f.Severity.String())
		}

		fmt.Printf("\n%s %s\n", prefix, f.Title)
		fmt.Printf("  File:     %s:%d\n", f.FilePath, f.LineNumber)
		fmt.Printf("  Category: %s\n", f.Category)
		if f.CWE != "" {
			fmt.Printf("  CWE:      %s\n", f.CWE)
		}
		if f.CVSS > 0 {
			fmt.Printf("  CVSS:     %.1f\n", f.CVSS)
		}
		if f.CodeSnippet != "" {
			fmt.Printf("  Code:\n%s\n", indent(f.CodeSnippet, "    "))
		}
		if f.AttackScenario != nil && f.AttackScenario.IsReal {
			fmt.Printf("  Attack:\n")
			fmt.Printf("    Actor:  %s\n", f.AttackScenario.Actor)
			fmt.Printf("    Path:   %s\n", f.AttackScenario.Path)
			fmt.Printf("    Impact: %s\n", f.AttackScenario.Impact)
		}
	}
}

// indent adds prefix to each line.
func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
