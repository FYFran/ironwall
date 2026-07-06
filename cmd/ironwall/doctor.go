package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check tool availability and suggest fixes",
		Long: `Check that all required external tools are installed and working.
Shows installation instructions for any missing tools.`,
		RunE: runDoctor,
	}
}

type toolCheck struct {
	name       string
	checkCmd   string
	checkArgs  []string
	installMsg string
	required   bool
}

var tools = []toolCheck{
	{
		name:       "gitleaks",
		checkCmd:   "gitleaks",
		checkArgs:  []string{"version"},
		installMsg: "go install github.com/gitleaks/gitleaks/v8@latest",
		required:   true,
	},
	{
		name:       "gosec",
		checkCmd:   "gosec",
		checkArgs:  []string{"--version"},
		installMsg: "go install github.com/securego/gosec/v2/cmd/gosec@latest",
		required:   false,
	},
	{
		name:       "semgrep",
		checkCmd:   "semgrep",
		checkArgs:  []string{"--version"},
		installMsg: "pip install semgrep",
		required:   false,
	},
	{
		name:       "govulncheck",
		checkCmd:   "govulncheck",
		checkArgs:  []string{"-version"},
		installMsg: "go install golang.org/x/vuln/cmd/govulncheck@latest",
		required:   false,
	},
	{
		name:       "npm",
		checkCmd:   "npm",
		checkArgs:  []string{"--version"},
		installMsg: "Install Node.js from https://nodejs.org",
		required:   false,
	},
	{
		name:       "pip-audit",
		checkCmd:   "pip-audit",
		checkArgs:  []string{"--version"},
		installMsg: "pip install pip-audit",
		required:   false,
	},
	{
		name:       "go",
		checkCmd:   "go",
		checkArgs:  []string{"version"},
		installMsg: "Install Go from https://go.dev/dl",
		required:   true,
	},
}

func runDoctor(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen).SprintfFunc()
	red := color.New(color.FgRed).SprintfFunc()
	yellow := color.New(color.FgYellow).SprintfFunc()
	bold := color.New(color.Bold).SprintfFunc()

	fmt.Println(bold("\n🔧 ironwall doctor — Environment Check"))
	fmt.Println(strings.Repeat("━", 55))

	okCount := 0
	warnCount := 0
	failCount := 0

	for _, tool := range tools {
		fmt.Printf("  %-20s ", tool.name)

		version, err := getToolVersion(tool.checkCmd, tool.checkArgs)
		if err == nil {
			fmt.Printf("%s %s\n", green("✅"), version)
			okCount++
		} else if tool.required {
			fmt.Printf("%s %s\n", red("❌"), "NOT FOUND (required)")
			fmt.Printf("    → Install: %s\n", yellow(tool.installMsg))
			failCount++
		} else {
			fmt.Printf("%s %s\n", yellow("⚠️ "), "not found (optional)")
			fmt.Printf("    → Install: %s\n", tool.installMsg)
			warnCount++
		}
	}

	// Check optional AI key
	fmt.Printf("  %-20s ", "AI API key")
	key := os.Getenv("IRONWALL_AI_KEY")
	if key == "" {
		key = os.Getenv("DEEPSEEK_API_KEY")
	}
	if key != "" {
		masked := key[:4] + "***" + key[len(key)-4:]
		fmt.Printf("%s %s\n", green("✅"), masked)
		okCount++
	} else {
		fmt.Printf("%s set IRONWALL_AI_KEY or DEEPSEEK_API_KEY for AI features\n", yellow("⚠️ "))
		warnCount++
	}

	// Summary
	fmt.Println(strings.Repeat("━", 55))
	fmt.Printf("  %s: %d  %s: %d  %s: %d\n",
		green("✅ OK"), okCount,
		yellow("⚠️  Warn"), warnCount,
		red("❌ Missing"), failCount)

	if failCount > 0 {
		fmt.Printf("\n  %s\n", bold("Required tools missing. Install them to use all scan steps."))
	} else {
		fmt.Printf("\n  %s\n", green("All required tools available. Run 'ironwall scan .' to start."))
	}
	fmt.Println()

	return nil
}

// getToolVersion runs a command and returns its version string.
func getToolVersion(name string, args []string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(out))
	// Take first line only
	if idx := strings.Index(version, "\n"); idx > 0 {
		version = version[:idx]
	}
	// Truncate long versions
	if len(version) > 40 {
		version = version[:40] + "..."
	}
	return version, nil
}
