package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/FYFran/ironwall/internal/config"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ironwall",
		Short: "Ironwall — Multi-SAST Runner with AI Noise Filter",
		Long: `Ironwall runs multiple SAST scanners with one command and optionally uses AI to filter false positives.

Pipeline (8 steps):
  1. Secret scanning (gitleaks)
  2. SAST analysis (semgrep + gosec + bandit)
  3. Endpoint detection (pattern-based)
  4. Hardcoded secrets (regex)
  5. Dependency CVE check (syft + grype)
  6. IaC misconfigurations (KICS)
  7. Database configuration check
  8. AI noise filter (DeepSeek — requires --ai flag + API key)

Steps 1-7 run 100% locally. Step 8 sends code snippets to DeepSeek API.
The AI does not find new vulnerabilities — it filters false positives from existing findings.
The underlying SAST recall determines what Ironwall can detect.`,
		Version: config.Version,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newQuickCmd())
	rootCmd.AddCommand(newReviewCmd())
	rootCmd.AddCommand(newDoctorCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
