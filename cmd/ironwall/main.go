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
		Short: "🔍 Ironwall — 7-Step Security Audit CLI",
		Long: `Ironwall is an open-source security audit CLI tool.
It runs a 7-step pipeline against your codebase:
  1. Secret scanning (gitleaks)
  2. SAST analysis (semgrep + AI review)
  3. Endpoint audit
  4. Hardcoded secrets
  5. Dependency CVE check
  6. Server configuration
  7. Database audit

All scanning happens locally. Your code never leaves your machine.
AI analysis sends only code snippets to the API (you bring your own key).`,
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
