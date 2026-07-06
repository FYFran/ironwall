package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/FYFran/ironwall/internal/config"
)

func newReviewCmd() *cobra.Command {
	var (
		staged    bool
		baseRef   string
		format    string
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "review",
		Short: "Review only changed files (git diff / staged changes)",
		Long: `Scan only files changed in the current working tree.

Examples:
  ironwall review --staged          # Review staged changes before commit
  ironwall review --base main       # Review changes vs main branch
  ironwall review --base HEAD~3     # Review last 3 commits`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := getChangedFiles(staged, baseRef)
			if err != nil {
				return fmt.Errorf("failed to get changed files: %w", err)
			}

			if target == "" {
				fmt.Println("No changed files to review.")
				return nil
			}

			cfg := config.Defaults()
			cfg.Target = target
			cfg.QuickMode = true // Diff review = quick mode (secrets only)
			cfg.OutputFormat = format
			cfg.OutputFile = outputFile

			fmt.Printf("Reviewing changed files in: %s\n", target)
			return runScan(cfg)
		},
	}

	cmd.Flags().BoolVar(&staged, "staged", false, "Review staged changes only")
	cmd.Flags().StringVar(&baseRef, "base", "", "Base ref to compare against (e.g. HEAD~3, main)")
	cmd.Flags().StringVarP(&format, "format", "f", "terminal", "Report format: terminal, markdown, json")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")

	return cmd
}

// getChangedFiles copies changed files to a temp directory for scanning.
// Returns the path to the temp directory, or empty string if no files changed.
func getChangedFiles(staged bool, baseRef string) (string, error) {
	var changedFiles []string

	if staged {
		// Get staged files
		out, err := runGit("diff", "--staged", "--name-only", "--diff-filter=ACMR")
		if err != nil {
			return "", err
		}
		changedFiles = parseFileList(string(out))
	} else if baseRef != "" {
		out, err := runGit("diff", "--name-only", "--diff-filter=ACMR", baseRef)
		if err != nil {
			return "", err
		}
		changedFiles = parseFileList(string(out))
	} else {
		// Default: unstaged changes
		out, err := runGit("diff", "--name-only", "--diff-filter=ACMR")
		if err != nil {
			return "", err
		}
		changedFiles = parseFileList(string(out))
	}

	if len(changedFiles) == 0 {
		return "", nil
	}

	// Copy changed files to a temp directory
	tmpDir, err := os.MkdirTemp("", "ironwall-review-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	repoRoot, err := getGitRoot()
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	for _, file := range changedFiles {
		src := filepath.Join(repoRoot, file)
		dst := filepath.Join(tmpDir, file)

		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			continue
		}

		if err := copyFile(src, dst); err != nil {
			continue
		}
	}

	return tmpDir, nil
}

// runGit runs a git command and returns its output.
func runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

// parseFileList splits a newline-separated file list, skipping empty lines.
func parseFileList(raw string) []string {
	lines := strings.Split(raw, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// getGitRoot returns the root directory of the current git repository.
func getGitRoot() (string, error) {
	return runGit("rev-parse", "--show-toplevel")
}

// copyFile copies a single file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
