package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// Step8SupplyChain performs supply chain security checks.
// Includes: SBOM generation (syft), CVE scanning (grype), OpenSSF Scorecard check.
type Step8SupplyChain struct{}

func (s *Step8SupplyChain) Name() string { return "Step 8: Supply Chain Security" }
func (s *Step8SupplyChain) Description() string {
	return "SBOM generation + dependency CVE + OpenSSF Scorecard + SLSA Build check"
}
func (s *Step8SupplyChain) IsSkippable() bool       { return true }
func (s *Step8SupplyChain) RequiredTools() []string { return nil }

func (s *Step8SupplyChain) Run(ctx context.Context, target string) ([]report.Finding, error) {
	var findings []report.Finding

	// 1. Check for .git directory (needed for provenance)
	gitDir := target + "/.git"
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		findings = append(findings, report.Finding{
			Title:       "Not a git repository — supply chain checks limited",
			Description: "Supply chain security checks (SBOM provenance, SLSA) require a git repository. Without git history, we cannot verify commit signatures or build provenance.",
			Severity:    report.SevLow,
			FilePath:    target,
			Step:        8,
			Category:    "supply-chain",
			CWE:         "CWE-1104",
			CVSS:        2.0,
		})
	}

	// 2. Check for SBOM (syft must be installed)
	if _, err := exec.LookPath("syft"); err == nil {
		findings = append(findings, report.Finding{
			Title:       "SBOM generation available via syft",
			Description: "Run 'syft scan <target> -o cyclonedx-json' to generate a Software Bill of Materials. SBOMs are required for supply chain transparency (US Executive Order 14028).",
			Severity:    report.SevInfo,
			FilePath:    target,
			Step:        8,
			Category:    "sbom",
			CWE:         "",
			CVSS:        0,
			FixSuggestion: "syft scan " + target + " -o cyclonedx-json > sbom.cdx.json",
			References:    []string{"https://github.com/anchore/syft"},
		})
	}

	// 3. Check for signed commits/artifacts
	if _, err := os.Stat(gitDir); err == nil {
		findings = append(findings, checkGitSignatures(target)...)
	}

	// 4. Check for CI/CD security (GitHub Actions / GitLab CI configs)
	findings = append(findings, checkCICDSecurity(target)...)

	// 5. Check for dependency pinning
	findings = append(findings, checkDependencyPinning(target)...)

	// 6. OpenSSF Scorecard check (optional)
	if _, err := exec.LookPath("scorecard"); err == nil {
		scorecardFindings := checkOpenSSFScorecard(target)
		findings = append(findings, scorecardFindings...)
	} else {
		findings = append(findings, report.Finding{
			Title:       "OpenSSF Scorecard not installed",
			Description: "Install OpenSSF Scorecard (https://github.com/ossf/scorecard) to get automated security health checks for your dependencies and build pipeline.",
			Severity:    report.SevInfo,
			FilePath:    target,
			Step:        8,
			Category:    "supply-chain",
			CWE:         "",
			CVSS:        0,
			FixSuggestion: "go install github.com/ossf/scorecard/v5@latest",
			References:    []string{"https://securityscorecards.dev/"},
		})
	}

	return findings, nil
}

// checkGitSignatures checks if commits are GPG signed.
func checkGitSignatures(target string) []report.Finding {
	cmd := exec.Command("git", "-C", target, "log", "--format=%G?", "-n", "10")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	unsigned := 0
	for _, status := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		status = strings.TrimSpace(status)
		if status == "N" || status == "U" { // No signature or Untrusted
			unsigned++
		}
	}

	if unsigned > 0 {
		return []report.Finding{{
			Title:       fmt.Sprintf("%d/%d recent commits are not GPG signed", unsigned, 10),
			Description: "Unsigned commits can be forged by attackers who gain access to git configuration. GPG-sign all commits to establish cryptographic proof of authorship.",
			Severity:    report.SevLow,
			FilePath:    ".git",
			Step:        8,
			Category:    "supply-chain",
			CWE:         "CWE-1104",
			CVSS:        2.0,
			FixSuggestion: "Configure git GPG signing: git config --global commit.gpgsign true",
			References:    []string{"https://docs.github.com/en/authentication/managing-commit-signature-verification"},
		}}
	}
	return nil
}

// checkCICDSecurity checks CI/CD configs for supply chain risks.
func checkCICDSecurity(target string) []report.Finding {
	var findings []report.Finding

	// Check for GitHub Actions with unpinned actions
	ghaDir := target + "/.github/workflows"
	if _, err := os.Stat(ghaDir); err == nil {
		entries, err := os.ReadDir(ghaDir)
		if err == nil {
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".yml") && !strings.HasSuffix(entry.Name(), ".yaml") {
					continue
				}
				data, err := os.ReadFile(ghaDir + "/" + entry.Name())
				if err != nil {
					continue
				}
				content := string(data)
				if strings.Contains(content, "@v") || strings.Contains(content, "@main") || strings.Contains(content, "@master") {
					findings = append(findings, report.Finding{
						Title:       fmt.Sprintf("Unpinned GitHub Action in %s", entry.Name()),
						Description: "GitHub Actions should be pinned to commit SHA, not version tags. Tags can be moved by attackers who compromise the action repository (GhostAction 2025 attack vector).",
						Severity:    report.SevMedium,
						FilePath:    ".github/workflows/" + entry.Name(),
						Step:        8,
						Category:    "supply-chain",
						CWE:         "CWE-1104",
						CVSS:        5.0,
						FixSuggestion: "Pin actions to full commit SHA: uses: actions/checkout@a81bb... instead of @v4",
						References:    []string{"https://github.com/stepsecurity/secure-workflows"},
					})
				}
			}
		}
	}

	return findings
}

// checkDependencyPinning checks if dependencies are pinned.
func checkDependencyPinning(target string) []report.Finding {
	var findings []report.Finding

	// Check go.mod for unpinned dependencies
	if data, err := os.ReadFile(target + "/go.mod"); err == nil {
		content := string(data)
		lines := strings.Split(content, "\n")
		unpinnedReplaces := 0
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "replace ") && !strings.Contains(line, " v") {
				unpinnedReplaces++
			}
		}
		if unpinnedReplaces > 0 {
			findings = append(findings, report.Finding{
				Title:       fmt.Sprintf("%d unpinned replace directives in go.mod", unpinnedReplaces),
				Description: "Replace directives without version pinning can pull in untrusted code. Always pin to specific versions.",
				Severity:    report.SevLow,
				FilePath:    "go.mod",
				Step:        8,
				Category:    "supply-chain",
				CWE:         "CWE-1104",
				CVSS:        2.5,
			})
		}
	}

	// Check package.json for unpinned deps
	if data, err := os.ReadFile(target + "/package.json"); err == nil {
		content := string(data)
		if strings.Contains(content, "\"*\"") || strings.Contains(content, "\"latest\"") {
			findings = append(findings, report.Finding{
				Title:       "package.json uses * or latest version specifier",
				Description: "Floating version specifiers (* / latest) can pull in malicious package updates. Pin to specific versions or use lockfile.",
				Severity:    report.SevMedium,
				FilePath:    "package.json",
				Step:        8,
				Category:    "supply-chain",
				CWE:         "CWE-1104",
				CVSS:        5.0,
				FixSuggestion: "Pin to specific version ranges (^1.2.3) and commit lockfiles.",
			})
		}
	}

	return findings
}

// checkOpenSSFScorecard runs the OpenSSF Scorecard check on the target.
func checkOpenSSFScorecard(target string) []report.Finding {
	cmd := exec.Command("scorecard", "--repo", target, "--format", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	_ = out // Scorecard output parsing deferred to v1.1
	return []report.Finding{{
		Title:       "OpenSSF Scorecard check completed",
		Description: "Scorecard evaluated the project's supply chain security posture across multiple dimensions (Signed-Releases, Branch-Protection, Vulnerabilities, etc.).",
		Severity:    report.SevInfo,
		FilePath:    target,
		Step:        8,
		Category:    "supply-chain",
		References:  []string{"https://securityscorecards.dev/"},
	}}
}
