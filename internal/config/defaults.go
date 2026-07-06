package config

const (
	// Version is the ironwall CLI version.
	Version = "0.4.0"

	// DefaultTimeout is the default scan timeout in seconds.
	DefaultTimeout = 300

	// MaxReportFindings caps the number of findings in a report summary.
	MaxReportFindings = 500

	// AppName is the CLI application name.
	AppName = "ironwall"

	// AppDescription is shown in help text.
	AppDescription = "8-Step Security Audit CLI — find secrets, vulns, misconfigurations, and supply chain risks in your code."
)

// StepNames maps step numbers to human-readable names.
var StepNames = map[int]string{
	1: "Secret scanning (Betterleaks)",
	2: "SAST analysis (gosec + CodeQL + semgrep)",
	3: "Endpoint audit",
	4: "Hardcoded secrets",
	5: "Dependency CVE + SBOM",
	6: "Server & IaC configuration",
	7: "Database audit",
	8: "Supply chain security",
}

// StepEmoji maps step numbers to emoji indicators.
var StepEmoji = map[int]string{
	1: "🔑",
	2: "🔬",
	3: "🔗",
	4: "🔐",
	5: "📦",
	6: "🖥️ ",
	7: "🗄️ ",
	8: "🔗",
}

// StepTools lists the external tools required by each step.
var StepTools = map[int][]string{
	1: {"betterleaks"},  // Falls back to gitleaks
	2: {},               // gosec embedded, semgrep/codeql optional
	3: {},               // AI-only, no external tools
	4: {},               // AI-only
	5: {},               // Uses go/npm/pip directly, syft/grype optional
	6: {},               // Regex (always), nuclei/kics optional
	7: {},               // File analysis, no external tools
	8: {},               // Git + file analysis, scorecard optional
}
