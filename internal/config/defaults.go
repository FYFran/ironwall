package config

const (
	// Version is the ironwall CLI version.
	Version = "0.1.0"

	// DefaultTimeout is the default scan timeout in seconds.
	DefaultTimeout = 300

	// MaxReportFindings caps the number of findings in a report summary.
	MaxReportFindings = 500

	// AppName is the CLI application name.
	AppName = "ironwall"

	// AppDescription is shown in help text.
	AppDescription = "7-Step Security Audit CLI — find secrets, vulns, and misconfigurations in your code."
)

// StepNames maps step numbers to human-readable names.
var StepNames = map[int]string{
	1: "Secret scanning (gitleaks)",
	2: "SAST analysis (semgrep + AI)",
	3: "Endpoint audit",
	4: "Hardcoded secrets",
	5: "Dependency CVE check",
	6: "Server configuration",
	7: "Database audit",
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
}

// StepTools lists the external tools required by each step.
var StepTools = map[int][]string{
	1: {"gitleaks"},
	2: {"semgrep"},
	3: {}, // AI-only, no external tools
	4: {}, // AI-only
	5: {}, // Uses go/npm/pip directly
	6: {}, // File analysis, no external tools
	7: {}, // File analysis, no external tools
}
