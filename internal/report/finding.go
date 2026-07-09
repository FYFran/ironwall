package report

// Severity represents the severity level of a security finding.
type Severity int

const (
	SevCritical Severity = iota // 🔴 Credential leaks / RCE / data breach
	SevHigh                     // 🟠 Injection / IDOR / privilege escalation
	SevMedium                   // 🟡 Missing rate limit / CSRF / info leak
	SevLow                      // 🟢 Config hardening / best practice
	SevInfo                     // ℹ️ Informational only
)

// String returns the human-readable severity name.
func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	case SevInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// Emoji returns the severity emoji indicator.
func (s Severity) Emoji() string {
	switch s {
	case SevCritical:
		return "🔴"
	case SevHigh:
		return "🟠"
	case SevMedium:
		return "🟡"
	case SevLow:
		return "🟢"
	case SevInfo:
		return "ℹ️"
	default:
		return "❓"
	}
}

// AttackTest holds the results of the three attack-scenario questions.
type AttackTest struct {
	Actor       string `json:"actor"`       // Q1: What role/conditions does attacker need?
	Path        string `json:"path"`        // Q2: What is the attack path?
	Impact      string `json:"impact"`      // Q3: What is the attacker's gain?
	IsReal      bool   `json:"is_real"`     // All three have concrete answers = true
	Explanation string `json:"explanation"` // Reasoning behind the verdict
}

// Finding represents a single security finding discovered during audit.
type Finding struct {
	ID             string      `json:"id"`                        // Unique ID (e.g. "IRON-001")
	Title          string      `json:"title"`                     // Short title
	Description    string      `json:"description"`               // Detailed description
	Severity       Severity    `json:"severity"`                  // Severity level
	FilePath       string      `json:"file_path"`                 // Relative file path
	LineNumber     int         `json:"line_number"`               // Line number (1-based)
	CodeSnippet    string      `json:"code_snippet"`              // Offending code + context (±2 lines)
	Step           int         `json:"step"`                      // Which step found this (1-7)
	Category       string      `json:"category"`                  // e.g. sql-injection, hardcoded-secret
	AttackScenario *AttackTest `json:"attack_scenario,omitempty"` // Three questions result
	AIConfidence   float64     `json:"ai_confidence"`             // AI confidence (0-1), 0 if no AI used
	FixSuggestion  string      `json:"fix_suggestion"`            // How to fix
	CWE            string      `json:"cwe"`                       // CWE ID
	CVSS           float64     `json:"cvss"`                      // CVSS 3.1 score
	ToolOutput     string      `json:"tool_output,omitempty"`     // Raw tool output that produced this
	References     []string    `json:"references,omitempty"`      // Reference links
}

// ScanResult holds the complete result of one scan run.
type ScanResult struct {
	Version        string      `json:"version"`
	Target         string      `json:"target"`
	StartedAt      string      `json:"started_at"`
	CompletedAt    string      `json:"completed_at"`
	Duration       string      `json:"duration"`
	Summary        ScanSummary `json:"summary"`
	Findings       []Finding   `json:"findings"`
	SkippedSteps   []string    `json:"skipped_steps,omitempty"`
	AnalysisStatus string      `json:"analysis_status"` // "full" | "partial" | "skipped" | "error"
}

// ScanSummary is the aggregated count of findings by severity.
type ScanSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// AddFinding updates summary counts and assigns a sequential ID.
func (s *ScanSummary) AddFinding(f Finding) {
	switch f.Severity {
	case SevCritical:
		s.Critical++
	case SevHigh:
		s.High++
	case SevMedium:
		s.Medium++
	case SevLow:
		s.Low++
	case SevInfo:
		s.Info++
	}
	s.Total++
}

// SeverityToCVSS maps a Severity to a representative CVSS 3.1 score.
func SeverityToCVSS(s Severity) float64 {
	switch s {
	case SevCritical:
		return 9.8
	case SevHigh:
		return 7.5
	case SevMedium:
		return 5.0
	case SevLow:
		return 2.5
	default:
		return 0.0
	}
}

// TruncateString truncates a string to maxLen characters with ellipsis.
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen || maxLen < 4 {
		return s
	}
	return s[:maxLen-3] + "..."
}
