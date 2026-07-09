package agent

// InputFinding is a self-contained scanner finding used by the Agent Engine.
// It mirrors report.Finding but avoids circular imports between agent ↔ report.
// Conversion from report.Finding happens in report/agent_report.go.
type InputFinding struct {
	ID             string
	Title          string
	Description    string
	Severity       InputSeverity
	FilePath       string
	LineNumber     int
	CodeSnippet    string
	Category       string
	ToolOutput     string
	AIConfidence   float64
	FixSuggestion  string
	CWE            string
	CVSS           float64
	References     []string
	AttackScenario *AttackScenario // Enriched by Agent Engine analysis
}

// AttackScenario describes how a vulnerability could be exploited.
// Mirrors report.AttackTest.
type AttackScenario struct {
	Actor       string
	Path        string
	Impact      string
	IsReal      bool
	Explanation string
}

// InputSeverity mirrors report.Severity values.
type InputSeverity int

const (
	InputSevCritical InputSeverity = 0
	InputSevHigh     InputSeverity = 1
	InputSevMedium   InputSeverity = 2
	InputSevLow      InputSeverity = 3
	InputSevInfo     InputSeverity = 4
)

// String returns the string representation.
func (s InputSeverity) String() string {
	switch s {
	case InputSevCritical:
		return "CRITICAL"
	case InputSevHigh:
		return "HIGH"
	case InputSevMedium:
		return "MEDIUM"
	case InputSevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// InputSeverityToAgent converts InputSeverity to agent Severity.
func InputSeverityToAgent(s InputSeverity) Severity {
	switch s {
	case InputSevCritical:
		return SevCritical
	case InputSevHigh:
		return SevHigh
	case InputSevMedium:
		return SevMedium
	case InputSevLow:
		return SevLow
	default:
		return SevInfo
	}
}

// IsHighSeverity returns true for CRITICAL and HIGH findings.
func (s InputSeverity) IsHighSeverity() bool {
	return s <= InputSevHigh
}

// NeedsAnalysis returns true if this finding should be analyzed by AI.
func (s InputSeverity) NeedsAnalysis() bool {
	return s <= InputSevMedium // CRITICAL, HIGH, MEDIUM
}
