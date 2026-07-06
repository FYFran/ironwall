package ai

// All structured response types for AI analysis.
// Every AI interaction now returns proper JSON that is unmarshaled,
// NOT string-matched with contains().

// TriageResult is the response from the fast triage stage (DeepSeek V3).
type TriageResult struct {
	Findings []TriageVerdict `json:"findings"`
}

// TriageVerdict is a single finding's triage decision.
type TriageVerdict struct {
	ID              string  `json:"id"`
	IsFalsePositive bool    `json:"is_false_positive"`
	Confidence      float64 `json:"confidence"`
	Reason          string  `json:"reason"`
	SeverityOverride string `json:"severity_override,omitempty"` // CRITICAL/HIGH/MEDIUM/LOW/INFO or empty
}

// AttackTestResult is the structured response from deep verification (DeepSeek R1).
type AttackTestResult struct {
	IsReal      bool    `json:"is_real"`
	Confidence  float64 `json:"confidence"`
	Actor       string  `json:"actor"`
	Path        string  `json:"path"`
	Impact      string  `json:"impact"`
	Explanation string  `json:"explanation"`
	CVE         string  `json:"cve,omitempty"`  // If matches known CVE pattern
	CWERefined  string  `json:"cwe_refined,omitempty"` // More precise CWE than tool default
}

// DeepVerifyResult wraps the deep verification output for batch processing.
type DeepVerifyResult struct {
	Findings []DeepVerifyVerdict `json:"findings"`
}

// DeepVerifyVerdict is a single finding's deep verification decision.
type DeepVerifyVerdict struct {
	ID         string  `json:"id"`
	IsReal     bool    `json:"is_real"`
	Confidence float64 `json:"confidence"`
	Actor      string  `json:"actor"`
	Path       string  `json:"path"`
	Impact     string  `json:"impact"`
	Explanation string `json:"explanation"`
}

// FixResult is the response from fix generation.
type FixResult struct {
	FixCode              string   `json:"fix_code"`
	Explanation          string   `json:"explanation"`
	AlternativeApproaches []string `json:"alternative_approaches,omitempty"`
}

// SASTReviewResult is the response from SAST false-positive review.
type SASTReviewResult struct {
	Findings []SASTReviewVerdict `json:"findings"`
}

// SASTReviewVerdict is a single SAST finding's review verdict.
type SASTReviewVerdict struct {
	ID               string  `json:"id"`
	IsReal           bool    `json:"is_real"`
	Confidence       float64 `json:"confidence"`
	Reason           string  `json:"reason"`
	SeverityOverride string  `json:"severity_override,omitempty"`
}

// ReachabilityResult describes whether a code location is reachable from external input.
type ReachabilityResult struct {
	IsReachable bool   `json:"is_reachable"`
	EntryPoint  string `json:"entry_point,omitempty"`
	Path        string `json:"path,omitempty"`
	Confidence  float64 `json:"confidence"`
}
