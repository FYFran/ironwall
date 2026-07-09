// Package agent implements the Ironwall AI Agent Engine.
//
// Report builder produces human-readable security audit reports from
// structured AnalystResult data. Supports 6-section format for CRITICAL,
// 4-section for HIGH, and 1-section+fix for MEDIUM/LOW.
package agent

import (
	"fmt"
	"strings"
)

// Severity is the finding severity level.
type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
)

// AttackStep represents one step in an attack path.
type AttackStep struct {
	StepNumber  int    `json:"step_number"`
	Description string `json:"description"`
	FileRef     string `json:"file_ref,omitempty"`
	LineRef     int    `json:"line_ref,omitempty"`
}

// EvidenceItem is one piece of evidence supporting or refuting a finding.
type EvidenceItem struct {
	Type        string `json:"type"`        // "code", "config", "dependency", "runtime"
	Description string `json:"description"` // What this evidence shows
	FilePath    string `json:"file_path,omitempty"`
	LineNumber  int    `json:"line_number,omitempty"`
	CodeSnippet string `json:"code_snippet,omitempty"`
	Confidence  string `json:"confidence"` // "certain", "likely", "possible"
}

// VerificationResult is the outcome of secret verification or reachability check.
type VerificationResult struct {
	Verified     bool   `json:"verified"`                // Was the finding independently verified?
	Method       string `json:"method"`                  // "api-call", "ast-reachability", "regex-match"
	Detail       string `json:"detail"`                  // Human-readable verification detail
	APIEndpoint  string `json:"api_endpoint,omitempty"`  // Which API was called (for secret verification)
	APIResponse  string `json:"api_response,omitempty"`  // Truncated response (for secret verification)
	IsReachable  bool   `json:"is_reachable,omitempty"`  // For AST reachability: can tainted data reach sink?
	ReachPath    string `json:"reach_path,omitempty"`    // Source→Sink data flow path
}

// AnalystResult is the structured output from the Analyst Agent.
// This is the CONTRACT between analyst.go and report_builder.go.
// Both sides code to this interface.
type AnalystResult struct {
	FindingID    string             `json:"finding_id"`
	Title        string             `json:"title"`
	Severity     Severity           `json:"severity"`
	IsExploitable bool              `json:"is_exploitable"`
	Confidence   float64            `json:"confidence"` // 0.0-1.0
	Narrative    string             `json:"narrative"`   // Human-readable analysis narrative
	AttackPath   []AttackStep       `json:"attack_path"`
	Evidence     []EvidenceItem     `json:"evidence"`
	Verification VerificationResult `json:"verification"`
	CWE          string             `json:"cwe"`
	CVSS         float64            `json:"cvss"`
	FixSuggestion string            `json:"fix_suggestion"`
	References   []string           `json:"references,omitempty"`
	// RawFindings are the original scanner findings that fed this analysis.
	RawFindings []RawFinding `json:"raw_findings,omitempty"`
}

// RawFinding is a minimal reference to the original scanner finding.
type RawFinding struct {
	Source   string `json:"source"`   // "gitleaks", "semgrep", "gosec", etc.
	RuleID   string `json:"rule_id"`  // Scanner rule ID
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
	Snippet  string `json:"snippet"`
}

// ReportSection is one section of the generated report.
type ReportSection struct {
	Heading string // Section heading (e.g. "## Executive Summary")
	Content string // Section body in markdown
	Order   int    // Display order
}

// ReportBuilder produces markdown security reports from AnalystResult.
type ReportBuilder interface {
	// BuildReport generates a complete markdown report from an analysis result.
	BuildReport(result AnalystResult) (string, error)
	// BuildSections returns individual report sections for custom assembly.
	BuildSections(result AnalystResult) ([]ReportSection, error)
}

// DefaultReportBuilder implements ReportBuilder with the 6-section template.
type DefaultReportBuilder struct {
	// IncludeRawFindings controls whether raw scanner output appears in the appendix.
	IncludeRawFindings bool
}

// NewReportBuilder creates a DefaultReportBuilder.
func NewReportBuilder() *DefaultReportBuilder {
	return &DefaultReportBuilder{IncludeRawFindings: true}
}

// BuildReport generates a complete markdown report.
func (b *DefaultReportBuilder) BuildReport(result AnalystResult) (string, error) {
	sections, err := b.BuildSections(result)
	if err != nil {
		return "", fmt.Errorf("build sections: %w", err)
	}

	var buf strings.Builder
	buf.WriteString(b.buildHeader(result))
	buf.WriteString("\n")

	for _, sec := range sections {
		buf.WriteString(sec.Heading)
		buf.WriteString("\n\n")
		buf.WriteString(sec.Content)
		buf.WriteString("\n\n")
	}

	buf.WriteString(b.buildFooter(result))
	return buf.String(), nil
}

// BuildSections returns sections based on severity:
//
//	CRITICAL → 6 sections: Summary, Narrative, Evidence, AttackPath, Verification, Fix
//	HIGH     → 4 sections: Summary, Evidence, AttackPath, Fix
//	MEDIUM   → 1 section: Summary (with fix inline)
//	LOW/INFO → 1 section: Summary only
func (b *DefaultReportBuilder) BuildSections(result AnalystResult) ([]ReportSection, error) {
	if result.FindingID == "" {
		return nil, fmt.Errorf("AnalystResult.FindingID is required")
	}

	switch result.Severity {
	case SevCritical:
		return b.buildCriticalSections(result), nil
	case SevHigh:
		return b.buildHighSections(result), nil
	default:
		return b.buildStandardSections(result), nil
	}
}

// buildCriticalSections builds all 6 sections for CRITICAL findings.
func (b *DefaultReportBuilder) buildCriticalSections(r AnalystResult) []ReportSection {
	sections := []ReportSection{
		{Order: 1, Heading: "## 📋 Executive Summary", Content: b.buildSummary(r)},
		{Order: 2, Heading: "## 📖 Analysis Narrative", Content: b.buildNarrative(r)},
		{Order: 3, Heading: "## 🔍 Evidence", Content: b.buildEvidence(r)},
		{Order: 4, Heading: "## 🎯 Attack Path", Content: b.buildAttackPath(r)},
		{Order: 5, Heading: "## ✅ Verification", Content: b.buildVerification(r)},
		{Order: 6, Heading: "## 🔧 Remediation", Content: b.buildFix(r)},
	}
	return sections
}

// buildHighSections builds 4 sections for HIGH findings.
func (b *DefaultReportBuilder) buildHighSections(r AnalystResult) []ReportSection {
	return []ReportSection{
		{Order: 1, Heading: "## 📋 Summary", Content: b.buildSummary(r)},
		{Order: 2, Heading: "## 🔍 Evidence", Content: b.buildEvidence(r)},
		{Order: 3, Heading: "## 🎯 Attack Path", Content: b.buildAttackPath(r)},
		{Order: 4, Heading: "## 🔧 Remediation", Content: b.buildFix(r)},
	}
}

// buildStandardSections builds 1 section for MEDIUM/LOW/INFO findings.
func (b *DefaultReportBuilder) buildStandardSections(r AnalystResult) []ReportSection {
	content := b.buildSummary(r)
	if r.FixSuggestion != "" {
		content += "\n\n**Fix:** " + r.FixSuggestion
	}
	return []ReportSection{
		{Order: 1, Heading: "## 📋 Finding", Content: content},
	}
}

func (b *DefaultReportBuilder) buildHeader(r AnalystResult) string {
	status := "CONFIRMED — EXPLOITABLE"
	if !r.IsExploitable {
		status = "REJECTED — NOT EXPLOITABLE"
	}
	return fmt.Sprintf(`# Security Finding: %s

| Field       | Value                              |
|-------------|------------------------------------|
| **ID**      | %s                                 |
| **Severity**| %s                                 |
| **Status**  | %s                                 |
| **Confidence** | %.0f%%                            |
| **CWE**     | %s                                 |
| **CVSS**    | %.1f                               |
`, r.Title, r.FindingID, r.Severity, status, r.Confidence*100, r.CWE, r.CVSS)
}

func (b *DefaultReportBuilder) buildSummary(r AnalystResult) string {
	exploitability := "EXPLOITABLE"
	if !r.IsExploitable {
		exploitability = "NOT EXPLOITABLE"
	}
	return fmt.Sprintf(`**Verdict:** %s (confidence: %.0f%%)

%s`, exploitability, r.Confidence*100, r.Narrative)
}

func (b *DefaultReportBuilder) buildNarrative(r AnalystResult) string {
	if r.Narrative == "" {
		return "_No narrative provided. The Analyst did not generate an analysis narrative for this finding._"
	}
	return r.Narrative
}

func (b *DefaultReportBuilder) buildEvidence(r AnalystResult) string {
	if len(r.Evidence) == 0 {
		return "_No evidence items collected._"
	}

	var buf strings.Builder
	for i, e := range r.Evidence {
		buf.WriteString(fmt.Sprintf("### Evidence %d: %s (%s confidence)\n\n", i+1, e.Type, e.Confidence))
		buf.WriteString(e.Description)
		if e.FilePath != "" {
			buf.WriteString(fmt.Sprintf("\n\n**Location:** `%s:%d`", e.FilePath, e.LineNumber))
		}
		if e.CodeSnippet != "" {
			buf.WriteString(fmt.Sprintf("\n\n```\n%s\n```", e.CodeSnippet))
		}
		buf.WriteString("\n\n")
	}
	return buf.String()
}

func (b *DefaultReportBuilder) buildAttackPath(r AnalystResult) string {
	if len(r.AttackPath) == 0 {
		return "_No attack path constructed. The finding could not be linked to an exploitable chain._"
	}

	var buf strings.Builder
	buf.WriteString("An attacker could exploit this finding through the following steps:\n\n")
	for _, step := range r.AttackPath {
		buf.WriteString(fmt.Sprintf("**Step %d:** %s", step.StepNumber, step.Description))
		if step.FileRef != "" {
			ref := fmt.Sprintf("`%s`", step.FileRef)
			if step.LineRef > 0 {
				ref = fmt.Sprintf("`%s:%d`", step.FileRef, step.LineRef)
			}
			buf.WriteString(fmt.Sprintf(" (%s)", ref))
		}
		buf.WriteString("\n\n")
	}
	return buf.String()
}

func (b *DefaultReportBuilder) buildVerification(r AnalystResult) string {
	if !r.Verification.Verified {
		return fmt.Sprintf("**Verification:** Not independently verified.\n\n**Method:** %s\n\n**Detail:** %s",
			r.Verification.Method, r.Verification.Detail)
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("**Status:** ✅ Independently verified\n\n"))
	buf.WriteString(fmt.Sprintf("**Method:** %s\n\n", r.Verification.Method))
	buf.WriteString(fmt.Sprintf("**Detail:** %s\n\n", r.Verification.Detail))

	if r.Verification.APIEndpoint != "" {
		buf.WriteString(fmt.Sprintf("**API Endpoint:** `%s`\n\n", r.Verification.APIEndpoint))
	}
	if r.Verification.APIResponse != "" {
		buf.WriteString(fmt.Sprintf("**Response:**\n```\n%s\n```\n\n", r.Verification.APIResponse))
	}
	if r.Verification.ReachPath != "" {
		buf.WriteString(fmt.Sprintf("**Data Flow Path:** `%s`\n\n", r.Verification.ReachPath))
	}

	return buf.String()
}

func (b *DefaultReportBuilder) buildFix(r AnalystResult) string {
	if r.FixSuggestion == "" {
		return "_No fix suggestion available._"
	}
	return fmt.Sprintf("### Recommended Fix\n\n%s\n\n**CWE Reference:** [%s](https://cwe.mitre.org/data/definitions/%s.html)",
		r.FixSuggestion, r.CWE, strings.TrimPrefix(r.CWE, "CWE-"))
}

func (b *DefaultReportBuilder) buildFooter(r AnalystResult) string {
	var buf strings.Builder
	buf.WriteString("---\n\n")
	buf.WriteString("*Report generated by Ironwall Agent Engine v0.5.0*\n\n")

	if b.IncludeRawFindings && len(r.RawFindings) > 0 {
		buf.WriteString("### Raw Scanner Findings\n\n")
		for _, rf := range r.RawFindings {
			buf.WriteString(fmt.Sprintf("- **%s** (%s) — `%s:%d`\n", rf.RuleID, rf.Source, rf.FilePath, rf.Line))
		}
	}

	return buf.String()
}
