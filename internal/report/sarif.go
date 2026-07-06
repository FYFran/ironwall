package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/FYFran/ironwall/internal/config"
)

// SARIF v2.1.0 output for GitHub Code Scanning integration.

// SARIFLog is the root SARIF v2.1.0 object.
type SARIFLog struct {
	Version string    `json:"version"` // "2.1.0"
	Schema  string    `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run of the analysis tool.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
	Artifacts []SARIFArtifact `json:"artifacts,omitempty"`
}

// SARIFTool describes the tool that performed the analysis.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver contains tool metadata.
type SARIFDriver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	InformationURI  string `json:"informationUri"`
	Rules           []SARIFRule `json:"rules"`
}

// SARIFRule describes a detection rule.
type SARIFRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	HelpURI string `json:"helpUri,omitempty"`
}

// SARIFResult is a single finding in SARIF format.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"` // "error", "warning", "note", "none"
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage is the result message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation points to the code location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation contains file and region info.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

// SARIFArtifactLocation identifies the file.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion is the line range.
type SARIFRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

// SARIFArtifact represents analyzed files.
type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
}

// WriteSARIF writes the scan result as a SARIF v2.1.0 JSON file.
func WriteSARIF(result *ScanResult, cfg *config.Config) error {
	sarif := convertToSARIF(result)

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal SARIF: %w", err)
	}

	filename := cfg.ReportFilename()
	// Change extension to .sarif.json
	if len(filename) > 3 {
		filename = filename[:len(filename)-3] + ".sarif.json"
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("write SARIF: %w", err)
	}

	fmt.Printf("SARIF report written to %s\n", filename)
	return nil
}

func convertToSARIF(result *ScanResult) *SARIFLog {
	// Collect unique rule IDs
	ruleSet := make(map[string]string)
	for _, f := range result.Findings {
		if f.Category != "" {
			ruleSet[f.Category] = f.Title
		}
	}

	// Build rules
	var rules []SARIFRule
	for cat, desc := range ruleSet {
		rule := SARIFRule{ID: cat}
		rule.ShortDescription.Text = desc
		rule.HelpURI = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cat)
		rules = append(rules, rule)
	}

	// Build results
	var results []SARIFResult
	for _, f := range result.Findings {
		level := mapSeverityToSARIFLevel(f.Severity)
		result := SARIFResult{
			RuleID: f.Category,
			Level:  level,
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s: %s", f.Title, f.Description),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: f.FilePath},
						Region:           SARIFRegion{StartLine: f.LineNumber},
					},
				},
			},
			Properties: map[string]interface{}{
				"cvss":  f.CVSS,
				"cwe":   f.CWE,
				"step":  f.Step,
				"ai_confidence": f.AIConfidence,
			},
		}
		if f.FixSuggestion != "" {
			result.Properties["fix"] = f.FixSuggestion
		}
		results = append(results, result)
	}

	return &SARIFLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "ironwall",
						Version:        result.Version,
						InformationURI: "https://github.com/FYFran/ironwall",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

func mapSeverityToSARIFLevel(s Severity) string {
	switch s {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow:
		return "note"
	default:
		return "none"
	}
}

func init() {
	// SARIF timestamp helper
	_ = time.Now
}
