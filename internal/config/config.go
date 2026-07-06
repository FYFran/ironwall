package config

import (
	"os"
	"path/filepath"
)

// Config holds all configuration for an ironwall scan.
type Config struct {
	// Target is the directory or file to scan.
	Target string

	// OutputFormat is the report format: "terminal", "markdown", or "json".
	OutputFormat string

	// OutputFile is the path to write the report (empty = stdout for terminal, auto-name for markdown).
	OutputFile string

	// QuickMode runs only fast steps (1 + 4) — gitleaks + hardcoded secrets.
	QuickMode bool

	// FullMode runs all 7 steps (default: steps 1-7).
	FullMode bool

	// NoColor disables colored terminal output.
	NoColor bool

	// Verbose enables debug-level logging.
	Verbose bool

	// AI config
	AIModel     string // Triage model (e.g. "deepseek-chat") — fast, cheap
	AIDeepModel string // Deep verify model (e.g. "deepseek-reasoner") — reasoning, adversarial
	AIEndpoint  string // API endpoint base URL
	AIKey       string // API key (from env: IRONWALL_AI_KEY or DEEPSEEK_API_KEY)
	AIEnabled   bool   // Whether AI analysis is enabled

	// TimeoutSeconds is the max time for the full scan (0 = no limit).
	TimeoutSeconds int

	// GitCloneDepth for --github mode (0 = full clone).
	GitCloneDepth int
}

// Defaults returns a Config populated with sensible defaults.
func Defaults() *Config {
	return &Config{
		OutputFormat:   "terminal",
		FullMode:       true,
		QuickMode:      false,
		NoColor:        false,
		Verbose:        false,
		AIEnabled:      false,
		AIModel:        "deepseek-chat",
		AIDeepModel:    "deepseek-reasoner",
		AIEndpoint:     "https://api.deepseek.com/v1",
		TimeoutSeconds: 300,
		GitCloneDepth:  0,
	}
}

// ResolveAIKey looks up the AI API key from environment variables.
func (c *Config) ResolveAIKey() {
	if c.AIKey != "" {
		return
	}
	if key := os.Getenv("IRONWALL_AI_KEY"); key != "" {
		c.AIKey = key
		return
	}
	if key := os.Getenv("DEEPSEEK_API_KEY"); key != "" {
		c.AIKey = key
		return
	}
	c.AIEnabled = false
}

// ReportFilename generates a default report filename based on target and timestamp.
func (c *Config) ReportFilename() string {
	if c.OutputFile != "" {
		return c.OutputFile
	}
	base := filepath.Base(c.Target)
	if base == "." || base == ".." {
		abs, _ := filepath.Abs(c.Target)
		base = filepath.Base(abs)
	}
	return "ironwall-report-" + base + ".md"
}
