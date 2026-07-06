package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGitleaksOutput_Empty(t *testing.T) {
	result, err := parseGitleaksOutput([]byte("[]"))
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result.Findings)
}

func TestParseGitleaksOutput_SingleFinding(t *testing.T) {
	json := `[{
		"RuleID": "test-rule",
		"Description": "Test finding",
		"StartLine": 10,
		"EndLine": 10,
		"File": "test.go",
		"Secret": "my-secret-key-12345",
		"Match": "secret = \"my-secret-key-12345\"",
		"Entropy": 4.5,
		"Tags": ["key"],
		"Fingerprint": "test.go:test-rule:10"
	}]`

	result, err := parseGitleaksOutput([]byte(json))
	require.NoError(t, err)
	assert.Equal(t, 1, len(result.Findings))
	assert.Equal(t, "test-rule", result.Findings[0].RuleID)
	assert.Equal(t, "test.go", result.Findings[0].File)
	assert.Equal(t, 10, result.Findings[0].StartLine)
}

func TestParseGitleaksOutput_Invalid(t *testing.T) {
	_, err := parseGitleaksOutput([]byte("not json at all"))
	assert.Error(t, err)
}

func TestGitleaksToFindings(t *testing.T) {
	result := &GitleaksResult{
		Findings: []gitleaksFinding{
			{
				RuleID:      "generic-api-key",
				Description: "API Key",
				StartLine:   15,
				File:        "config.go",
				Secret:      "sk-abc123def456",
				Entropy:     5.2,
				Tags:        []string{"key"},
			},
		},
	}

	findings := result.ToFindings("/test")
	assert.Equal(t, 1, len(findings))
	assert.Equal(t, "IRON-GITLEAKS-001", findings[0].ID)
	assert.Equal(t, "config.go", findings[0].FilePath)
	assert.Equal(t, 15, findings[0].LineNumber)
}

func TestMaskSecret(t *testing.T) {
	// len <= 8 → all asterisks
	assert.Equal(t, "***", maskSecret("abc"))
	assert.Equal(t, "********", maskSecret("12345678"))
	// len > 8 → first 4 + asterisks + last 4
	assert.Equal(t, "sk-a*******f456", maskSecret("sk-abc123def456")) // 15 chars: 4+7+4
}
