package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSeverityString(t *testing.T) {
	assert.Equal(t, "CRITICAL", SevCritical.String())
	assert.Equal(t, "HIGH", SevHigh.String())
	assert.Equal(t, "MEDIUM", SevMedium.String())
	assert.Equal(t, "LOW", SevLow.String())
	assert.Equal(t, "INFO", SevInfo.String())
}

func TestSeverityEmoji(t *testing.T) {
	assert.Equal(t, "🔴", SevCritical.Emoji())
	assert.Equal(t, "🟠", SevHigh.Emoji())
	assert.Equal(t, "🟡", SevMedium.Emoji())
	assert.Equal(t, "🟢", SevLow.Emoji())
	assert.Equal(t, "ℹ️", SevInfo.Emoji())
}

func TestSeverityToCVSS(t *testing.T) {
	assert.Equal(t, 9.8, SeverityToCVSS(SevCritical))
	assert.Equal(t, 7.5, SeverityToCVSS(SevHigh))
	assert.Equal(t, 5.0, SeverityToCVSS(SevMedium))
	assert.Equal(t, 2.5, SeverityToCVSS(SevLow))
	assert.Equal(t, 0.0, SeverityToCVSS(SevInfo))
}

func TestScanSummaryAddFinding(t *testing.T) {
	s := &ScanSummary{}

	s.AddFinding(Finding{Severity: SevCritical})
	assert.Equal(t, 1, s.Critical)
	assert.Equal(t, 1, s.Total)

	s.AddFinding(Finding{Severity: SevHigh})
	s.AddFinding(Finding{Severity: SevHigh})
	assert.Equal(t, 2, s.High)
	assert.Equal(t, 3, s.Total)

	s.AddFinding(Finding{Severity: SevMedium})
	assert.Equal(t, 1, s.Medium)
	assert.Equal(t, 4, s.Total)

	s.AddFinding(Finding{Severity: SevLow})
	assert.Equal(t, 1, s.Low)

	s.AddFinding(Finding{Severity: SevInfo})
	assert.Equal(t, 1, s.Info)
	assert.Equal(t, 6, s.Total)
}

func TestTruncateString(t *testing.T) {
	assert.Equal(t, "hello", TruncateString("hello", 10))
	assert.Equal(t, "hello...", TruncateString("hello world long", 8))
	// maxLen too small — returns original
	assert.Equal(t, "abcdef", TruncateString("abcdef", 3))
}
