package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/FYFran/ironwall/internal/report"
)

// BanditFinding is the JSON structure bandit outputs per match.
type BanditFinding struct {
	Filename     string `json:"filename"`
	TestID       string `json:"test_id"`
	TestName     string `json:"test_name"`
	IssueSeverity string `json:"issue_severity"`
	IssueConfidence string `json:"issue_confidence"`
	IssueText    string `json:"issue_text"`
	LineNumber   int    `json:"line_number"`
	LineRange    []int  `json:"line_range"`
	Code         string `json:"code"`
	MoreInfo     string `json:"more_info"`
}

// BanditResult wraps bandit JSON output.
type BanditResult struct {
	Errors  []interface{}        `json:"errors"`
	Results []BanditFinding      `json:"results"`
	Metrics map[string]interface{} `json:"metrics"`
}

// RunBandit runs bandit on the given target and returns parsed results.
func RunBandit(target string) (*BanditResult, error) {
	args := []string{
		"-r", target,
		"-f", "json",
		"--quiet",
	}
	cmd := exec.Command("bandit", args...)
	out, err := cmd.Output()
	if err != nil {
		// bandit exits 1 when findings exist — normal
		if len(out) > 0 {
			return parseBanditOutput(out)
		}
		return nil, fmt.Errorf("bandit failed: %w", err)
	}
	return parseBanditOutput(out)
}

func parseBanditOutput(raw []byte) (*BanditResult, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "{}" {
		return &BanditResult{}, nil
	}
	var result BanditResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse bandit JSON: %w", err)
	}
	return &result, nil
}

// banditCWE maps bandit test IDs to CWE numbers.
var banditCWE = map[string]string{
	"B101": "CWE-79",  // assert — XSS via debug code
	"B102": "CWE-94",  // exec_used — code injection
	"B103": "CWE-22",  // set_bad_file_permissions — path traversal
	"B104": "CWE-22",  // hardcoded_bind_all_interfaces — network binding
	"B105": "CWE-22",  // hardcoded_password_string — hardcoded secret
	"B106": "CWE-798", // hardcoded_password_funcarg — hardcoded secret
	"B107": "CWE-798", // hardcoded_password_default — hardcoded secret
	"B108": "CWE-22",  // hardcoded_tmp_directory — path traversal
	"B110": "CWE-703", // try_except_pass — error handling
	"B112": "CWE-703", // try_except_continue — error handling
	"B201": "CWE-89",  // sql_injection — SQLi via flask_sqlalchemy
	"B202": "CWE-89",  // sql_injection — SQLi via sqlalchemy raw
	"B301": "CWE-502", // pickle — unsafe deserialization
	"B302": "CWE-502", // marshal — unsafe deserialization
	"B303": "CWE-328", // md5 — weak hash
	"B304": "CWE-327", // ciphers — weak encryption
	"B305": "CWE-327", // cipher_modes — weak encryption mode
	"B306": "CWE-327", // mktemp_q — unsafe temp file
	"B307": "CWE-94",  // eval — code injection
	"B308": "CWE-79",  // mark_safe — XSS
	"B309": "CWE-611", // httpsconnection — weak TLS
	"B310": "CWE-22",  // urlopen — path traversal
	"B311": "CWE-330", // random — weak random
	"B312": "CWE-79",  // telnetlib — XSS/security
	"B313": "CWE-327", // xml_bad_etree — XML parsing
	"B314": "CWE-611", // xml_bad_element_tree — XXE
	"B315": "CWE-611", // xml_bad_expatreader — XXE
	"B316": "CWE-611", // xml_bad_expatbuilder — XXE
	"B317": "CWE-611", // xml_bad_sax — XXE
	"B318": "CWE-611", // xml_bad_dom — XXE
	"B319": "CWE-611", // xml_bad_pulldom — XXE
	"B320": "CWE-611", // xml_bad_xmlrpc — XXE
	"B321": "CWE-327", // ftplib — weak encryption
	"B322": "CWE-78",  // input — command injection
	"B323": "CWE-327", // unverified_context — weak SSL
	"B324": "CWE-328", // hashlib — weak hash (MD4/MD5/SHA1)
	"B325": "CWE-327", // tempnam — unsafe temp file
	"B401": "CWE-327", // telnet — weak protocol
	"B402": "CWE-327", // ftp — weak protocol
	"B403": "CWE-502", // pickle — unsafe deserialization
	"B404": "CWE-78",  // subprocess — command injection
	"B405": "CWE-611", // xml_etree — XXE
	"B406": "CWE-327", // cryptography — weak crypto
	"B407": "CWE-327", // cryptography_weak — weak crypto
	"B408": "CWE-327", // cryptography_deprecated — weak crypto
	"B409": "CWE-327", // cryptography_rc4 — weak crypto
	"B410": "CWE-327", // cryptography_idea — weak crypto
	"B411": "CWE-327", // cryptography_blowfish — weak crypto
	"B412": "CWE-327", // cryptography_skip — weak crypto
	"B413": "CWE-327", // cryptography_pycrypto — weak crypto
	"B501": "CWE-295", // request_with_no_cert_validation — weak SSL
	"B502": "CWE-295", // ssl_with_bad_version — weak SSL
	"B503": "CWE-295", // ssl_with_bad_defaults — weak SSL
	"B504": "CWE-295", // ssl_with_no_version — weak SSL
	"B505": "CWE-327", // weak_cryptographic_key — weak crypto
	"B506": "CWE-79",  // yaml_load — unsafe deserialization → XSS
	"B507": "CWE-327", // ssh_no_host_key_verification — weak SSH
	"B601": "CWE-78",  // paramiko_calls — command injection
	"B602": "CWE-78",  // subprocess_popen_with_shell_equals_true — cmd injection
	"B603": "CWE-78",  // subprocess_without_shell_equals_true — cmd injection
	"B604": "CWE-78",  // any_other_function_with_shell_equals_true — cmd injection
	"B605": "CWE-78",  // start_process_with_a_shell — cmd injection
	"B606": "CWE-78",  // start_process_with_no_shell — cmd injection
	"B607": "CWE-78",  // start_process_with_partial_path — cmd injection
	"B608": "CWE-89",  // sql_injection — SQLi
	"B609": "CWE-22",  // linux_commands_wildcard_injection — path traversal
	"B610": "CWE-22",  // django_sql_injection — SQLi via Django
	"B611": "CWE-22",  // django_sql_injection_raw — SQLi via Django raw
	"B701": "CWE-94",  // jinja2_autoescape_false — XSS via Jinja2
	"B702": "CWE-79",  // use_of_mako_templates — XSS via Mako
	"B703": "CWE-79",  // django_mark_safe — XSS via Django
}

// ToFindings converts bandit findings to ironwall Finding structs.
func (r *BanditResult) ToFindings() []report.Finding {
	var findings []report.Finding
	for i, f := range r.Results {
		sev := mapBanditSeverity(f.IssueSeverity, f.IssueConfidence)
		cwe := banditCWE[f.TestID]
		if cwe == "" {
			cwe = "CWE-0" // unknown
		}

		codeSnippet := f.Code
		if codeSnippet == "" {
			codeSnippet = fmt.Sprintf("  %d | %s", f.LineNumber, f.IssueText)
		}

		findings = append(findings, report.Finding{
			ID:           fmt.Sprintf("IRON-BANDIT-%03d", i+1),
			Title:        fmt.Sprintf("[%s] %s: %s", f.TestID, f.TestName, f.IssueText),
			Description:  fmt.Sprintf("Bandit rule %s detected: %s (confidence: %s)", f.TestID, f.IssueText, f.IssueConfidence),
			Severity:     sev,
			FilePath:     f.Filename,
			LineNumber:   f.LineNumber,
			CodeSnippet:  codeSnippet,
			Step:         2,
			Category:     "bandit-" + strings.ToLower(f.TestID),
			CWE:          cwe,
			CVSS:         report.SeverityToCVSS(sev),
			ToolOutput:   fmt.Sprintf("Bandit rule: %s | Severity: %s | Confidence: %s", f.TestID, f.IssueSeverity, f.IssueConfidence),
			References:   []string{"https://bandit.readthedocs.io/en/latest/plugins/" + strings.ToLower(f.TestID) + ".html"},
		})
	}
	return findings
}

func mapBanditSeverity(severity, confidence string) report.Severity {
	switch strings.ToUpper(severity) {
	case "HIGH":
		if strings.ToUpper(confidence) == "HIGH" {
			return report.SevCritical
		}
		return report.SevHigh
	case "MEDIUM":
		if strings.ToUpper(confidence) == "HIGH" {
			return report.SevHigh
		}
		return report.SevMedium
	case "LOW":
		return report.SevLow
	default:
		return report.SevInfo
	}
}
