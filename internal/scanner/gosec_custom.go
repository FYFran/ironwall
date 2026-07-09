package scanner

// Go Security Pattern Coverage
// =============================
// Ironwall's Go analysis uses a three-layer approach:
//
// Layer 1: Embedded gosec (77ms, ~30 rules)
//   Covers: SQL injection, hardcoded secrets, weak crypto, path traversal, SSRF, XSS
//   Rule set: G101-G402 (see https://github.com/securego/gosec#available-rules)
//
// Layer 2: AI Engine (DeepSeek API)
//   Handles: Cross-function data flow, business logic flaws, complex taint paths
//   Activation: --ai flag
//
// Layer 3: Semgrep (optional, if installed)
//   Handles: Multi-language pattern matching, framework-specific rules
//
// Gap Analysis (Go patterns NOT covered by gosec + AI):
//   - yaml.Unmarshal Billion Laughs (CWE-776) → gosec G305 in development
//   - filepath.Clean with traversal bypass (CWE-22 variant) → requires inter-procedural analysis
//   - reflect.ValueOf misuse → application-specific, low signal
//   - sync/atomic misuse → concurrency bug, not security
//
// Future work (v0.8.0+):
//   - Custom gosec rules (requires gosec analyzer API integration, ~2 days)
//   - Cross-function taint tracking (mini data-flow engine, ~2 weeks)
//   - gopls-based semantic analysis (LSP integration, ~1 week)

// Note: Ironwall's AI engine already detects many patterns that would require
// custom rules. The AI sees full function context (source→sink) and can flag
// issues that AST-level rules miss due to function boundaries.
