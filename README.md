# 🛡️ Ironwall — Multi-SAST Runner with AI Noise Filter

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.7.0-orange)](https://github.com/FYFran/ironwall/releases)

**Run semgrep + gosec + bandit with one command. AI filters the false positives.**

Ironwall combines multiple open-source SAST scanners into a unified pipeline. A single command runs them all, deduplicates findings, and optionally uses AI to separate real vulnerabilities from noise.

---

## ⚡ What Ironwall Actually Does

```
$ ironwall scan .
🔍 ironwall v0.7.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:    ./my-app
Duration:  12.4s
Findings:  12 (after AI filtering: 403 → 12 actionable)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

- **Multi-scanner pipeline** — semgrep + gosec + bandit + gitleaks + syft/grype + KICS in one run
- **Built-in deduplication** — same finding reported by multiple tools merged into one (7.5% precision improvement)
- **AI noise filter** — DeepSeek reviews findings, separates real vulns from false positives (Precision 100% on battle-tested findings)
- **CI-ready** — SARIF output, GitHub Actions template, JSON/Markdown/Terminal formats
- **~$0.02/scan** — AI filtering costs pennies, not dollars

---

## 🚀 Quick Start

```bash
# Install
go install github.com/FYFran/ironwall/cmd/ironwall@latest

# Scan your code (SAST only, no AI)
ironwall scan .

# With AI noise filtering
export DEEPSEEK_API_KEY="sk-..."
ironwall scan . --ai

# CI mode — SARIF output for GitHub Security tab
ironwall scan . --format sarif --output results.sarif

# Review mode — scan only changed files (diff-based)
ironwall review HEAD~1
```

**Requirements:** Go 1.22+. External scanners (semgrep, gosec, bandit) auto-detected if installed.

---

## 🧱 Pipeline (8 Steps)

| Step | What Runs | What It Finds |
|:----:|-----------|---------------|
| 1 | **Gitleaks** | Secrets, tokens, API keys, private keys |
| 2 | **Semgrep + Gosec + Bandit** | SQL injection, XSS, command injection, path traversal, weak crypto |
| 3 | **Route Detector** | HTTP endpoints (Flask, Gin, Echo, chi, etc.) |
| 4 | **Pattern Scanner** | Hardcoded credentials, debug flags, leftover comments |
| 5 | **Syft + Grype** | Known CVEs in Go, npm, pip, Docker dependencies |
| 6 | **KICS** | Terraform, Docker, K8s, CloudFormation misconfigurations |
| 7 | **DB Config Check** | Database connection strings, weak auth patterns |
| 8 | **AI Noise Filter** | Reviews findings via DeepSeek API, filters false positives |

Steps 1-7 run 100% locally. Step 8 (AI filter) requires DeepSeek API key.

---

## 📊 Honest Numbers

*Battle-tested on 4 real projects (544–6,826 lines, Python + Go). Full report: [FINAL_REPORT.md](battle_test_candidates/FINAL_REPORT.md)*

| Metric | No AI | With AI Filter |
|--------|:---:|:---:|
| **Precision** (actionable findings) | 26.7% | **100%** |
| **Recall** (vs ground truth) | 9.5% | 9.5% (unchanged — AI doesn't find new vulns) |
| **Scan speed** | ~2,900 lines/sec | ~500 lines/sec (AI adds latency) |
| **Cost** | Free | ~$0.02/scan |

**What this means:** AI makes findings trustworthy (zero false positives on actionable items). But it doesn't find vulnerabilities the underlying scanners miss. Ironwall's Recall is bounded by semgrep/gosec/bandit rule coverage.

**OWASP Python Benchmark (1,230 test cases):**

| Tool | Strict Recall | Strict F3 | CWE Covered |
|------|:---:|:---:|:---:|
| semgrep alone | 0.126 | 0.127 | 5/14 |
| **Ironwall (no AI)** | **0.372** | **0.339** | **10/14** |

Ironwall's multi-scanner approach (semgrep + bandit + p/python rules) finds 3× more real vulns than semgrep alone on Python.

---

## 🔧 Usage

```bash
# Full audit
ironwall scan <target>

# With AI noise filter
ironwall scan . --ai

# Quick secrets-only scan
ironwall quick <target>

# Review mode — only changed files
ironwall review <base-ref>

# Custom config
ironwall scan . --config ironwall.yaml --format json -o report.json

# Skip specific steps
ironwall scan . --skip step5,step7

# Doctor — check tool availability
ironwall doctor
```

### Output Formats

| Format | Use Case |
|--------|----------|
| `terminal` | Interactive review (default) |
| `markdown` | Team review, PR comments |
| `json` | CI pipelines, API consumption |
| `sarif` | GitHub Security tab, Code Scanning alerts |

### Configuration File

```yaml
# ironwall.yaml
pipeline:
  step1: { enabled: true, on_failure: fail }
  step5: { enabled: true, on_failure: warn }
ai:
  model: deepseek-chat
  endpoint: https://api.deepseek.com
ignore:
  paths: ["vendor/", "testdata/", "*.pb.go"]
  rules: ["generic-api-key-in-test-file"]
```

---

## 🆚 vs The Alternatives

| | Ironwall | Semgrep CLI | Trivy | Snyk |
|---|---|---|---|---|
| **Price** | Free (MIT) | Free (OSS) | Free | Freemium |
| **Multi-scanner** | ✅ semgrep+gosec+bandit | ❌ | ✅ | ✅ |
| **Secret scanning** | ✅ Gitleaks | ❌ | ✅ | ✅ |
| **Dependency CVEs** | ✅ Syft + Grype | ❌ | ✅ | ✅ |
| **IaC scanning** | ✅ KICS | ❌ | ✅ | ✅ |
| **AI noise filter** | ✅ DeepSeek ($0.02/scan) | ❌ (Assistant = paid) | ❌ | ✅ (paid) |
| **Deduplication** | ✅ Cross-tool | ❌ | ❌ | ✅ |
| **SARIF output** | ✅ | ✅ | ✅ | ✅ |
| **Diff-only review** | ✅ `review` command | ❌ (ci mode) | ❌ | ❌ |
| **Offline (no AI)** | ✅ | ✅ | ✅ | ❌ |

**Ironwall's niche:** One command = 4+ tools. AI filter makes output actually readable. Best for devs who want SAST without configuring a security pipeline.

---

## ⚠️ Limitations (Honest)

1. **AI needs network.** The noise filter calls DeepSeek API. No local LLM support yet.
2. **AI doesn't find new vulns.** It filters existing findings — it won't catch what semgrep/gosec miss.
3. **Recall is bounded by rules.** If a CWE has no detection rule, Ironwall won't find it.
4. **Go detection is weak.** gosec rules are limited. Python detection is better (semgrep + bandit).
5. **Not a replacement for security review.** It's a time-saver, not a security auditor.
6. **AI filter tested on n=30 findings.** Precision numbers are indicative, not statistically significant.

---

## 🗺️ Roadmap

- [x] **v0.7.0** — AI noise filter (DeepSeek), bandit integration, multi-scanner dedup, battle-tested on 4 projects
- [x] **v0.4.0** — 8-step pipeline, CodeQL, KICS, Syft/Grype, supply chain, SARIF
- [x] **v0.3.0** — 7-step pipeline, Nuclei scanner, review command
- [ ] **v0.8.0** — Local LLM support (Ollama), dashboard, more detection rules
- [ ] **v1.0.0** — Stable API, comprehensive benchmarks

---

## 🤝 Contributing

Looking for help with:

- **Detection rules** — Add semgrep/bandit/gosec rules for missing CWE coverage.
- **Test fixtures** — Real-world vulnerable code samples for `testdata/`.
- **Scanner plugins** — Add support for your language/framework.
- **CI integrations** — GitLab CI, CircleCI, Bitbucket Pipelines templates.

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 License

MIT © 2026 [FYFran](https://github.com/FYFran)
