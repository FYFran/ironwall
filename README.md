# 🔍 Ironwall — 7-Step Security Audit CLI

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-orange)](https://github.com/FYFran/ironwall/releases)

**Open-source security audit CLI. 7-step pipeline. AI-assisted analysis. Your code never leaves your machine.**

> ⚠️ **Phase 1 (v0.1.0):** Step 1 (gitleaks) is functional. Steps 2-7 are under active development.

## 🎯 What It Does

Ironwall scans your codebase through a 7-step security audit pipeline:

| Step | Name | Tool | What It Finds |
|------|------|------|---------------|
| 1 | 🔑 Secret Scanning | gitleaks | API keys, tokens, passwords in code |
| 2 | 🔬 SAST Analysis | semgrep + AI | SQL injection, XSS, command injection |
| 3 | 🔗 Endpoint Audit | AI | Auth bypass, IDOR, missing access control |
| 4 | 🔐 Hardcoded Secrets | AI | Patterns gitleaks missed |
| 5 | 📦 Dependency CVE | go/npm/pip | Known vulnerabilities in dependencies |
| 6 | 🖥️ Server Config | AI | Nginx, Docker, env misconfigurations |
| 7 | 🗄️ Database Audit | AI | Migration risks, SQL anti-patterns |

**Key principle:** All scanning happens locally. AI analysis optionally sends **code snippets** (not your entire repo) to the API using your own key.

## 📦 Installation

```bash
go install github.com/FYFran/ironwall/cmd/ironwall@latest
```

Or build from source:

```bash
git clone https://github.com/FYFran/ironwall.git
cd ironwall
make build
```

**Requirements:**
- Go 1.22+
- [gitleaks](https://github.com/gitleaks/gitleaks) (`go install github.com/gitleaks/gitleaks/v8@latest`)

## 🚀 Quick Start

```bash
# Scan current directory (terminal output)
ironwall scan .

# Quick scan — only secrets + hardcoded patterns (< 30s)
ironwall quick .

# Generate markdown report
ironwall scan . --format markdown

# Generate JSON report (for CI pipelines)
ironwall scan . --format json --output report.json

# Enable AI-assisted analysis
export DEEPSEEK_API_KEY="sk-..."
ironwall scan . --ai
```

## 📊 Example Output

```
🔍 ironwall v0.1.0 — 7-Step Security Audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:    ./my-app
Duration:  2.3s

  🔑 Secret scanning (gitleaks) .................... 2 found
  🔬 SAST (semgrep + AI) ............................ 5 found
  ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SUMMARY
  🔴 CRITICAL: 1   🟠 HIGH: 5   🟡 MEDIUM: 5   🟢 LOW: 3
  📄 Full report: ./ironwall-report-my-app.md
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 🔧 Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `markdown`, `json` |
| `--output`, `-o` | auto | Output file path |
| `--quick` | false | Only run fast steps (1+4) |
| `--ai` | false | Enable AI-assisted analysis |
| `--ai-model` | `deepseek-chat` | Model name (also supports OpenAI, Claude) |
| `--timeout` | 300 | Max scan time in seconds |
| `--verbose`, `-v` | false | Verbose output |

**Environment variables:**
- `IRONWALL_AI_KEY` or `DEEPSEEK_API_KEY` — Your AI API key
- `IRONWALL_AI_ENDPOINT` — Custom API endpoint (default: DeepSeek)

## 🏗️ Architecture

```
ironwall CLI
  ├── Pipeline Engine (sequential step execution)
  ├── AI Engine (DeepSeek API — optional)
  ├── Reporter Engine (terminal / markdown / JSON)
  └── External Tools (gitleaks, semgrep, nuclei, ...)
```

All external tools run as subprocesses on the user's machine. The AI engine uses the OpenAI-compatible API interface — works with DeepSeek, OpenAI, Claude, or local Ollama.

## 📖 Methodology

Ironwall follows a **7-step gated pipeline** inspired by professional security audit workflows:

1. **Gated execution** — Step 1 (gitleaks) is TIER1. If it fails, the scan aborts.
2. **Attack scenario verification** — Every AI-generated finding must pass three questions:
   - Q1: What role/conditions does the attacker need?
   - Q2: What is the concrete attack path?
   - Q3: What does the attacker gain?
   - If all three have specific, concrete answers → real vulnerability. Otherwise → filtered.
3. **Gotchas library** — Curated patterns that static analyzers typically miss.

Read the full methodology: [docs/methodology.md](docs/methodology.md)

## 🆚 Comparison

| | strix | PentestMate | **Ironwall** |
|---|---|---|---|
| Mode | Open-source CLI | Closed SaaS | **Open-source CLI** |
| Price | Free | $59/mo | **Free (MIT)** |
| Method | Multi-agent pentest | Scan-focused | **7-step gated + gotchas** |
| False positives | PoC-verified | Low | **Three-question attack verification** |

## 🗺️ Roadmap

- [x] v0.1.0 — Step 1: Secret scanning (gitleaks)
- [x] v0.2.0 — Steps 2+4: SAST + Hardcoded secrets with AI (545x faster)
- [x] v0.3.0 — Steps 3+5+6+7: Endpoint audit + Dependencies + Server + Database
- [x] v0.3.1 — Nuclei scanner, review command (diff-only), gitleaks tests, Fiverr gig
- [x] v0.4.0 — 8-step pipeline: Betterleaks (98.6% recall), CodeQL, KICS, Syft/Grype, supply chain, AI engine (dual-model V3+R1), SARIF, CI templates
- [ ] v0.5.0 — Custom rule engine, plugin system, language-specific gotchas expansion
- [ ] v1.0.0 — Stable API, comprehensive benchmarks, marketplace integration

## 🤝 Contributing

Contributions welcome! Especially:
- **Gotchas** — Patterns your tools missed. Add to `docs/gotchas.md`.
- **Test data** — Vulnerable code samples for `testdata/`.
- **Language support** — Scanner modules for new languages.

See [CONTRIBUTING.md](CONTRIBUTING.md) (coming soon).

## 📄 License

MIT © 2026 [FYFran](https://github.com/FYFran)

---

*Built by [@FYFran](https://github.com/FYFran) — CS freshman at Taizhou University. Learning security by building tools.*
