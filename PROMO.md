# Ironwall — Go Security Scanner

**One command instead of five.** Ironwall runs the tools you already use — semgrep, gitleaks, gosec, grype, govulncheck — merges their results, removes duplicates, and cuts the noise. You get one clean report instead of five noisy ones.

---

## What Ironwall Actually Does

Ironwall is not AI magic. It is an **aggregation and noise-reduction layer** on top of tools you already trust.

```
semgrep (SAST)       ─┐
gosec (Go AST)       ─┤
gitleaks (secrets)   ─┤
grype (CVE)          ─┤
govulncheck (Go CVE) ─┤
custom (endpoints)   ─┘    → Ironwall → 1 report, deduped, noise-filtered
```

Ironwall adds three things the individual tools do not:
1. **Endpoint analysis** — detects your web framework, maps every route, flags missing auth/rate-limit/CORS/CSRF per endpoint
2. **Noise reduction** — test/example files tagged, known false-positive patterns downgraded, informational output separated from real findings
3. **One format** — terminal, markdown, JSON, SARIF, HTML. Same output shape regardless of which underlying tool found it.

---

## Field Test Data (5 Projects, July 2026)

Scanned 5 Go projects with zero prior tuning. Then hand-verified every finding in chi.

| | Ironwall | Semgrep OSS | Gosec | Gitleaks |
|---|---|---|---|---|
| SAST | 4/5 | 4/5 | 2/5 | — |
| Secrets | 5/5 | 1/5 | — | 4/5 |
| Endpoint analysis | 4/5 | — | — | — |
| Dependency CVEs | 3/5 | — | — | — |
| Supply chain | 3/5 | — | — | — |
| Noise filter (test exclusion) | Yes | No | No | No |
| Single command | **Yes** | No | No | No |

**Honest precision (chi, hand-verified):** After noise reduction, 1 finding remained untagged out of 142 total. The raw precision before filtering was 10% — same order of magnitude as any SAST tool on library code. The difference is we filter.

---

## Quick Start

```bash
go install github.com/FYFran/ironwall/cmd/ironwall@latest
ironwall scan ./my-go-project
```

```bash
# Fast mode: secrets + hardcoded patterns only, ~2 seconds
ironwall scan . --quick

# Full report to file
ironwall scan . --format markdown -o report.md

# AI triage (optional): helps you decide which findings to look at first
ironwall scan . --ai
```

---

## Why Not Just Run 5 Tools Separately?

You can. Here is what you would need to do:
1. `gitleaks detect` → JSON output
2. `semgrep --config=auto` → JSON output
3. `gosec ./...` → text output
4. `grype .` → JSON output
5. `govulncheck ./...` → text output
6. Parse 5 formats, deduplicate across tools, filter test files, triage by severity, decide what to actually fix

Ironwall does steps 1-5 in one command. Step 6 is still your judgment — we just give you a cleaner starting point.

---

## Limitations (we tell you upfront)

- **Not AI-powered vulnerability discovery.** The `--ai` mode helps with triage (which of these 35 findings should I look at first?), not with finding new things.
- **Go-first.** Python via bandit+semgrep. Other languages via semgrep only.
- **Precision varies.** ~10% raw on library code (same as any SAST tool), ~95% after our noise filters on chi. We publish real data, not marketing numbers.
- **Not a pentesting replacement.** Finds code-level issues. Runtime exploitation requires a human.
- **Stdlib CVEs detected** via govulncheck (71 found across 5 test projects).

---

## Pricing (on Xianyu)

| Tier | Price | Includes |
|------|-------|----------|
| **OSS** | Free | Full pipeline, terminal/JSON/SARIF output |
| **Pro** | 29 yuan/month | AI triage, HTML/markdown reports, email support |
| **Team** | 99 yuan/month | CI/CD integration, 5 projects, priority support |

---

## Roadmap

- [x] 8-step pipeline (5 tools + endpoint analysis + noise reduction)
- [x] Test/example exclusion
- [x] Gosec category correction
- [x] Noise reduction rules (G104, G710, step9 library detection)
- [x] Field test with hand-verified precision (chi: 142 → 1 untagged)
- [ ] CI/CD GitHub Action
- [ ] VS Code extension
- [ ] Framework-specific security profiles (Gin, Echo, Chi, Fiber)

---

*Built by a college student who was tired of running the same 5 tools every code review. 泰州.*
