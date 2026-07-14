# Ironwall — Go Security Scanner

**Find what SAST misses.** Ironwall combines 8 analysis steps into one tool: secrets, SAST, endpoints, dependencies, config, supply chain.

---

## Why Ironwall

Semgrep finds code patterns. Gitleaks finds secrets. Neither finds missing auth on your API endpoints. Neither tells you your dependencies have known CVEs. You run 4 tools, merge results, deduplicate — or you run Ironwall once.

**Ironwall = Semgrep + Gitleaks + Gosec + Grype + Endpoint Analysis + Supply Chain. In one binary.**

---

## 5-Project Field Test (July 2026)

Scanned 5 Go open-source projects with zero prior tuning. Compared head-to-head with Semgrep OSS.

| | Ironwall | Semgrep |
|---|---|---|
| **Total findings** | 308 (107 after test exclusion) | 60 |
| **Unique categories** | Secrets, SAST, Endpoints, Config, Dependencies, Supply Chain | SAST only |
| **Secrets detected** | Yes (gitleaks + custom patterns) | No (0 on hardcoded secrets) |
| **Endpoint analysis** | Yes (framework detection + missing controls) | No |
| **Dependency CVEs** | Yes (govulncheck + grype) | No |
| **Supply chain** | Yes (SBOM + OpenSSF + unpinned actions) | No |

---

## vs The Competition

| Dimension | Ironwall | Semgrep OSS | Gosec | Gitleaks |
|-----------|----------|-------------|-------|----------|
| SAST (code patterns) | 4/5 | 4/5 | 2/5 | — |
| Secrets | 5/5 | 1/5 | — | 4/5 |
| Endpoint analysis | 4/5 | — | — | — |
| Dependency CVEs | 3/5 | — | — | — |
| Config/IaC audit | 3/5 | — | — | — |
| Supply chain | 3/5 | — | — | — |
| Test exclusion | Yes | No | No | No |
| **All-in-one** | **Yes** | No | No | No |

---

## Quick Start

```bash
go install github.com/FYFran/ironwall/cmd/ironwall@latest
ironwall scan ./my-go-project
```

Output formats: terminal, markdown, json, sarif, html.

---

## Pricing

| Tier | Price | Includes |
|------|-------|----------|
| **OSS** | Free | 8-step pipeline, terminal output, JSON/SARIF |
| **Pro** | 29 yuan/mo | AI noise filtering, HTML/PDF reports, priority support |
| **Team** | 99 yuan/mo | CI/CD integration, team dashboard, 5 projects |

Launch: first 50 Pro users 50% off for 3 months. Code: `IRONWALL-LAUNCH`

---

## Honest Limitations

- **Precision:** ~50-70% on unseen code. AI mode improves this. Working on it.
- **Go-first.** Python via bandit+semgrep. Other languages via semgrep only.
- **Not pentesting.** Finds code-level issues, not runtime exploits.

---

*Built by a college freshman who got tired of running 4 tools separately.*
