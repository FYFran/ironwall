# Ironwall Benchmark Methodology v1.0

## Overview

This document describes the methodology used to evaluate Ironwall's vulnerability detection capabilities against real-world CVE patterns and open-source Go projects. The benchmark is designed to be reproducible, transparent about limitations, and aligned with academic standards for security tool evaluation.

---

## Test Suite Structure

### Suite A: Curated CVE Pattern Detection (15 cases)

Synthetic test files each containing a single vulnerability pattern mapped to a real CVE category. Each file is a minimal, compilable Go program that isolates the vulnerability.

**Selection criteria:**
- Pattern appears in at least one real CVE with a CWE classification
- Pattern is detectable by static analysis (not runtime-only)
- Pattern covers a distinct CWE category (no duplicates)
- Pattern is relevant to Go web/backend applications

**Cases:**

| # | CWE | Category | Real CVE Reference |
|---|-----|----------|-------------------|
| 1 | CWE-89 | SQL Injection | CVE-2020-series Go CRUD apps |
| 2 | CWE-22 | Path Traversal | CVE-2023-45283 (filepath.Clean) |
| 3 | CWE-78 | Command Injection | CVE-2021-series (os/exec) |
| 4 | CWE-798 | Hardcoded Secrets | CVE-2019-series leaked credentials |
| 5 | CWE-327 | Weak Cryptography | CVE-2020-series (MD5/SHA1/DES) |
| 6 | CWE-918 | SSRF | CVE-2021-series (http.Get user URL) |
| 7 | CWE-79 | XSS via Templates | CVE-2023-29400 (html/template) |
| 8 | CWE-295 | TLS Bypass | CVE-2021-series InsecureSkipVerify |
| 9 | CWE-338 | Insecure Random | CVE-2023-series (math/rand) |
| 10 | CWE-601 | Open Redirect | CVE-2023-series (http.Redirect) |
| 11 | CWE-943 | NoSQL Injection | CVE-2021-20329 (mongo-go-driver) |
| 12 | CWE-770 | Resource Exhaustion | CVE-2023-24536 (multipart form) |
| 13 | CWE-347 | JWT Algorithm Confusion | CVE-2022-39221 (jwt-go) |
| 14 | CWE-532 | Sensitive Data in Logs | CVE-2023-series (credential logging) |
| 15 | CWE-915 | Prototype Pollution | Common in Go map manipulation |

### Suite B: Real-World Field Test (5 projects)

Five open-source Go projects scanned without prior tuning or configuration.

**Selection criteria:**
- Popular (100+ stars on GitHub)
- Diverse domains (auth, routing, networking, database, CLI)
- Go-native (not multi-language monorepos)
- Security-relevant attack surface
- Not previously scanned by Ironwall

**Projects:**

| Project | Domain | Approx. LOC | GitHub Stars |
|---------|--------|-------------|-------------|
| golang-jwt/jwt | JWT authentication | ~5,000 | 7k+ |
| go-chi/chi | HTTP router/middleware | ~6,000 | 18k+ |
| gorilla/websocket | WebSocket library | ~4,000 | 22k+ |
| go-sql-driver/mysql | MySQL driver | ~10,000 | 14k+ |
| urfave/cli | CLI framework | ~3,000 | 22k+ |

---

## Measurement Metrics

### Primary Metrics

| Metric | Definition | Formula |
|--------|-----------|---------|
| **Recall (CVE)** | Proportion of known CVE patterns detected | TP / (TP + FN) |
| **Finding Count** | Total findings reported after deduplication | count(findings) |
| **Noise Reduction** | Proportion of findings filtered as test/example | tagged / total |

### Secondary Metrics

| Metric | Definition |
|--------|-----------|
| **Category Coverage** | Number of distinct CWE categories with at least 1 finding |
| **Tool Overlap** | Proportion of findings found by both tools vs either |
| **Speed** | Wall-clock time for full scan |

### Precision Estimation

Precision requires manual verification of every finding. We provide:
1. **Estimated precision by category** — based on pattern type (secrets > SAST > endpoint analysis)
2. **Precision baseline** — for chi project, manual TP/FP verification of 100% of findings

---

## Test Environment

```
OS:      Windows 11
Go:      1.21+
Ironwall: v0.7.0 (commit: see git log)
Semgrep: latest OSS (pip install semgrep)
CPU:     Consumer laptop (no GPU used)
```

**Ironwall flags:** `--format json --timeout 120` (default pipeline, no AI)
**Semgrep flags:** `--config=auto --no-git-ignore --json`

---

## Limitations (Honest Disclosure)

1. **Sample size.** 15 synthetic CVE cases + 5 projects. Not statistically significant for broad claims. Expanding to CVEfixes full DB (~12k CVEs) would improve confidence.
2. **Synthetic bias.** Suite A cases are *designed* to be detected. Real code has more nuance, dead code, and compensating controls. Suite A recall is an upper bound.
3. **Selection bias.** Suite B projects are well-maintained, popular repos. They may have fewer vulnerabilities than average. Results may not generalize to legacy or proprietary code.
4. **No manual verification (full).** Only chi project has 100% manual TP/FP verification. Other projects use category-based estimation.
5. **Version pinning.** Results are tied to specific tool versions. Both Ironwall and Semgrep rules change frequently.
6. **Single language.** Go-only. Multi-language projects would stress different code paths.

---

## Reproducibility

```bash
# Suite A: CVE Pattern Detection
cd benchmark
python run_benchmark.py

# Suite B: Field Test
cd field_test
python batch_scan.py

# Analysis
python summary_v3.py
```

Full raw outputs available in `raw_outputs/` and `field_test/iw_*_v3.json`.

---

## Comparison to Academic Standards

| Standard | Our Status | Gap |
|----------|-----------|-----|
| **OWASP Benchmark** | Not run | Requires Java/PHP test suite setup |
| **CVEfixes (full)** | Not run | 12.7GB DB download pending |
| **NIST SAMATE** | Not run | Requires C/Java test cases |
| **Statistical significance** | Partial | 15 cases + 5 projects = indicative only |
| **Cross-validation** | Partial | Semgrep comparison done, CodeQL pending |
| **Blind verification** | Not done | Findings not blinded for manual review |

---

*Version: 1.0 | Last updated: 2026-07-14 | Author: Ironwall Benchmark Suite*
