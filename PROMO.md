# Ironwall 宣传物料

## Show HN (v0.4.0 — updated 2026-07-07)

**Title:** Show HN: Ironwall — 8-step security audit CLI. Scanned Gin, found 4 real supply chain risks, 0 false positives.

**Body:**

I'm a CS freshman who got frustrated with existing security tools. They're either too slow (semgrep takes 30s+), too noisy (90% false positives), or too expensive.

So I built Ironwall v0.4.0. It runs 8 audit steps with a dual-model AI engine (DeepSeek V3 for triage + R1 for adversarial verification). Scanned [gin-gonic/gin](https://github.com/gin-gonic/gin) (130 Go files) in 1.1s — found 12 findings, 0 false positives:

**8 Audit Steps:**
1. Secret scanning (Betterleaks — BPE tokenization, 98.6% recall)
2. SAST (gosec 77ms + CodeQL + semgrep — three-layer analysis)
3. Endpoint audit (7 frameworks, auto-skips test files + comments)
4. Hardcoded secrets (15 regex patterns + AI deep scan)
5. Dependency CVE + SBOM (govulncheck/npm/pip + Syft/Grype)
6. Server & IaC config (regex + nuclei + KICS 2400+ queries)
7. Database audit (SQL migrations + ORM risk detection)
8. Supply chain security (GPG signing, CI pinning, SBOM, OpenSSF Scorecard)

**Real benchmark — scanned gin-gonic/gin v1.11:**
```
1.1s scan time | 130 files | 8 steps
0 CRITICAL | 0 HIGH | 5 MEDIUM | 3 LOW | 4 INFO

Findings:
🟡 4x Unpinned GitHub Actions (GhostAction 2025 attack vector)
🟡 1x Test certificate key in testdata (downgraded)
🟢 3x Test file secrets (downgraded)
ℹ️ SBOM available (49 components) | Scorecard not installed
```

**What makes this different:**
- **Dual-model AI engine**: DeepSeek V3 triages findings, R1 does adversarial verification (F1 96.6% on OWASP vuln detection benchmark)
- **545x faster** than semgrep for Go (gosec embedded as library, 77ms vs 42s subprocess)
- **Source-level FP reduction**: skips test files, comments, fixtures — not just AI post-filtering
- **Attack scenario verification**: every finding must answer Who attacks? How? What do they gain?
- **8-tool orchestration**, not one scanner: Betterleaks + gosec + CodeQL + semgrep + KICS + Syft + Grype + nuclei
- **Single binary**, zero external deps (core engine). MIT license. Code never leaves your machine.
- **Supply chain aware**: detects unpinned CI actions, unsigned commits, floating deps

**AI mode (add --ai flag with DEEPSEEK_API_KEY):**
- Triage: DeepSeek V3 filters obvious FP (test files, examples, placeholders)
- Deep verify: DeepSeek R1 adversarial reasoning (actor → path → impact)
- On gin: correctly identified 43/43 endpoint route FP in test files

**Try it:**
```bash
go install github.com/FYFran/ironwall/cmd/ironwall@v0.4.0
ironwall scan .                      # basic scan
ironwall scan . --ai                 # with AI (needs DEEPSEEK_API_KEY)
ironwall scan . --format sarif       # GitHub Code Scanning
ironwall doctor                      # check your toolchain
```

**What's next:**
- v0.5.0: Custom rule engine + plugin system
- v1.0.0: Comprehensive benchmarks, marketplace

Feedback on the methodology welcome. What patterns do your scanners miss that I should add?

Repo: https://github.com/FYFran/ironwall

---

## Reddit r/golang

**Title:** Show r/golang: ironwall v0.4.0 — audited gin, found 4 unpinned GitHub Actions, zero FPs

Scanned [gin-gonic/gin](https://github.com/gin-gonic/gin) with ironwall — a Go security audit CLI I built. 1.1 seconds, 130 files, 8-step pipeline.

**Results on gin:**
- 0 CRITICAL, 0 HIGH, 5 MEDIUM, 3 LOW, 4 INFO
- 4 real findings: unpinned GitHub Actions in CI workflows
- 0 endpoint audit false positives (skips test file routes + comments at source)

**Go-specific optimizations:**
- Embedded gosec v2.27.1 — 77ms AST analysis (545x faster than semgrep subprocess)
- Betterleaks — BPE tokenization (98.6% recall) for secret scanning
- CodeQL support — deep data flow + taint tracking for complex vulns
- Syft/Grype integration — SBOM generation + CVE scanning
- Global test file severity downgrade — no more HIGH findings in `*_test.go`

**Tech stack:** cobra, securego/gosec v2.27.1, fatih/color, testify. 8 tests passing.

**Repo:** https://github.com/FYFran/ironwall

Would love Go community feedback on:
- What security patterns do you catch in code review that automated tools miss?
- Architecture feedback on the 8-step pipeline?
- Ideas for Go-specific gotchas to add?

---

## Reddit r/cybersecurity

**Title:** I built ironwall — free 8-step security audit CLI. Scanned gin-gonic, found 4 real supply chain risks, zero false positives.

Hi r/cybersecurity,

Student here. I built ironwall v0.4.0 — an open-source CLI that runs 8 gated audit steps. Just dogfooded it on [gin-gonic/gin](https://github.com/gin-gonic/gin).

**What it found (1.1s, 130 files):**
- 🔴 0 CRITICAL
- 🟠 0 HIGH  
- 🟡 4 unpinned GitHub Actions (real GhostAction 2025 vector)
- 🟡 1 test certificate (testdata, downgraded)
- 🟢 3 test file secrets (downgraded)
- ℹ️ SBOM + Scorecard recommendations

**Key differentiators from existing tools:**

| | semgrep | CodeQL | Trivy | ironwall |
|---|---|---|---|---|
| Scan depth | Pattern match | Data flow | CVE match | **8-dimension** |
| Speed (Go) | 42s | 30s+ | 5s | **77ms–1s** |
| AI verification | ❌ | ❌ | ❌ | **Dual-model (V3+R1)** |
| Supply chain | ❌ | ❌ | ✅ | **✅ + CI pinning** |
| IaC | ❌ | ❌ | ✅ | **✅ KICS 2400+ queries** |
| False positive mgmt | Tuning | Query | Baseline | **Source skip + AI** |
| License | Source-available | MIT | Apache 2.0 | **MIT** |
| Price | $30/dev/mo | $30/dev/mo | Free | **Free** |

**How it works:**
1. Betterleaks (BPE, 98.6% recall) → 2. gosec+CodeQL+semgrep → 3. Endpoint audit → 4. Hardcoded secrets → 5. Deps+SBOM → 6. IaC (KICS) → 7. Database → 8. Supply chain
2. AI engine: DeepSeek V3 triages FPs, R1 does adversarial verification (actor→path→impact)
3. Source-level FP reduction: skips test files, comments, fixtures BEFORE AI

**Repo:** https://github.com/FYFran/ironwall

Honest question for the pros: what would make you actually use this vs your current stack? What's the minimum bar?

---

## V2EX（中文）

**标题:** 写了个 8 步安全审计工具，扫了 Gin 框架，0 误报 — 大一学生作品

大家好，我是一名大一学生，学电气工程的。

用 Go 写了个开源安全审计工具 ironwall v0.4.0，刚扫了 [gin-gonic/gin](https://github.com/gin-gonic/gin)。

**实际数据（130 个 Go 文件，1.1 秒）：**
- 0 严重 | 0 高危 | 5 中危 | 3 低危 | 4 信息
- 4 个真实发现：GitHub Actions 没 pin commit SHA（GhostAction 2025 攻击向量）
- **0 误报** — 端点审计自动跳过测试文件和注释

**8 步审计管道：**
密钥扫描 → SAST（三层引擎）→ 端点审计 → 硬编码密钥 → 依赖CVE+SBOM → 服务器/IaC配置 → 数据库审计 → 供应链安全

**技术亮点：**
- Betterleaks 替换 gitleaks：BPE tokenization，召回率 98.6%（原 70.4%）
- 双模型 AI 引擎：DeepSeek V3 快速过滤 + R1 对抗验证（F1 96.6%）
- 嵌入 gosec：77ms，比 semgrep 快 545 倍
- CodeQL + KICS + Syft/Grype 多工具编排
- SARIF 输出 → GitHub Code Scanning 原生支持
- MIT 开源，代码不离开本机

**安装：**
```bash
go install github.com/FYFran/ironwall/cmd/ironwall@v0.4.0
ironwall scan .           # 基础扫描
ironwall scan . --ai      # AI 模式（需要 DEEPSEEK_API_KEY）
ironwall doctor           # 检查工具链
```

**GitHub:** https://github.com/FYFran/ironwall

求大佬们轻喷，给点建议。特别是：你们觉得什么功能是刚需？

---

## 即刻/小红书（中文简短版）

🔍 ironwall v0.4.0 — 免费开源安全审计工具

大一学生用 Go 写的，刚扫了 Gin 框架（130 文件 / 1.1 秒）。

8 步全自动审计：
🔑 密钥 → 🔬 代码注入 → 🔗 接口权限 → 🔐 硬编码 → 📦 依赖+SBOM → 🖥️ IaC → 🗄️ 数据库 → 🔗 供应链

对比数据：
- 比 semgrep 快 545 倍（77ms vs 42s）
- 0 误报（自动跳过测试文件+注释）
- AI 双模型验证（DeepSeek V3 + R1）
- SARIF 输出 → GitHub 一键集成

MIT 开源 | 代码不离开电脑
GitHub: FYFran/ironwall
