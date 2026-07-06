# Ironwall 宣传物料

## Show HN

**Title:** Show HN: Ironwall — 7-step open-source security audit CLI, 545x faster than semgrep

**Body:**

I'm a CS freshman who got frustrated with existing security tools — they're either too slow (semgrep takes 30s+), too noisy (90% false positives), or too expensive.

So I built Ironwall. It runs 7 audit steps against your codebase:

1. Secret scanning (gitleaks)
2. SAST (embedded gosec — Go AST, 77ms vs semgrep 42s)
3. Endpoint audit (auth/access control)
4. Hardcoded secrets (regex + AI)
5. Dependency CVE (govulncheck/npm/pip)
6. Server config (Docker/nginx/env)
7. Database audit (migration risks)

**Key differentiators:**
- 545x faster than semgrep (gosec embedded as Go library, not subprocess)
- Attack scenario verification — every finding must answer: who, how, what?
- Single binary, zero external deps (for Go projects)
- MIT license. Code never leaves your machine.
- Gotchas library: 15+ patterns that scanners miss

**Try it:**
```bash
go install github.com/FYFran/ironwall/cmd/ironwall@v0.2.0
ironwall scan .
ironwall doctor
```

Looking for feedback on the methodology and what patterns your scanners miss that I should add to the gotchas library.

---

## Reddit r/golang

**Title:** Show r/golang: ironwall — 545x faster Go security scanning with embedded gosec

Wanted to share a project that might interest Go devs here.

Ironwall is a 7-step security audit CLI written in Go. The interesting part: instead of shelling out to semgrep, it embeds `securego/gosec` as a Go library. This took scan time from 42s to 77ms.

**Tech stack:**
- cobra + viper (CLI)
- securego/gosec v2.27 (embedded SAST)
- gitleaks (subprocess, still the best for secrets)
- fatih/color (terminal output)
- testify (tests, 10/10 passing)

**Repo:** https://github.com/FYFran/ironwall

Would love feedback from experienced Go devs. Especially interested in:
- What security patterns do you check for in code review that automated tools miss?
- Thoughts on the pipeline architecture?

---

## Reddit r/cybersecurity

**Title:** I built a free 7-step security audit CLI — looking for feedback from security pros

Hi r/cybersecurity,

I'm a student learning security by building tools. I built ironwall — an open-source CLI that runs a 7-step gated audit pipeline against any codebase.

**The methodology:**
1. TIER1 gating — if secret scanning fails, the scan aborts (no partial results)
2. Attack scenario verification — every AI finding must pass three questions (actor, path, impact)
3. Signal attenuation management — severity auto-downgrades for test files, comments, low AI confidence

**Comparison to existing tools:**
- strix (36K stars) does pentesting/exploitation. Ironwall does static audit.
- semgrep does single-dimension scanning. Ironwall does 7-step pipeline.
- Horusec does multi-tool but no methodology depth. Ironwall has gotchas + three-questions.

**Repo:** https://github.com/FYFran/ironwall

Honest question: as security professionals, what would make a tool like this actually useful to you vs just another scanner?

---

## V2EX

**标题:** 写了一个 7 步安全审计 CLI 工具，比 semgrep 快 545 倍

大家好，我是一名大一学生，学电气工程的。

最近写了一个开源安全审计工具 ironwall，Go 写的，单二进制文件，MIT 许可证。

**7 步审计管道：**
密钥扫描 → SAST → 端点审计 → 硬编码密钥 → 依赖CVE → 服务器配置 → 数据库审计

**一些特色：**
- 嵌入 gosec 替换 semgrep，扫描从 42 秒降到 77 毫秒
- 攻击场景三问验证 — 每个漏洞必须回答：谁攻击？怎么攻击？得到什么？
- ironwall doctor 一键检查环境
- 中英文文档
- 代码不离开本机

**安装：**
```bash
go install github.com/FYFran/ironwall/cmd/ironwall@v0.2.0
```

**GitHub:** https://github.com/FYFran/ironwall

刚开源，求大佬们轻喷，给点建议。特别是想知道：你们平时代码审查中最常发现的漏洞类型是什么？

---

## 即刻/小红书（中文简短版）

🔍 写了个免费的安全审计工具 ironwall

大一学生，用 Go 写的。

7 步全自动扫描你的代码：
🔑 密钥 → 🔬 代码注入 → 🔗 接口权限 → 🔐 硬编码 → 📦 依赖漏洞 → 🖥️ 服务器 → 🗄️ 数据库

比 semgrep 快 545 倍（77ms vs 42s）
MIT 开源，代码不离开你的电脑

GitHub: FYFran/ironwall
