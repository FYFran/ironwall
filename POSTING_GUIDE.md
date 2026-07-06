# Ironwall v0.4.0 发布清单

## ✅ 已完成
- [x] 代码完成 (6 commits, 31 files)
- [x] All tests pass
- [x] Push to GitHub (FYFran/ironwall)
- [x] PROMO.md 全部更新
- [x] SARIF + CI templates

## 📋 发布步骤

### 1. Show HN (最重要!)
**网址**: https://news.ycombinator.com/submit
**标题**: `Show HN: Ironwall — 8-step security audit CLI. Scanned Gin, found 4 real supply chain risks, 0 FP.`
**URL**: `https://github.com/FYFran/ironwall`
**正文**: 见 PROMO.md "Show HN" 部分

⏰ **最佳时间**: 美东周二/周三 10am = 北京时间 周二/周三 晚上10点
📊 首页需要 ~200 upvotes

### 2. Reddit r/golang
**网址**: https://reddit.com/r/golang/submit
**标题**: `Show r/golang: ironwall v0.4.0 — audited gin, found 4 unpinned GitHub Actions, zero FPs`
**正文**: 见 PROMO.md "Reddit r/golang" 部分

### 3. Reddit r/cybersecurity
**网址**: https://reddit.com/r/cybersecurity/submit
**标题**: `I built ironwall — free 8-step security audit CLI. Scanned gin-gonic, found 4 real supply chain risks, zero false positives.`
**正文**: 见 PROMO.md "Reddit r/cybersecurity" 部分

### 4. V2EX
**网址**: https://www.v2ex.com/new/create
**节点**: 分享创造
**标题**: `写了个 8 步安全审计工具，扫了 Gin 框架，0 误报 — 大一学生作品`
**正文**: 见 PROMO.md "V2EX" 部分

### 5. Fiverr Gig 更新
**网址**: https://www.fiverr.com/ (你的gig)
**更新内容**:
- Title: "I will audit your code with ironwall — 8-step security pipeline, AI-powered verification"
- Description: 加 real gin benchmark data
- 价格: $15-75 (保持)

### 6. 程序员客栈 Profile 更新
- 技术标签加: "安全审计" "SAST" "开源工具ironwall作者"
- 价格提: 500-800/天 (有开源项目背书)
- 项目经历加: ironwall v0.4.0 — 8步安全审计CLI, GitHub FYFran/ironwall

## 📊 关键数据 (宣传用)

```
ironwall v0.4.0 实战数据 (gin-gonic/gin):
- 130 Go files, 1.1s scan time
- 0 CRITICAL, 0 HIGH, 5 MEDIUM, 3 LOW, 4 INFO = 12 total
- 0 false positives
- 4 real GitHub Actions supply chain risks found

对比:
- 比 semgrep 快 545x (77ms vs 42s for Go)
- Betterleaks 召回率 98.6% (vs gitleaks 70.4%)
- AI 引擎: DeepSeek V3 + R1 (F1 96.6% on OWASP benchmark)
- MIT license, single binary, code never leaves machine
```

## 🔗 链接

- GitHub: https://github.com/FYFran/ironwall
- 安装: `go install github.com/FYFran/ironwall/cmd/ironwall@v0.4.0`
