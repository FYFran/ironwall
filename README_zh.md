# 🔍 Ironwall（铁壁）— 7步安全审计CLI

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-orange)](https://github.com/FYFran/ironwall/releases)

**开源安全审计CLI工具。7步管道。AI辅助分析。代码永不离开本机。**

> 作者：[王一凡](https://github.com/FYFran) — 泰州学院电气工程大一。通过造工具学安全。

## 🎯 做什么的

对你的代码库跑7步安全审计：

| 步骤 | 名称 | 工具 | 检测什么 |
|------|------|------|---------|
| 1 | 🔑 密钥扫描 | gitleaks | API密钥、Token、硬编码密码 |
| 2 | 🔬 SAST分析 | semgrep + AI | SQL注入、XSS、命令注入 |
| 3 | 🔗 端点审计 | AI | 权限绕过、IDOR、缺失访问控制 |
| 4 | 🔐 硬编码密钥 | AI | gitleaks漏掉的密钥模式 |
| 5 | 📦 依赖CVE | go/npm/pip | 已知依赖漏洞 |
| 6 | 🖥️ 服务器配置 | AI | Nginx、Docker、环境变量问题 |
| 7 | 🗄️ 数据库审计 | AI | 迁移风险、SQL反模式 |

**核心原则：** 所有扫描本地执行。AI分析可选——只发送代码片段到API（用自己的Key）。

## 📦 安装

```bash
go install github.com/FYFran/ironwall/cmd/ironwall@latest
```

要求：
- Go 1.22+
- [gitleaks](https://github.com/gitleaks/gitleaks) — `go install github.com/gitleaks/gitleaks/v8@latest`
- [semgrep](https://semgrep.dev) — `pip install semgrep`（可选，用于Step 2）

## 🚀 快速开始

```bash
# 扫描当前目录
ironwall scan .

# 快速扫描 — 仅密钥检测 (< 30秒)
ironwall quick .

# 生成Markdown报告
ironwall scan . --format markdown

# CI用JSON输出
ironwall scan . --format json --output report.json

# 启用AI辅助分析
export DEEPSEEK_API_KEY="sk-..."
ironwall scan . --ai
```

## 📊 示例输出

```
🔍 ironwall v0.1.0 — 7步安全审计
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:    ./my-app
Duration:  12.3s

  🔑 密钥扫描 (gitleaks) .............. 2 found
  🔬 SAST (semgrep + AI) .............. 5 found
  🔗 端点审计 ........................... 3 found
  🔐 硬编码密钥 ........................ 0 found
  📦 依赖CVE ............................ 1 found
  🖥️  服务器配置 ........................ SKIP
  🗄️  数据库审计 ......................... 2 found

📊 SUMMARY
  🔴 CRITICAL: 1   🟠 HIGH: 5   🟡 MEDIUM: 5   🟢 LOW: 3
  📄 Full report: ./ironwall-report-my-app.md
```

## 🔧 配置

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--format`, `-f` | `terminal` | 输出格式: `terminal`, `markdown`, `json` |
| `--output`, `-o` | 自动 | 输出文件路径 |
| `--quick` | false | 仅快速步骤 (1+4) |
| `--ai` | false | 启用AI分析 |
| `--ai-model` | `deepseek-chat` | AI模型 |
| `--timeout` | 300 | 最大扫描秒数 |
| `-v` | false | 详细输出 |

**环境变量：**
- `IRONWALL_AI_KEY` 或 `DEEPSEEK_API_KEY` — AI API密钥

## 🏗️ 架构

```
ironwall CLI
  ├── Pipeline Engine（顺序步骤执行）
  ├── AI Engine（DeepSeek API — 可选）
  ├── Reporter Engine（terminal / markdown / JSON）
  └── 外部工具（gitleaks, semgrep, govulncheck...）
```

所有外部工具在用户机器上本地运行。AI引擎使用OpenAI兼容接口——支持DeepSeek、OpenAI、Claude或本地Ollama。

## 📖 方法论

铁壁采用**7步门控管道**，灵感来自专业安全审计流程：

1. **门控执行** — Step 1 (gitleaks) 是TIER1。失败则扫描中止。
2. **攻击场景三问** — 每个AI生成的finding必须回答三个问题：
   - Q1: 攻击者需要什么角色/条件？
   - Q2: 具体的攻击路径是什么？
   - Q3: 攻击者能得到什么？
   - 三个问题都有具体答案 → 真漏洞。否则 → 过滤。
3. **Gotchas库** — 扫描器通常漏掉的精选模式。

详见：[docs/methodology.md](docs/methodology.md)

## 🆚 对比

| | strix | PentestMate | **Ironwall** |
|---|---|---|---|
| 模式 | 开源CLI | 闭源SaaS | **开源CLI** |
| 价格 | 免费 | $59/月 | **免费 (MIT)** |
| 方法 | 多Agent渗透 | 扫描为主 | **7步门控 + gotchas** |
| 假阳性 | PoC验证 | 低 | **三问攻击验证** |

## 🗺️ 路线图

- [x] v0.1.0 — 7步管道全部实现
- [ ] v0.2.0 — CI集成 (GitHub Actions, SARIF输出)
- [ ] v0.3.0 — 性能优化 + gotchas扩展
- [ ] v0.4.0 — HTML报告 + 趋势分析
- [ ] v1.0.0 — 稳定API + 向后兼容保证

## 🤝 贡献

欢迎！特别是：
- **Gotchas** — 你的工具漏掉的模式。添加到 `docs/gotchas.md`。
- **测试数据** — 各种语言的漏洞代码样本。
- **语言支持** — 新语言的扫描模块。

## 📄 许可证

MIT © 2026 [FYFran](https://github.com/FYFran)

---

*由 [@FYFran](https://github.com/FYFran) 构建 — 泰州学院大一学生。通过造工具学习安全。*
