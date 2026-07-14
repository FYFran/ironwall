# 新会话启动 — Ironwall v0.7.1

**日期**: 2026-07-13

---

## 启动指令

```
1. MCP pete_recent_diary — 读最新日记
2. MCP pete_recall keyword=ironwall — 查ironwall记忆
3. Read f:/ClaudeFiles/_research/ironwall/docs/NEW_SESSION_START.md (本文件)
4. Read f:/ClaudeFiles/_research/ironwall/docs/DEEP_ANALYSIS_V5.md — 市场分析
5. 查Brain B: curl -s http://localhost:4000/health
6. 调Brain B审查下一步计划
```

## Ironwall v0.7.1 状态

### 核心指标
- GitHub: https://github.com/FYFran/ironwall (14 commits, tag v0.7.1)
- OWASP Benchmark: Recall 62%, semgrep 13% (4.9x)
- 自定义扫描器: 5 CWE (路径遍历/XSS/重定向/LDAP/信任边界)
- 测试集: 74 vulns, 7 projects
- 成本: $0.02-0.03/scan (AI Phase B)

### AI Phase B 验证
- go-vuln-target: 7/7 vulns found (TRACE R=100%)
- campus_go: 11/11 SAST FP suppressed, 1 MISSING found
- rewriter-go: 10/10 SAST FP suppressed, 30 MISSING (too noisy)
- ecommerce-flask: 7 MISSING found, 4/10 GT covered
- secure-file-mgmt: 76% FP suppressed, 10 unique findings

### 已知问题
- FP率: 75% SAST-only, ~24% after AI
- MISSING噪声: rewriter-go 30 findings偏高 (内部API端点不需要CSRF/限流)
- CONFIG: 读不到模块级代码 (只扫handler sections)
- CWE-22: 23% recall (taint引擎需要系统升级)
- GitHub push: 本地网络不通, 通过HK服务器(47.82.103.247)中转。服务器7月14日到期。
- 无IDE集成, 无CI/CD, 无法直接卖给企业

### 诚实定位
- 个人开发者的辅助安全工具
- 不如CodeQL/Snyk/Semgrep Pro
- 唯一独特价值: MISSING检测 (找到SAST检测不到的缺失安全控制)
- 可变现方式: 闲鱼/Fiverr代码审计服务 $15-75/单

## Brain B v3 状态
- 双模型仲裁 (v4-pro + v4-flash + 共识合并)
- Fresh Intel (Tavily搜索+LLM摘要, 5644 chars缓存)
- ReviewDB (SQLite, 2审查11攻击点)
- AutoLearner (WANN评分+隔离+3-confirmation)
- sanity_check (Tier1 regex预检, 4/4 FP拦截)
- 代理: localhost:4000, KB 11,396 chars
- v4-pro thinking bug已修复 (thinking=disabled)

## TokenLine
- 服务器7月14日到期, 已决定不续
- 0真实用户, 0收入 (19个账号全是测试号)
- 数据已备份到 f:/ClaudeFiles/_server-backup/2026-07-12/
- tokenline.db: 19 users, 15 tables
- SSL证书, nginx配置, 运维脚本已拉取

## 下一步讨论
- 铁壁是否值得继续全力投入?
- 要不要先接外包赚钱?
- MISSING检测是真正的新东西, 但天花板低
- 训练专用模型 vs 继续调prompt?
