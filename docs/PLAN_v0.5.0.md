# Ironwall v0.5.0 — 完整执行计划

> 双脑共识通过 | Brain A(皮特) + Brain B(顶级安全ML专家) | 2026-07-09

---

## 目标

| 维度 | 当前(v0.4.1) | 目标(v0.5.0) |
|------|-------------|-------------|
| 检出率 | 31% (11/35) | >70% (25+/35) |
| 报告价值 | "自动扫描列表" | "专家攻击路径分析" |
| 收入 | $0 | 闲鱼99-599/单 |
| 离线可用 | 5个switch-case | Qwen 7B本地或AST规则引擎 |
| GitHub | 无demo | 案例+README+Docker快速体验 |

## 核心设计决策

1. **Agent是核心引擎，不是附加层。** 当前Engine.Analyze()是空壳，重写为真正的AI推理。
2. **移植GoldHunter到Go。** GoldHunter(517行Python)已验证AI验证逻辑，翻译+升级。
3. **砍掉Attacker LLM对抗。** LLM验证LLM = 自洽偏差。改为规则检查证据充分性。
4. **先出报告再磨引擎。** Day 2就有可交付物(报告模板)，不是等到最后。
5. **必须先建验证集。** 没有ground truth就没有量化优化。GEPA核心教训。

---

## 模块架构

```
                    ┌─────────────────────────┐
 传统工具             │  Ironwall Agent Engine   │         输出
 gitleaks ───┐       │                          │
 semgrep ────┤       │  context_provider.go     │    report_builder.go
 gosec ──────┤       │  · Go AST (go/parser)    │    · 6段式模板
 kics ───────┤       │  · Python AST (脚本)     │    · Severity分层
             ├───────┤  · 文件读取(其他语言)     │    · 攻击路径叙事
             │       │                          │
             │       │  analyst.go              │
             │       │  · 4步推理(OBSERVE→      │
             │       │    TRACE→VERIFY→ASSESS)  │
             │       │  · GoldHunter prompt移植  │
             │       │                          │
             │       │  verifier.go             │
             │       │  · API key验证            │
             │       │  · AST可达性确认          │
             │       │                          │
             │       │  offline.go              │
             │       │  · Ollama Qwen 7B        │
             │       │  · AST规则引擎             │
             └───────┴──────────────────────────┘
```

---

## 8天执行计划

### Day 1 — 验证集 + 报告模板框架 [2026-07-10]

**上午：建最小验证集**
- [ ] 从vulnbench选10个最有代表性的finding
- [ ] 每个手工标注: is_exploitable, attack_steps, cvss, fix
- [ ] 存为 `testdata/agent_bench/golden.json`
- [ ] 写 `agent/agent_test.go` — 用mock LLM client验证Agent输出格式

**下午：报告模板框架**
- [ ] 建 `agent/report_builder.go` — 接口+数据结构
- [ ] 实现6段式markdown模板(Summary/Narrative/Evidence/AttackPath/Verification/Fix)
- [ ] 输入: AnalystResult → 输出: markdown string
- [ ] 手写第一份案例报告(用vulnbench的CRITICAL finding)

**交付物**：golden.json(10样本) + report_builder.go + 1份案例报告

---

### Day 2 — 报告模板完成 + 闲鱼更新 [2026-07-11]

**上午：报告模板完善**
- [ ] Severity分层输出: CRITICAL→6段, HIGH→4段, MEDIUM→1段+fix
- [ ] 集成到Ironwall `--format agent-report` 输出选项
- [ ] 用GoldHunter手动跑3个真实项目，生成3份案例报告

**下午：闲鱼**
- [ ] 更新闲鱼商品: 标题+描述+案例截图
- [ ] 挂"免费审计前3个项目"引流

**交付物**：`--format agent-report` 可用 + 闲鱼案例更新 + 3份真实案例

---

### Day 3 — ContextProvider: Go实现 [2026-07-12]

**全天：**
- [ ] `agent/context_provider.go` — ContextProvider接口
- [ ] `agent/context_go.go` — Go语言实现
  - `go/parser.ParseFile()` 解析AST
  - 提取: 所属函数(full body) + imports + 变量定义
  - 查找: finding行所在的函数/方法
- [ ] 单元测试: 用vulnbench/crypto.go验证

**交付物**：GoContextProvider 完成 + 测试通过

---

### Day 4 — ContextProvider: Python + 通用 [2026-07-13]

**上午：Python**
- [ ] 写 `testdata/agent_bench/extract_ast.py` — Python AST提取脚本
  - 用 `ast` 模块解析Python文件
  - 输出: 函数签名 + 函数体 + imports + 变量定义 (JSON)
- [ ] `agent/context_python.go` — 调脚本收集上下文

**下午：通用实现**
- [ ] 非Go/Python文件: 直接读取文件，找finding行附近前后找到最近的函数/块边界
- [ ] 配置文件关联: 同目录下.env/config.yaml/secrets.json推测+读取
- [ ] 集成测试

**交付物**：PythonContextProvider + 通用ContextProvider + 集成测试

---

### Day 5 — Analyst Agent移植 [2026-07-14]

**全天：从GoldHunter移植AI分析逻辑**
- [ ] `agent/analyst.go` — Analyst Agent
  - 移植GoldHunter `ai_verify_finding()` 的prompt结构
  - OBSERVE→TRACE→VERIFY→ASSESS 4步推理
  - 每个步骤有明确的JSON输出schema
  - 证据链引用具体文件名+行号
- [ ] `agent/client.go` — 更新HTTP client
  - 移植GoldHunter `parse_ai_json()` 的3层JSON容错
  - Go风格错误处理(network/API/JSON分级)
- [ ] 单元测试: 用mock client

**交付物**：Analyst Agent + 3层JSON容错 + 测试

---

### Day 6 — Analyst Agent + Engine集成 [2026-07-15]

**上午：Analyst完成**
- [ ] ContextProvider → Analyst: 上下文传入prompt
- [ ] Analyst → Verifier: 输出传给验证层
- [ ] 批量处理优化: 同类型finding合并为一次API调用

**下午：Engine集成**
- [ ] 重写 `agent/engine.go` — 替换空壳
  - 保留 `Engine.Analyze(ctx, findings) []Finding` 接口不变
  - 内部: Orchestrator(简化规则版)→Analyst→Verifier→ReportBuilder
- [ ] 接入Ironwall scan命令的pipeline
- [ ] 回归测试: 所有现有测试继续通过

**交付物**：Agent Engine集成到Ironwall + 回归测试通过

---

### Day 7 — Verifier + 离线降级 [2026-07-16]

**上午：Verifier**
- [ ] `agent/verifier.go` — 秘密验证
  - GitHub PAT验证 (GET /user)
  - Stripe key验证 (GET /v1/balance)
  - Slack webhook验证 (POST check)
  - 超时5秒，失败不阻塞
- [ ] AST可达性确认: 基于ContextProvider的AST分析判断source→sink是否可达

**下午：离线降级**
- [ ] `agent/offline.go` — Ollama集成
  - 检测Ollama + Qwen 2.5 Coder 7B
  - 调 `/api/generate` 做基础推理
- [ ] AST规则引擎: 纯Go实现的规则分析(数据结构流+危险函数检测)
  - 比GoldHunter的heuristic_verify强10倍(基于AST，不是category白名单)

**交付物**：Verifier + OfflineEngine + 降级测试

---

### Day 8 — 验证集跑分 + Buffer [2026-07-17]

**上午：验证集跑分**
- [ ] 在golden.json 10样本上跑完整Agent Engine
- [ ] 计算: precision(确认的漏洞有多少是真), recall(真漏洞有多少被确认), F1
- [ ] 记录基线分数到 `testdata/agent_bench/BASELINE.md`

**下午：Buffer**
- [ ] 如果时间充裕: Attacker Agent(规则版) — 检查Analyst输出证据充分性
- [ ] 如果时间不够: 打磨报告模板 + 多跑几个真实案例
- [ ] GitHub push + tag v0.5.0-alpha

**交付物**：基线分数 + v0.5.0-alpha tag

---

## 文件结构（变更后的）

```
internal/agent/
├── engine.go              # 重写 — Agent引擎核心
├── analyst.go             # 新建 — Analyst Agent (GoldHunter移植)
├── context_provider.go    # 新建 — ContextProvider接口+通用实现
├── context_go.go          # 新建 — Go AST上下文
├── context_python.go      # 新建 — Python AST上下文
├── verifier.go            # 新建 — 秘密验证+可达性确认
├── offline.go             # 新建 — Ollama+AST规则引擎
├── report_builder.go      # 新建 — 6段式报告生成
├── client.go              # 已有 — HTTP客户端(更新JSON容错)
├── prompts.go             # 新建 — Prompt模板(从GoldHunter提取)

testdata/
├── vulnbench/             # 已有 — 7文件35漏洞测试集
└── agent_bench/
    ├── golden.json        # 新建 — 10样本标注验证集
    ├── BASELINE.md        # 新建 — 基线分数
    └── extract_ast.py     # 新建 — Python AST提取脚本
```

---

## 风险清单

| # | 风险 | 概率 | 缓解 |
|---|------|------|------|
| R1 | Go go/parser不支持CGO等特殊语法 | 低 | Go标准库覆盖率>99%, fallback文件读取 |
| R2 | Python AST脚本跨平台兼容 | 中 | 纯标准库ast, Win/Linux/Mac分别测试 |
| R3 | DeepSeek API JSON输出不稳定 | 高 | 3层容错: json.Unmarshal→regex提取→逐行重试 |
| R4 | API限流 | 中 | 批量合并finding, 串行调用, 如果429自动退避 |
| R5 | 离线Qwen 7B内存不够 | 中 | Q4量化版~4GB; 8GB机器可跑; 最终降级到AST规则 |
| R6 | 8天不够 | 中 | P0模块优先; Attacker可砍; 离线引擎可简化 |

---

## 成功判定

| 指标 | 当前 | 目标 | 测量 |
|------|------|------|------|
| vulnbench检出率 | 31% | >70% | 7文件测试集 |
| Agent报告有attack_path | 0% | 100%(CRITICAL) | 人工抽检 |
| golden.json F1 | N/A | >0.7 | Agent vs 人工标注 |
| 闲鱼收入 | $0 | >¥200 | 平台记录 |
| 离线可用 | 5 switch-case | AST规则引擎>heuristic | 断网测试 |
