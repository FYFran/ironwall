# Ironwall v0.5.0 — AI Agent Engine 设计文档

> ⚠️ **状态: 未实现 (PLAN ONLY).** 本文档描述 v0.5.0 的计划架构。当前代码 (v0.7.0) 中 OBSERVE→TRACE→VERIFY→ASSESS 四阶段、攻击路径生成、上下文采集、本地LLM支持均为零行代码。现有 AI 引擎是单阶段 DeepVerify prompt 调用，仅做 finding 真伪判断。
>
> 双脑对抗验证通过 | 2026-07-09 | Brain A(皮特架构师) + Brain B(顶级安全ML专家)

---

## 1. 设计目标

| # | 目标 | 判定标准 |
|---|------|---------|
| G1 | Agent是核心推理引擎，不是可选附加层 | 关闭API key时能降级运行，但默认开启Agent推理 |
| G2 | 检出率达到竞品水平 | 测试项目检出率 >70%（当前31%） |
| G3 | 输出对客户有10倍价值 | 从"漏洞列表"升级为"攻击路径+验证+修复方案" |
| G4 | 月底前可交付 | 2026-07-31前代码完成+测试通过 |
| G5 | 离线可运行 | 无API key时使用本地模型或AST引擎，不退化到空壳 |

---

## 2. 核心架构

```
                          ┌──────────────────────┐
  传统工具(数据源)          │   AI Agent Engine    │          输出
                          │                      │
  gitleaks ─┐             │  ┌────────────────┐  │    ┌──────────┐
  semgrep ──┤             │  │  Orchestrator   │  │    │ 6段式报告 │
  gosec ────┼─ findings ──┼─→│  · 校准severity │──┼───→│ · Summary│
  kics ─────┤     ↓       │  │  · 合并去重     │  │    │ · Attack │
  syft ─────┘     │       │  │  · 优先级排序   │  │    │ · Fix   │
                  │       │  └───────┬────────┘  │    └──────────┘
                  │       │          │分级       │
                  │       │    ┌─────┼─────┐     │
                  │       │    ▼     ▼     ▼     │
                  │       │ CRITICAL HIGH  MEDIUM│
                  │       │    │     │     │     │
                  │       │    ▼     ▼     ▼     │
                  │       │ ┌──────────────┐     │
                  │       │ │ContextProvider│     │
                  │       │ │· AST解析     │     │
                  │       │ │· 文件读取    │     │
                  │       │ │· 配置关联    │     │
                  │       │ └──────┬───────┘     │
                  │       │        │上下文        │
                  │       │        ▼             │
                  │       │ ┌──────────────┐     │
                  │       │ │   Analyst     │     │
                  │       │ │· 代码意图理解 │     │
                  │       │ │· 数据流追踪   │     │
                  │       │ │· 可利用性判断 │     │
                  │       │ └──────┬───────┘     │
                  │       │        │Analyst输出  │
                  │       │        ▼             │
                  │       │ ┌──────────────┐     │
                  │       │ │   Attacker    │     │
                  │       │ │· 对抗验证     │  ←仅CRITICAL
                  │       │ │· 推翻/确认    │     │
                  │       │ └──────┬───────┘     │
                  │       │        │             │
                  │       │        ▼             │
                  │       │ ┌──────────────┐     │
                  │       │ │   Verifier    │     │
                  │       │ │· API key验证  │     │
                  │       │ │· 可达性确认   │     │
                  │       │ └──────────────┘     │
                  └──────────────────────┘
```

**数据流**：传统工具产生finding → Orchestrator分拣 → ContextProvider采集上下文 → Analyst推理 → Attacker验证(仅CRITICAL) → Verifier确认 → 6段式报告

---

## 3. 模块设计

### 3.1 Orchestrator (`agent/orchestrator.go`)

**职责**：finding预处理，决定哪些进入Agent推理

```
输入: []report.Finding (全量finding)
输出: AnalysisPlan {priority_findings, merged_groups, skipped}
```

**核心逻辑**：

```go
type Orchestrator struct {
    client *Client // 轻量LLM client（便宜模型）
}

type AnalysisPlan struct {
    PriorityFindings []PrioritizedFinding // 需Agent推理的finding
    MergedGroups     []MergedGroup        // 同文件同类型合并
    SkippedCount     int                  // 跳过的低危finding
}

type PrioritizedFinding struct {
    Finding        report.Finding
    AgentLevel     AgentLevel // full | basic | skip
    CalibratedSev  report.Severity // Agent校准后的severity
    CalibrationReason string
}

func (o *Orchestrator) Plan(ctx context.Context, findings []report.Finding) (*AnalysisPlan, error) {
    // 1. 按severity+文件+类型分组
    // 2. 同组finding合并（同文件相邻行的同类型finding → 1个分析单元）
    // 3. 批量调LLM校准severity（一次API调处理整批，不是逐条处理）
    // 4. 分配AgentLevel: CRITICAL→full, HIGH→basic, MEDIUM→basic(仅前20), LOW→skip
    // 5. 返回AnalysisPlan
}
```

### 3.2 ContextProvider (`agent/context_provider.go`)

**职责**：为Agent收集分析所需的代码上下文，不依赖外部索引

```go
type AnalysisContext struct {
    Finding          report.Finding
    SurroundingLines []CodeLine  // 前后30行
    FunctionBody     string      // finding所在函数的完整函数体
    FunctionSignature string     // 函数签名
    FileImports      []string    // 当前文件的所有import/include
    VariableDefs     []VarDef    // 相关变量定义
    RelatedConfigs   map[string]string // 推测的相关配置文件内容
    CallChain        []CallRef   // 函数调用链（如果可解析）
}

type ContextProvider interface {
    Gather(ctx context.Context, f report.Finding) (*AnalysisContext, error)
    SupportedLanguages() []string
}

// Go实现：用go/parser+go/ast原生解析
type GoContextProvider struct{}

// Python实现：调python脚本提取AST
type PythonContextProvider struct{}
```

**实现策略**：
- **Go文件**：`go/parser.ParseFile()` 原生AST，零外部依赖
- **Python文件**：`exec.Command("python", "extract_ast.py", file, line)` 调脚本提取
- **其他文件**：直接读取文件，返回前后30行（最小上下文）
- **配置文件关联**：按命名推测（同目录下.env/config.yaml/secrets.json），读取内容

### 3.3 Analyst Agent (`agent/analyst.go`)

**职责**：核心推理——理解代码意图、追踪数据流、判断漏洞真实性

```go
type Analyst struct {
    client *Client // 主力LLM client (DeepSeek V3 / deepseek-chat)
}

type AnalystResult struct {
    Observation       string        // 代码意图理解
    DataFlow          DataFlowTrace // 数据流追踪
    IsExploitable     bool
    ExploitPrerequisites []string
    ImpactAssessment  string
    Confidence        Confidence    // high | medium | low
    Evidence          []EvidenceRef
}

type DataFlowTrace struct {
    Sources    []string // 数据来源（用户输入/环境变量/配置文件/外部API）
    Transforms []string // 中间变换（字符串拼接/编码/过滤函数）
    Sinks      []string // 危险函数（SQL执行/命令执行/文件操作/网络请求）
    IsReachable bool    // 来源到sink的路径是否可达
}
```

**Prompt策略**（见第4节）

### 3.4 Attacker Agent (`agent/attacker.go`)

**职责**：对抗验证——尝试推翻Analyst的结论。只在CRITICAL finding上运行。

```go
type Attacker struct {
    client *Client // 推理LLM client
}

type AttackerResult struct {
    AnalystConfirmed   bool   // 同意Analyst？
    AttackPath         []AttackStep
    DefenseBypass      string // 如何绕过防御
    AlternativeExploit string // Analyst没发现的替代攻击路径
    Confidence         Confidence
}

// 核心逻辑：如果Attacker说"同意Analyst，漏洞确实可利用"→ 高可信度
// 如果Attacker说"不同意，因为XX防御"→ 降低severity或标记为争议
// 如果Attacker发现新攻击路径→ 合并到最终报告
```

**为什么需要Attacker**：
- 单Agent容易产生确认偏误（看得越多越觉得是漏洞）
- 对抗视角强制LLM从另一个方向思考
- Code-Augur论文的核心机制就是reason→falsify循环
- 如果两个Agent都确认→漏洞极可能是真的

### 3.5 Verifier (`agent/verifier.go`)

**职责**：确定性验证，不依赖LLM判断

```go
type Verifier struct{}

type VerificationResult struct {
    Type    string // api_key | config_check | reachability
    Status  string // verified_valid | verified_invalid | unverifiable
    Evidence string
}

func (v *Verifier) VerifySecret(finding report.Finding) (*VerificationResult, error) {
    // 根据finding的category确定平台：
    // github-pat → GitHub API /user
    // stripe-key → Stripe API /v1/balance  
    // slack-webhook → POST到webhook URL（检查返回码）
    // aws-key → AWS STS GetCallerIdentity
    // 通用 → 尝试HTTP请求（带超时5s）
}

func (v *Verifier) VerifyReachability(finding report.Finding, ctx *AnalysisContext) (*VerificationResult, error) {
    // 不是真的发动攻击，而是静态确认数据路径
    // 基于Analyst.DataFlowTrace的结果
    // 如果Source→Sink路径完整且无过滤函数 → confirmed_reachable
    // 如果路径中存在过滤 → potentially_blocked
    // 如果路径不完整 → cannot_determine
}
```

### 3.6 离线降级 (`agent/offline.go`)

**三层降级策略**：

```go
type OfflineEngine struct {
    useLocalModel   bool   // 是否使用Ollama本地模型
    useASTRules     bool   // 是否使用AST规则引擎
}

func NewOfflineEngine() *OfflineEngine {
    // 优先级：
    // 1. 检测Ollama + Qwen 2.5 Coder 7B可用 → useLocalModel=true
    // 2. 否则 → useASTRules=true
}

// 本地模型推理（通过Ollama API）
func (e *OfflineEngine) AnalyzeWithLocalModel(ctx context.Context, f report.Finding, actx *AnalysisContext) (*AnalystResult, error) {
    // 调用 Ollama API: http://localhost:11434/api/generate
    // 模型: qwen2.5-coder:7b-instruct-q4_K_M (~4GB)
    // 速度: 2-5秒/finding (CPU)
}

// AST规则引擎（纯Go，零外部依赖）
func (e *OfflineEngine) AnalyzeWithRules(f report.Finding, actx *AnalysisContext) (*AnalystResult, error) {
    // 基于AST的规则分析：
    // 1. 数据流可达性分析（遍历AST查找source→sink路径）
    // 2. 危险函数调用检测（exec, eval, os.system, sql concatenation）
    // 3. 配置安全评分（TLS版本, 密码复杂度, 权限配置）
    // 不依赖任何外部API，纯静态分析
}
```

---

## 4. Agent Prompt 策略

### 4.1 System Prompt（所有角色共享底座）

```
你是 Ironwall 安全分析引擎 v0.5.0。

核心原则：
1. 只基于提供的代码上下文分析，绝不编造信息
2. 严格区分"确认的事实"和"推测的可能性"——标注来源
3. 每条结论附代码证据（文件名+行号）
4. 证据不足时明确说"证据不足，无法确认"，不自圆其说
5. 输出必须严格遵循指定的JSON格式
6. 使用中文输出分析内容（客户阅读语言），但代码引用保持原文
```

### 4.2 Orchestrator Prompt

```
任务：安全扫描发现的finding列表。你需要做三件事：
1. 校准severity：根据finding的category+代码片段，判断severity是否被低估或高估
2. 合并同类：同文件、同类型、位置相邻的finding合并为一个分析单元
3. 排序：按真实风险排序，不是按原始severity排序

输入：
{findings_json}

输出（严格JSON格式）：
{
  "calibrated_findings": [
    {
      "original_id": "IRON-001",
      "calibrated_severity": "CRITICAL",  // 可能和原始不同
      "calibration_reason": "GitHub PAT with repo+workflow scope, 代码仓库公开",
      "require_deep_analysis": true,
      "merged_ids": ["IRON-001", "IRON-007"]  // 如果合并了其他finding
    }
  ],
  "skipped_count": 15  // 跳过的低危finding数量
}
```

### 4.3 Analyst Prompt

```
你是一个资深应用安全工程师。分析以下安全发现。

Finding信息：
- 标题: {title}
- 文件: {file}:{line}
- 分类: {category}
- 代码片段: {code_snippet}
- 当前severity: {severity}

代码上下文（已自动收集）：
- 所在函数: {function_body}
- 前后代码: {surrounding_lines}
- 文件导入: {imports}
- 相关配置: {related_configs}

请按以下步骤分析：

步骤1 - OBSERVE（观察）：
这段代码的设计意图是什么？它在系统中扮演什么角色？
输出：1-3句话描述这段代码"应该"做什么。

步骤2 - TRACE（追踪）：
追踪finding中涉及的数据/变量：
- SOURCE（来源）: 数据从哪里来？（用户输入？环境变量？硬编码？）
- TRANSFORM（变换）: 数据经过了什么处理？（拼接？编码？无处理？）
- SINK（汇点）: 数据最终去了哪里？（数据库？网络？日志？文件？）
输出：完整的 source → transform → sink 路径，每步标注文件名+行号。

步骤3 - VERIFY（验证）：
基于以上分析，这个漏洞是真实的吗？
- 是：什么条件允许攻击者利用它？
- 否：什么机制阻止了利用？
- 不确定：缺少什么信息？

步骤4 - ASSESS（评估）：
如果可利用：
- 影响范围：单个用户？整个系统？所有客户数据？
- 攻击难度：需要什么权限？是否需要用户交互？
- 数据敏感度：涉及什么类型的数据？

输出（严格JSON格式）：
{
  "observation": "...",
  "data_flow": {
    "sources": [{"location": "file:line", "description": "..."}],
    "transforms": [{"location": "file:line", "description": "..."}],
    "sinks": [{"location": "file:line", "description": "..."}],
    "is_reachable": true
  },
  "is_exploitable": true,
  "exploit_prerequisites": ["需要代码仓库读取权限"],
  "impact_assessment": "攻击者可访问所有私有仓库并修改代码",
  "confidence": "high",
  "evidence": [
    {"file": "secrets.py", "line": 7, "description": "GitHub PAT硬编码在源码中"}
  ]
}
```

### 4.4 Attacker Prompt

```
你是一名渗透测试专家。你的任务是挑战安全分析师的结论。

分析师对以下finding的分析结果：
{analyst_result_json}

你的任务——**尝试推翻分析师**：

1. 攻击路径检验：分析师说的攻击路径中，每一步是否真的可行？
   哪一步最可能失败？

2. 防御机制搜索：有哪些防御措施可能阻止这个攻击？
   - 网络层：防火墙/WAF/内网隔离
   - 应用层：输入验证/输出编码/认证鉴权
   - 配置层：最小权限/密钥过期/IP白名单

3. 替代攻击路径：如果分析师的路径不对，有没有其他攻击方式？

4. 最终判断：
   - CONFIRM: 同意分析师，漏洞确实存在且可利用
   - DISPUTE: 不同意，因为[具体理由]
   - UNDECIDED: 信息不足，需要人工判断

输出（严格JSON格式）：
{
  "verdict": "CONFIRM|DISPUTE|UNDECIDED",
  "attack_path": [
    {"step": 1, "action": "...", "precondition": "...", "feasibility": "high|medium|low"}
  ],
  "defense_bypass_analysis": "...",
  "alternative_exploit": "..." or null,
  "confidence": "high|medium|low",
  "final_recommendation": "立即修复|尽快修复|按计划修复|无需修复"
}
```

---

## 5. 分级处理策略

| Severity | Orchestrator | ContextProvider | Analyst | Attacker | Verifier | 报告输出 |
|----------|-------------|-----------------|---------|----------|----------|---------|
| **CRITICAL** | ✅ 校准 | ✅ 完整上下文 | ✅ 全4步 | ✅ 对抗验证 | ✅ 秘密验证 | 完整6段 |
| **HIGH** | ✅ 校准 | ✅ 局部上下文 | ✅ 全4步 | ❌ | ✅ 秘密验证 | 4段(简化) |
| **MEDIUM** | ✅ 仅合并 | ✅ 最小上下文(前后30行) | ✅ 简化(跳过TRACE) | ❌ | ❌ | 1段+fix |
| **LOW/INFO** | ✅ 计数 | ❌ | ❌ | ❌ | ❌ | 列表统计 |

**批量优化**：Orchestrator阶段对所有finding做**一次API调用**完成校准和合并，不做逐条调用。

---

## 6. 输出报告结构

### 6.1 6段式CRITICAL报告

```markdown
## 🔴 CRITICAL: Stripe Live Secret Key 泄露

### 📋 摘要
生产环境Stripe live密钥硬编码在配置文件中。攻击者可发起任意金额扣款。

### 📖 漏洞叙事
`config/payment.yaml`第7行的`sk_live_xxx`是Stripe生产环境密钥。
该密钥具有完全API权限,包括：
- 发起任意金额的Stripe Charge
- 查询所有客户的支付历史（含卡号后4位）
- 修改/取消订阅计划
- 发起退款

任何能读取代码仓库的人（内部员工、第三方外包、通过其他漏洞获取
代码权限的攻击者）都可以提取此密钥并直接调用Stripe API。

### 🔗 证据链
1. `config/payment.yaml:7` — Stripe密钥硬编码在源码中
2. `internal/payment/stripe.go:34` — 使用此密钥初始化Stripe客户端
3. `internal/payment/stripe.go:56-78` — Charge API调用，amount参数来自用户输入
4. 无任何IP白名单或使用量限制配置

### 🎯 攻击路径
[攻击者] → [获取代码仓库权限] → [提取sk_live密钥]
→ [Stripe API: POST /v1/charges] → [客户信用卡被扣款]
→ [Stripe API: GET /v1/customers] → [客户支付信息泄露]

### ✅ 验证结果
- **API密钥验证**: ✅ 密钥当前有效 (已通过Stripe API验证)
- **权限确认**: 具有读写权限 (sk_live_xxx, 非受限密钥)
- **可重复性**: 任何持有此密钥的人均可复现此攻击

### 🔧 修复方案
1. **立即**: 在Stripe Dashboard吊销此密钥 (https://dashboard.stripe.com/apikeys)
2. **今天**: 将密钥迁移到环境变量或KMS
   ```yaml
   # config/payment.yaml — 修改前
   stripe_key: "sk_live_xxx"
   # 修改后
   stripe_key: ${STRIPE_SECRET_KEY}  # 从环境变量读取
   ```
3. **本周**: 审计Stripe API日志，排查过去30天是否有异常调用
```

### 6.2 报告格式对照

| 元素 | 传统SAST | Ironwall Agent |
|------|---------|---------------|
| 漏洞描述 | 1行标题 | 叙事段落+背景 |
| 危害说明 | severity标签 | 具体影响+场景 |
| 证据 | 文件+行号 | 完整数据流路径 |
| 攻击演示 | 无 | 分步攻击链 |
| 验证 | 无 | 密钥验证/可达性确认 |
| 修复 | 1句子 | 分步操作指南+代码示例 |

---

## 7. 文件结构

```
internal/
├── agent/
│   ├── engine.go           # 重写 — Agent引擎核心，替换当前空壳
│   ├── orchestrator.go     # 新建 — Finding分拣+severity校准
│   ├── analyst.go          # 新建 — Analyst Agent推理
│   ├── attacker.go         # 新建 — Attacker Agent对抗验证
│   ├── context_provider.go # 新建 — ContextProvider接口+通用实现
│   ├── context_go.go       # 新建 — Go语言AST上下文收集
│   ├── context_python.go   # 新建 — Python语言AST上下文收集
│   ├── verifier.go         # 新建 — 确定性验证（秘密+可达性）
│   ├── offline.go          # 新建 — Ollama本地模型+AST规则引擎降级
│   ├── prompts.go          # 新建 — 所有Prompt模板
│   ├── client.go           # 已有 — HTTP客户端(保留)
│   └── report_builder.go   # 新建 — 6段式报告构建器
├── report/
│   └── finding.go          # 已有 — 可能需加字段（AttackNarrative等）
```

---

## 8. 开发路线图（2周 sprint）

### Week 1 (7/10-7/14): 核心引擎

| 天 | 模块 | 产出 |
|----|------|------|
| Day 1 | `context_provider.go` + `context_go.go` | Go AST上下文收集器完成 |
| Day 2 | `context_python.go` + `extract_ast.py` | Python AST上下文收集器完成 |
| Day 3 | `prompts.go` + `client.go` 重连 | 4个Prompt模板+LLM客户端验证 |
| Day 4 | `orchestrator.go` | Orchestrator完成，含1次API调校准+合并 |
| Day 5 | `analyst.go` | Analyst完成，4步推理流程跑通 |

### Week 2 (7/15-7/19): 验证+集成

| 天 | 模块 | 产出 |
|----|------|------|
| Day 6 | `attacker.go` | Attacker对抗验证完成 |
| Day 7 | `verifier.go` | 秘密验证(GitHub/Stripe/Slack/AWS) + 可达性确认 |
| Day 8 | `offline.go` | Ollama集成 + AST规则引擎 |
| Day 9 | `report_builder.go` + `engine.go` 集成 | 全部模块接入Engine |
| Day 10 | 回归测试 + 测试项目验证 | 检出率>70%，全测试通过 |

### Week 2 末尾 (7/20-7/21): 打磨

| 天 | 产出 |
|----|------|
| Day 11 | 跑10个真实开源项目，收集案例 |
| Day 12 | GitHub push + README更新 + 闲鱼商品升级 |

---

## 9. 风险和对策

| # | 风险 | 概率 | 影响 | 对策 |
|---|------|------|------|------|
| R1 | LLM JSON输出格式不稳定 | 高 | 中 | 3层容错：json.Unmarshal → regex提取 → 行级重试。已在prompt中强调JSON格式 |
| R2 | DeepSeek API限流/不可用 | 中 | 高 | 自动fallback到Ollama本地模型，再fallback到AST规则引擎 |
| R3 | ContextProvider AST解析太难 | 中 | 中 | Go用标准库go/parser(无难度)；Python用脚本提取(有难度但可控)；其他语言先文件读取 |
| R4 | Agent输出质量无法自动测试 | 高 | 中 | Mock LLM client做回归测试；用固定代码片段验证输出格式；人工抽检 |
| R5 | 月底做不完 | 中 | 高 | CRITICAL路径优先：如果时间不够，先砍Attacker(仅CRITICAL用到)和离线引擎(先用API key方案) |
| R6 | Python AST脚本在不同系统不兼容 | 低 | 中 | 脚本用纯标准库ast模块；Windows/Linux/macOS分别测试 |

---

## 10. 成功判定标准

| 指标 | 当前(v0.4.1) | 目标(v0.5.0) | 测量方式 |
|------|-------------|-------------|---------|
| 测试项目检出率 | 31% (11/35) | >70% (25+/35) | 7文件漏洞测试集 |
| CRITICAL finding有攻击路径 | 0% | 100% | 人工抽检 |
| 报告客户感知价值 | "这是自动扫描" | "这是专家分析" | 盲测反馈 |
| 离线可用性 | 退化到5个switch-case | 本地模型或AST引擎 | 断网测试 |
| API调次数/full scan | 0 | <50 | 监控日志 |

---

## 附录A：否决的设计

| 否决项 | 理由 |
|--------|------|
| 多Agent大框架(5+角色) | 太复杂，月底做不完。单Agent+Attacker够用 |
| 全语言支持 | 不可能2周内覆盖。先Go+Python |
| 自主漏洞发现Agent(不依赖传统工具) | 需要fuzzer+验证基础设施。留给v0.6.0 |
| 基于RAG的漏洞知识库 | 维护成本高，收益不明确。留给v0.7.0 |
| 图形化攻击路径(Mermaid/SVG) | 好看但有风险。先ASCII文本，客户反馈后再加 |
| 实时协作编辑修复方案 | 不是v0.5.0的优先级。先输出静态修复建议 |

## 附录B：双脑对抗记录

本设计经过Brain A(架构师)与Brain B(顶级安全ML专家)共17轮对抗验证。
关键分歧及收敛：
1. 范围(全语言→Go+Python) — B说服A
2. Agent数量(单→双) — B说服A
3. 上下文收集(外部索引→AST自建) — 共识
4. 离线策略(AST引擎做最低保障) — A说服B
5. 输出格式(长度控制+分层) — 共识
6. 与现有代码集成方式(ContextProvider新接口) — B纠正A的错误方向
