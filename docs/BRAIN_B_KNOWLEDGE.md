# Brain B Knowledge Base — 铁壁 Ironwall

> v4.1 | 2026-07-10 | +Arnica AI SAST +CSA 2026 +竞争缺口分析 | Brain A(皮特) + Brain B(Codex) 联合维护

本文档是铁壁项目的核心知识库。Brain B 每次会话必读。**Proxy启动时自动注入为system prompt。**

---

## 1. SAST 工具格局

### 1.1 核心工具对比

| 工具 | 方法 | 精度 | 召回率 | F1 | 价格 |
|------|------|:---:|:---:|:---:|------|
| **CodeQL** | 关系DB + QL查询, 全程序污点追踪 | 60.3% | 97.0% | 74.4% | 公开仓库免费, 私有$30/committer/mo |
| **Semgrep CE** | AST模式匹配, 文件内 | 56.3% | 90.4% | 69.4% | 免费 |
| **Semgrep Pro** | 跨文件过程间分析 | — | — | — | <10 devs免费, 之后$30/committer/mo |
| **gosec** | Go AST规则引擎 | — | — | — | 免费 |
| **bandit** | Python AST规则引擎 | — | — | — | 免费 |
| **bearer** | 多语言SAST, 隐私/安全规则 | — | — | — | 免费 |

### 1.2 真实世界检测现实 (EASE 2024, Bennett et al.)

- 502个真实Java漏洞, 4个工具:
  - 单个工具检测率: **11.2%–26.5%**
  - 4个工具合并: **38.8%**
  - 加自定义Semgrep规则后: **44.7%** (+181%)
- **76.9%的FN源于缺失规则, 非引擎限制**

### 1.3 2025-2026 关键发展

- **Opengrep fork** (2025.1): 10+厂商在Semgrep CE改许可证后fork
- **CodeQL增量分析** (2025.9): 所有语言支持PR扫描 (快5-40%)
- **CodeQL Rust支持** (2025.7): 公开预览
- **Semgrep Code重写引擎** (2024底): 性能大幅提升
- **GitHub Copilot Autofix** (2024 GA): CodeQL + AI修复建议
- **Semgrep Assistant**: GPT-4驱动triage + 误报过滤
- **Snyk DeepCode AI**: 混合符号执行 + 多模型LLM
- **Snyk AppRisk**: ASPM平台, 2024收购Helios (运行时观测)

### 1.4 开源新星

| 工具 | 语言 | 亮点 |
|------|------|------|
| **ruff** | Python | 2024爆发, 取代flake8, 含基础安全检查 |
| **trivy** | 跨语言 | 容器+依赖+IaC+密钥, 已成标配 |
| **osv-scanner** | 跨语言 | Google OSV数据库前端, Go实现 |
| **zizmor** | GitHub Actions | 2024新星, CI/CD安全审计 |
| **govulncheck** | Go | Go 1.19+官方漏洞扫描 |

---

## 2. 竞争格局 (统一视图)

### 2.1 商业竞品

| 选手 | 核心能力 | 精度 | 召回率 | 差异化 | 弱点 |
|------|---------|:---:|:---:|------|------|
| **Neo** (ProjectDiscovery) | Runtime验证, 多Agent | 93% | 100% crit+high | 构建exploit, 22个CVE (RSAC 2026) | SaaS-only, 企业$$$ |
| **CodeQL** | 数据流深度, 全程序QL | 60% | 97% | AST级污点追踪 | 需构建环境, 非AI原生 |
| **Semgrep** | 速度, 自定义规则 | 56% | 90% | 分钟级规则编写 | 无语义理解 |
| **Snyk Code** | IDE集成, 开发者体验 | — | — | DeepCode AI混合引擎 | 贵, 锁定平台 |
| **Checkmarx** | 企业合规, 全语言 | — | — | 25+语言, Gartner Leader 7年 | 贵, 学习曲线陡 |
| **Corgea** | AI-first triage+自动修复 | — | — | AI推理+代码上下文+可达性 | 商业闭源 |
| **Veracode** | 二进制分析, 合规 | — | — | FedRAMP/SOC2, 30+语言 | 慢, 开发者体验差 |
| **Fortify** | 政府/军工, 审计 | — | — | 30+语言, 完全本地部署, 等保 | 老旧, 贵 |
| **Endor Labs** | 可达性分析降噪 | — | — | 全栈可达性 (代码+依赖+容器) | SaaS |
| **Arnica** | AI SAST多文件污点追踪 | — | — | 跨文件AI taint analysis, 双检测层(规则+AI), 100%覆盖无需pipeline配置 | 商业闭源, SaaS |

### 2.1.1 Arnica深度分析 (2026.7新增)

Arnica是Ironwall最直接的AI SAST竞品:

- **双检测层**: 确定性规则层(已知签名) + AI生成层(代码推理), 两层并行运行
- **多文件AI SAST** (2026.5 GA, 7月扩展): 跨文件/服务边界污点追踪, 解决单文件扫描器天花板
- **AI误报过滤**: 读取漏洞位置→调查相关文件→检查缓解措施→记录推理→标记FP
- **Pipelineless ASPM**: 无需CI/CD集成, Day 1起覆盖所有仓库+所有SCM事件
- **关键差异**: Arnica的AI层reason across codebase, 不依赖预定义规则 — 比Ironwall的MISSING detection更系统化
- **Ironwall优势**: 极低成本(~$0.016/scan vs Arnica企业$$$), 离线OBSERVE, 可定制prompt

**教训**: Arnica的多文件方法验证了Ironwall方向(跨文件上下文是关键), 但也暴露了Ironwall差距(没有全仓库级调用图分析)

### 2.2 免费替代方案 (Ironwall必须证明增量价值)

- GitHub免费安全功能: CodeQL + Dependabot + Secret scanning → 覆盖SAST+SCA+密钥
- Trivy + Semgrep CE + DefectDojo → 免费完整管线
- GitLab SAST (内置, 免费层可用)

### 2.3 中国厂商

| 厂商 | 产品 | 定位 |
|------|------|------|
| **奇安信** | 代码卫士 | 企业SAST, Forrester代表厂商 |
| **默安科技** | 雳鉴 | SAST + IAST |
| **悬镜安全** | 灵脉 | IAST + RASP |
| **华为云** | CodeCheck | DevSecOps集成 |
| **阿里云** | 云效代码安全 | 内置CI/CD |
| **腾讯云** | CODING代码扫描 | 内置平台 |

---

## 3. 中国SAST市场

### 3.1 市场规模

- ~$200M, 25% CAGR (2026-2032预测)
- 政策驱动: 等保2.0、信创、数据安全法
- 三级以上系统要求代码审计能力

### 3.2 关键趋势

1. **AI+SAST军备竞赛** — 各家接大模型做误报过滤/规则生成
2. **信创适配硬门槛** — 必须支持国产CPU/OS/数据库
3. **DevSecOps一体化** — 不再单独卖SAST, CI/CD全链路
4. **SCA增长最快** — 供应链安全受重视
5. **价格战白热化** — 中小企业市场被免费/开源蚕食
6. **Runtime Shift** (CSA 2026) — 组织从shift-left转向runtime security+持续监控+生产防御。已知漏洞+延迟修复仍是事件主因。AI应用增加runtime可见性需求。
7. **多文件AI SAST崛起** (Arnica 2026) — 单文件扫描天花板被打破, AI跨文件污点追踪成为新标准

### 3.3 闲鱼 = 阿里巴巴

- Java/Go技术栈, 海量微服务
- 阿里内部有Aone工程平台, 可能有内置安全门控
- **Ironwall要打入阿里, 必须比内部工具好10倍**

---

## 4. 漏洞基准与指标

### 4.1 标准指标

| 指标 | 公式 | 用途 |
|------|------|------|
| Precision | TP/(TP+FP) | 多少告警是真的 |
| Recall/TPR | TP/(TP+FN) | 多少真漏洞被找到 |
| F1 | 2PR/(P+R) | 平衡度量 |
| **F3** | (10·P·R)/(9·P+R) | **安全优先 (漏报比误报严重9倍)** |
| MCC | Matthews | 类别不平衡下稳健 |
| AI Suppression Rate | TP_killed_by_AI / TP | 灾难性失败指标 |

### 4.2 关键基准数据集

| 基准 | 语言 | 规模 | 状态 |
|------|------|------|------|
| **OWASP Benchmark v1.2** | Java | 2,740用例 | 事实标准 |
| **OWASP Python Benchmark** | Python | 1,000+用例 | 2025.11发布, AppSecAI |
| **RealVuln** | Python | 26仓库, 796标注 | 2026.4, F3排名 |
| **SastBench** | — | Agentic triage专用 | 2026.1 |
| **Snyk VulnBench JS 1.0** | JavaScript | 44参考发现, 300次运行 | 2026.6 |
| **CrossCommitVuln-Bench** | Python | 15个CVE, 跨commit链 | 2026.4, AIware '26 |
| **RealSec-bench** | Java | 105实例, 19 CWE | 2026.7, ACL 2026 |
| **JavaVulBench** | Java | 30,600方法, 1,740 CVE | 2026.7, 污染审计 |
| **RustMizan** | Rust | 可编译, 污染感知 | 2026.7 |

### 4.3 真实 vs 合成

- 合成基准高估工具性能
- 真实CVE上检测率降至11-27%/工具 (Bennett 2024)
- **规则覆盖 > 引擎复杂度** — 76.9% FN = 缺失规则
- CrossCommitVuln-Bench: 逐commit检测率仅13%, 87%的链对SAST不可见

---

## 5. CVE与威胁趋势

### 5.1 体量

- **48,174个新CVE in 2025** — 131/天 (2024: 113/天)
- 320,000+累计CVE by 2025.12
- 38% High/Critical (H1 2025: 1,773 Critical)

### 5.2 利用速度

- **Time-to-exploit: -7天** (漏洞在补丁存在前就被利用)
- 28.3%在披露24小时内武器化
- 中位利用时间: <5天

### 5.3 供应链 — #1担忧

- 4×增长 in 重大供应链攻击 over 5年 (IBM X-Force 2026)
- 2025翻倍: 26事件/月
- OWASP Top 10 2025: "Software Supply Chain Failures" at #3

### 5.4 AI作为攻击向量

- **2,130个AI相关CVE in 2025** (+34.6%)
- AI编码助手生成代码: 45%含漏洞, 62%至少1个可利用
- 首个AI生成的野外零日利用确认 (2026.5)
- Veracode 2026春: **AI代码安全通过率卡在~55%两年**

---

## 6. AI + 安全研究 (2025-2026)

### 6.1 核心论文

| 论文 | 时间 | 关键发现 |
|------|------|---------|
| **ZeroFalse** | 2026 | CodeQL+LLM, CWE特定prompt, F1=0.912 (OWASP), 0.955 (OpenVuln). Grok-4(0.912) > Gemini 2.5(0.910) > GPT-5(0.955) |
| **RealVuln** | 2026.4 | 15扫描器, 26 Python仓库. F3: Kolega.Dev=73.0 > Sonnet 4.6=51.7 > Semgrep=17.7 |
| **SastBench** | 2026.1 | Agentic SAST triage. Gemini 2.5 Acc=0.641, Rec=0.582. Sonnet 4.5 Acc=0.481, Rec=0.722 |
| **FuzzingBrain V2** | 2026.5 | 多Agent, OSS-Fuzz集成. 90%检测 on AIxCC, 41个零日, 26确认, 2 CVE |
| **Revelio** | 2026.6 | Agentic内存安全检测, 可执行PoV. 19个新漏洞 in 7个重度fuzzed项目. ~$300总成本 |
| **Snyk VulnBench JS** | 2026.6 | 300次重复扫描. 最佳LLM F1=75.4% (Opus 4.6 Medium). LLM独有报告50%仅出现1/5次. 贵≠好 (Opus 4.7 Max 5.7×cost, 分更低) |
| **Frame** | 2026 | 神经符号SAST: Z3污点+LLM. F1=0.58 vs Semgrep 0.45 on Endor Labs真实语料. LLM层恢复65个两者都漏的漏洞 |
| **Antaeus** | 2026.7 | 仓库级逻辑漏洞检测 (CWE-200, CWE-284). 上下文扎根LLM推理. 28仓库, 15个漏洞 |
| **LeanGuard** | 2026.7 | 神经符号: LLM语义过滤 + Lean 4形式验证. 5 CWE类 |
| **VIC-RAGENT** | 2026.7 | 多Agent漏洞引入commit检测. F1比基线高1.2-1.7× |
| **Veritas** | 2026.7 (更新) | 剥离二进制漏洞推理. 90%召回, 已验证候选中零FP. 发现Apple CVE |
| **JavaVulBench** | 2026.7 | Java漏洞基准, 30,600方法, 1,740 CVE, 12个检测器, 污染审计 |
| **CrossCommitVuln-Bench** | 2026.4 | 跨commit Python漏洞. 逐commit SAST检测率仅13% |
| **Abliterated LLMs** | 2026.7 | 消融模型补丁验证率67.8% vs 对齐模型29.9%. 拒绝训练损害安全准确性 |
| **RealSec-bench** | 2026.7 | RAG改善功能正确性但安全收益可忽略 (负面结果) |
| **Arnica AI SAST** | 2026.7 | 多文件AI污点追踪, 双检测层(规则+AI推理). 跨文件调用图, 跨服务边界, FP降低通过验证缓解措施. Pipelineless ASPM |

| 方法 | F1 | FPR |
|------|:---:|:---:|
| 传统SAST | 0.10–0.66 | 40-60%+ |
| 独立LLM | 0.61–0.88 | 可变 |
| **混合 (SAST+LLM)** | **0.91–0.99** | **~10-17%** |

- 30个LLM vs OWASP Benchmark v1.2
- Semgrep F1=0.66, Gemini 3 Pro F1=0.88
- Lviv Polytechnic (2026): 混合管线检测率提升2.5×, FP降低达91%

### 6.3 关键工程教训 (Rafter 2026)

- **Agent脚手架 > 模型质量.** GPT-4 raw 15-40% precision → +agent infra 70-85%
- SAST+AI混合 = "最佳实用权衡": 75-90% precision, 50-70% recall
- 架构洞察: 非确定性发现是大问题 — 同一扫描器两次运行得到不同结果

---

## 7. 铁壁架构与定位 (诚实版)

### 7.1 铁壁是什么

> **Ironwall = Multi-SAST Runner + AI降噪 + AI缺失控制检测**

- 一键运行 semgrep + gosec + bandit + gitleaks + syft/grype + KICS
- 跨工具去重 (7.5% precision提升)
- AI过滤误报 (actionable findings上Precision 100%, n=30)
- **AI缺失控制检测 — 发现SAST找不到的漏洞 (GT-008 CWE-306 已验证)**

### 7.2 铁壁不是什么

- ❌ 不是漏洞发现引擎 (Recall受限于底层SAST规则)
- ❌ 不是离线AI方案 (AI要联网, 离线引擎只有9条规则)
- ❌ 不是Neo竞品 (没有runtime验证)
- ❌ 不是CodeQL竞品 (没有全程序数据流分析)

### 7.3 真实差异化

| 独特性 | 证据 |
|--------|------|
| 一键多SAST | semgrep+gosec+bandit+gitleaks+syft+KICS |
| 跨工具去重 | OWASP基准: Precision +7.5%, Recall零损失 |
| AI降噪 | 实战: actionable findings Precision 100% |
| **AI缺失控制检测** | Phase B: GT-008(CWE-306) SAST找不到 |
| 极低成本 | ~$0.016/scan (含Phase B) |
| Go本地OBSERVE | 12安全模式, stdlib only, 零依赖 |

### 7.4 不可替代的场景

> "我想一键跑semgrep+gosec+bandit+gitleaks, 得到去重结果, AI过滤噪音, AI检测缺失控制——免费或几乎免费。"

没有其他工具做这个具体组合。Semgrep/Snyk/CodeQL对AI功能收费。Trivy没有多SAST。Neo是企业$$$。

---

## 8. 阿里巴巴生态系统策略

### 8.1 关键问题

闲鱼 = 阿里巴巴。阿里内部有:
- Aone工程平台 (可能内置安全门控)
- 云效代码安全 (CodeAdmin)
- 自研SAST/SCA方案

**Ironwall必须比阿里内部工具好10倍才有意义。**

### 8.2 可能的切入点

1. **供应链安全** — 阿里开源项目众多, 对外部依赖的可见性可能不足
2. **个人开发者/小团队** — 阿里云效面向企业, 个人开发者可能用免费工具
3. **等保2.0合规** — 离线扫描能力是独特卖点
4. **多语言混合项目** — 阿里内部工具可能偏重Java, Ironwall的Go+Python支持是补充

### 8.3 GitHub免费层是致命竞争

GitHub免费安全功能覆盖: CodeQL + Secret scanning + Dependabot。如果你的目标用户已经在GitHub上, 必须证明增量价值。离线场景对GitHub用户是小众。

---

## 9. 监管与合规

### 9.1 中国

- **等保2.0**: 三级以上系统要求代码审计能力。离线扫描是真实优势
- **信创**: 国产CPU/OS/数据库适配是硬门槛
- **数据安全法/PIPL**: 代码不出境的扫描方案有需求

### 9.2 国际

- PCI DSS: 要求代码审查 (要求6.5)
- SOC 2: 要求变更管理中的安全审查
- HIPAA: 要求技术保障措施
- GDPR: 数据保护影响评估

---

## 10. Phase B 开发历史 (压缩)

### 10.1 Phase B v1: OBSERVE→TRACE→VERIFY

- **OBSERVE**: Go AST解析器, 12安全模式, 纯本地
- **TRACE**: LLM数据流追踪 (input→sink)
- **VERIFY**: 对抗性验证
- **结果**: 找到4个SAST已发现的漏洞, 0独特发现
- **教训**: TRACE prompt问的是"输入到达sink了吗?" — 和gosec taint analysis同一个问题

### 10.2 Phase B v2: 加TraceMissing + TraceConfig

- **TraceMissing**: 检测HTTP handler缺失的安全控制 (认证/验证/限流/CSRF)
- **TraceConfig**: 检测危险配置模式
- **结果**: **找到GT-008 (CWE-306, admin endpoint缺失认证) — SAST永远检测不到**
- SAST recall 78% (7/9) → 89% (8/9) combined
- 成本: $0.0164/scan

### 10.3 Phase B v3: 降噪

- Severity tuning: rate_limiting→LOW, CSRF→LOW
- Smart dedup: 文件+行号 proximity matching
- `--deep-strict` flag: CRITICAL+HIGH only
- **结果: 34→5 actionable findings, zero noise**

### 10.4 Python OBSERVE

- `ast.parse()` via subprocess, 零C依赖
- 5文件→10 sections on secure-file-management
- VERIFY正确拒绝了所有finding (代码有proper sanitization)

### 10.5 Gosec Bug

- 嵌入式 `gosec/v2 v2.27.1` API on Go 1.25: 静默返回0 issues
- 修复: CLI gosec via subprocess `gosec -fmt=json ./...`
- 影响: Step 2对Go项目从0→正常

### 10.6 Brain B审查关键修复

- `safeConcernCategory()` panic guard
- CRLF normalization in code snippets
- Dead import checks (path\"→imp=="path")
- Timeout context wired
- collectPyFiles base-only matching
- gosec filepath.Rel path handling
- Dedup full-path matching (raw string backticks)
- DeepAnalysisResult.Errors field

---

## 11. 基准测试历史 (压缩)

### 11.1 OWASP Python Benchmark (1,230文件)

| 工具 | Strict Recall | Strict F3 | CWE Covered |
|------|:---:|:---:|:---:|
| semgrep alone | 0.126 | 0.127 | 5/14 |
| Ironwall no-AI | 0.372 | 0.339 | 10/14 |
| Ironwall +AI filter | Precision 100% | — | — |

Ironwall多扫描器方法 (semgrep+bandit) Python召回率比单独semgrep高3×。

### 11.2 Go Battle Test (go_target, 12 ground truth)

| 配置 | Recall | 独特发现 | 成本 |
|------|:---:|:---:|:---:|
| SAST only | 78% (7/9) | — | $0 |
| SAST + AI filter | 78% | — | $0.02 |
| SAST + AI + Phase B strict | **89% (8/9)** | **1 (GT-008)** | **$0.016** |

### 11.3 Python Battle Test (secure-file-management, 544行)

- OBSERVE: 5文件→10 sections
- TRACE: 4 traces, VERIFY全部正确拒绝 (代码有proper sanitization)
- MISSING: 20 controls, strict mode→0 actionable (correct — 代码安全)

---

## 12. 已知缺口与路线图

### 12.1 技术缺口

| 缺口 | 最佳 | 优先级 |
|------|------|:--:|
| Python TRACE/MISSING不支持 | — | 🟡 |
| 无运行时验证 | Neo | 🔴 |
| 无全仓库级调用图分析 | Arnica, CodeQL | 🔴 |
| 无跨文件AI污点追踪 | Arnica | 🔴 |
| 无过程间数据流 | CodeQL | 🟢 |
| 离线LLM (Ollama)未实现 | — | 🟡 |
| 无IDE插件 | Snyk, Semgrep | 🟢 |
| 无SCA深度 (仅有syft/grype基础) | Snyk, Endor | 🟢 |
| 无IaC深度 (仅有KICS基础) | Trivy, Checkmarx | 🟢 |
| 大项目未测试 (最大5文件) | — | 🟡 |
| PromptVerify vs DeepVerify逻辑矛盾 | — | 🟡 |
| KB未注入Brain B system prompt | — | ✅ v4.1已修复 |

### 12.2 战略缺口

- 无仪表板/UI (无企业可用性)
- 无合规报告生成
- 无PR评论集成
- 无定价模型

### 12.3 已解决

- ✅ Go OBSERVE (12安全模式)
- ✅ Python OBSERVE (ast.parse)
- ✅ AI降噪 (100% precision on actionable)
- ✅ AI缺失控制检测 (GT-008已验证)
- ✅ Gosec Go 1.25兼容性
- ✅ 多语言OBSERVE (Go+Python)
- ✅ Noise reduction (34→5 actionable)
- ✅ 诚实定位

---

## 13. 参考资料

### 13.1 铁壁内部文档
- `docs/DESIGN_PhaseB_Real_AI_Engine.md` — Phase B架构设计
- `docs/BRAIN_B_REVIEW_PhaseB.md` — 架构审查
- `docs/BRAIN_B_PROTOCOL.md` — 双脑协议
- `battle_test_candidates/go_target/BATTLE_REPORT.md` — 实战报告
- `CODE_REVIEW_CHECKLIST.md` — 代码审查清单

### 13.2 外部资源
- OWASP Benchmark: https://owasp.org/www-project-benchmark/
- OWASP Python Benchmark: GitHub `OWASP/www-project-benchmark`
- gosec: https://github.com/securego/gosec
- Semgrep: https://semgrep.dev
- CodeQL: https://codeql.github.com
- Neo: https://projectdiscovery.io
- RealVuln: arXiv:2604.13764
- Snyk VulnBench: arXiv:2606.15762
- ZeroFalse: arXiv:2510.02534

---

*End of Knowledge Base — v4.1*
*2026-07-10 | Brain A(皮特) + Brain B(Codex DeepSeek-v4-pro) 联合更新*
*v4.1: +Arnica AI SAST多文件分析 +CSA 2026 Runtime Shift +竞争缺口重评估 +KB注入proxy system prompt*
*每次 Brain B 会话必读: `cat f:/ClaudeFiles/_research/ironwall/docs/BRAIN_B_KNOWLEDGE.md`*
