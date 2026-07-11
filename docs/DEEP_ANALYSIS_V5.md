# Ironwall 深度分析 v5 — 方向·市场·前景

**生成日期**: 2026-07-11
**分析者**: Brain A (Claude Code) + Brain B (Codex/DeepSeek-v4-pro)

---

## 1. 当前真实状态

### 代码资产
- 57文件已commit, 未push, 仓库: github.com/FYFran/ironwall
- 核心: 4-step Agent Engine (OBSERVE→TRACE→VERIFY→ASSESS)
- Call graph: 799 functions, 1439 edges
- Go AST (go/parser) + Python AST (extract_ast.py) + Generic ContextProvider
- OfflineEngine: 9规则
- DeepSeekClient: 自包含，无import cycle

### 测试数据
- Precision 94.4% on vulnbench (17TP/1FP/1TN/1FN)
- AI 4/5 > offline 3/5 in grey zone
- 4-step OBSERVE ablation proof: beats one-shot on SSL key FP
- Core gap: Recall 7% (未审计)

### 未完成工作
- Call graph存在但TRACE未接入（核心gap）
- Python MISSING没实战测试
- +638行未提交 (callgraph.go+165, phaseb.go+88, NEXT_SESSION.md+367)
- battle_test_candidates/ 目录有python-vuln-target和go-vuln-target

### 定价
- 闲鱼listing: 99/299/599三档
- 前3单免费引流

---

## 2. 市场分析（2026年7月）

### AI代码安全市场规模
- AI生成代码正爆炸增长: GitHub Copilot/Codex/Cursor/Claude Code全面普及
- Addy Osmani(Google AI Director): AI代码含1.7x缺陷, 45%有OWASP漏洞
- AI短剧/视频市场半年110亿——大量非程序员在用AI生成代码
- 政府监管: OpenAI提议送美国政府5%股权, Anthropic模型被暂停出口

### 竞争格局
| 竞品 | 优势 | 弱点 |
|------|------|------|
| semgrep | 开源免费, 社区规则库 | 纯pattern matching, 无AI解释 |
| CodeQL | GitHub生态, 数据流分析强 | 学习曲线陡, 无AI叙事 |
| Snyk | $8.5B估值, 依赖扫描王者 | 代码SAST弱 |
| strix | 36K GitHub星, 渗透测试 | niche market |
| KERN | 多引擎, 非开源 | 商用, 小团队用不起 |

### 铁壁差异化
- 4-step AI不只是flag漏洞，还**解释攻击路径+给出修复方案**
- call graph(799/1439)是安全知识图谱的基础——可比Graphify(80K星)
- "AI审计AI"= 新兴赛道，目前无直接竞品
- Brain B双脑对抗验证= Karpathy在Anthropic做的RSI在安全领域的具体实现

---

## 3. 致命问题

### P0: Recall 7%
漏掉93%真实漏洞。Precision再高也没意义。不能卖一个漏93%漏洞的扫描器。

### P0: Call graph→TRACE未接入
铁壁区别于semgrep的唯一结构性优势是"理解数据流+解释攻击路径"。call graph建好了但Trace不用=引擎没接传动轴。

### P1: 无实战数据
所有测试数据来自vulnbench(合成)。零真实项目验证。铁壁大考(battle test)从未执行。

### P1: 定价策略不清晰
99块卖个人开发者=红海。但铁壁的真正价值是"AI输出可信"——卖给用AI写代码的团队/企业。

---

## 4. 战略建议

### 短期（6个月）
1. **停写功能，建ground truth**: 用battle_test_candidates/建真实漏洞数据集
2. **Recall从7%→70%+**: 接入call graph→TRACE，让AI看到数据流
3. **MCP化**: 包装为安全MCP server，任何AI agent都能调用
4. **定价改为9.9/月个人 + 99/月团队**: 靠量，不靠单价

### 中期（1-2年）
5. **从"找漏洞"扩展到"验证AI输出"**: Config/SQL/IaC/Deployment全验证
6. **安全知识图谱MCP**: call graph做成可查询的安全图谱
7. **开源核心+企业版**: GitHub开源 → 社区 → 企业pipeline

### 长期（3-5年）
8. **AIGC安全基础设施**: 每个AI生成的PR必须过验证→铁壁成为网关
9. **对抗验证协议标准**: 双脑对抗验证成为行业标准

---

## 5. 下一步行动（新对话）

1. 读本文件 + NEXT_SESSION.md
2. 调Brain B审查（Codex localhost:4000）
3. 优先级: Recall > call graph接入 > MCP化 > 定价重设
4. 第一个动作: 跑battle_test_candidates/建ground truth

---

## 6. PETE Memory 铁壁数据摘要

- 17条diary (6/30→7/11)覆盖全部铁壁版本
- 12条ironwall facts: Precision 94.4%, call graph 799/1439, 定价99/299/599, Brain B 3缺陷
- 最新: v4.2 VERIFY哲学统一 + Python OBSERVE修复 + Brain B KB v4.2
- Core gap: call graph→TRACE, Recall 7%, Python MISSING
- 决策: 停写代码→收集数据

---

*此文件与NEXT_SESSION.md一起喂给下一个对话。*