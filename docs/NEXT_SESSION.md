# NEXT_SESSION — 铁壁 (2026-07-10 晚间存档)

> Brain B v4.1注入 | 死代码清理 | 调用图 | Flask条件化 | 验证统一 | 全测试通过

---

## 本轮完成 (7.10晚间)

### 🔴 Brain B升级 ✅
- KB v4.1: +Arnica AI SAST +CSA 2026 +竞争缺口
- Proxy注入: `main.py`启动读KB → system prompt (13KB)
- tavily_search可用 → Brain B独立联网搜索
- KB路径: `docs/BRAIN_B_KNOWLEDGE.md`
- Proxy文档: `docs/CODEX_PROXY_FIXES.md`

### 🔴 死代码清理 ✅ — 170行移除
- `runTriage` (78行) + `runDeepVerify` wrapper (3行)
- 3个triage prompts + 2个triage types
- `noTestFilter` from Engine/NewEngine/scan.go/config.go
- `--no-test-filter` CLI flag

### 🔴 调用图 ✅ — AST-based, 零依赖
- 新文件: `internal/ai/observe/callgraph.go` (330行)
- Ironwall自身: 799函数, 1439调用边, 38包
- `WalkTaint()` BFS跨文件追踪
- 集成进 `ObserveResult` + OBSERVE pipeline
- 测试: `callgraph_test.go`

### 🟡 Verify Prompt统一 ✅
- `verifyBatchOneByOne` 现在用 `SystemPromptDeepVerify` (同batch)
- 阈值一致: `!IsReal && Confidence >= 0.7`
- 文档化一致性契约

### 🟡 Flask规则条件化 ✅
- `DeepVerifyPrompt(hasPython)` 动态选择prompt
- `Engine.SetLanguages(hasGo, hasPython)` API
- `detectLanguages()` 自动检测目标语言
- 非Python项目每次batch省~120 tokens

### 🟡 Python OBSERVE ✅
- CLI验证: 5文件, 10 sections, 8 handlers
- SAST发现30个(6 CRITICAL + 19 HIGH)
- MISSING应能找到: `delete_file`/`unshare_file` 缺CSRF保护(CWE-352)
- Phase B AI全pipeline: 需更长timeout (当前120s不够)

---

## 代码统计

- 提交: `b5afabd` — 5文件, +86/-20行 (Flask conditioning + verify fix)
- 提交: `00213f5` — Python OBSERVE集成测试
- 提交: `1eafe6e` — Brain B v4.1 + 死代码 + 调用图 (10文件, +676/-166)
- **总计: +819/-186行, 3 commits**

---

## 下一步

### ✅ 本次完成 (2026-07-10 深夜)
1. **Brain B对抗审查** — Option A(per-section raw CG)被否决，选Option C(pre-computed validated taint chains)
2. **调用图→TRACE集成** — `WalkTaintFromEntryPoints()` + `ValidateChain()` + `DeduplicateChains()` + `GetChainsForFunction()`
3. **TRACE prompt升级** — `SystemPromptTrace` 新增5条call graph hints解读规则
4. **Pipeline连接** — `AnalyzeDeep()` 自动计算taint chains传入`Trace()`
5. **全测试通过** — observe(4.4s) + pipeline(1.7s) + report/scanner 无回归
6. **Brain B攻击点**: 名称匹配over-match、token预算爆炸、Python nil静默退化、LLM信任错误图数据→更危险的幻觉 — 全部通过Option C guardrails防御

### 🔴 继续优先
1. ~~**Python TRACE AI实战 — 超时修复**~~ ✅ HTTP timeout 120s→300s, --deep auto-900s
2. **Brain B模型升级** — DeepSeek → Claude Opus 4.8 (SAST F1差~0.1)
3. **Recall审计** — 对比TRACE call graph ON vs OFF在实战项目上的Recall差异
4. **大项目调用图实战** — 100+文件Go项目验证entry point detection + chain质量
5. **Python TRACE 端到端测试** — 用secure-file-management跑完整Phase B (需API key)

### 🟡 下次
5. **Python调用图** — AST import追踪, 同Go模式
6. ~~**调用图接入TRACE**~~ ✅ 已完成

### 🟢 低优先级
7. 离线LLM (Ollama)
8. IDE插件
9. 定价模型
10. 闲鱼/GitHub发布

---

## 启动指令

```
1. python -m mempalace wake-up --wing claudefiles
2. python -m mempalace search "ironwall v4.1" --wing claudefiles
3. 读 docs/NEXT_SESSION.md (本文件)
4. Codex proxy port 4000 (应已运行, KB自动注入)
5. Brain B测试: curl -s http://localhost:4000/v1/responses -H "Content-Type: application/json" -d '{"input":[{"role":"user","content":"What is Arnica AI SAST?"}],"stream":false}' | grep delta
```

## 关键文件

| 文件 | 说明 |
|------|------|
| `docs/BRAIN_B_KNOWLEDGE.md` | v4.1知识库 |
| `docs/CODEX_PROXY_FIXES.md` | Codex代理修复 |
| `internal/ai/observe/callgraph.go` | 调用图引擎 (NEW) |
| `internal/ai/observe/callgraph_test.go` | 调用图测试 (NEW) |
| `internal/ai/engine.go` | 死代码清理 + verify统一 |
| `internal/ai/prompts.go` | Flask条件化 + DeepVerifyPrompt() |
| `internal/ai/types.go` | 砍TriageResult/TriageVerdict |
| `cmd/ironwall/scan.go` | detectLanguages() + SetLanguages |
| `internal/config/config.go` | 砍NoTestFilter |

---

*皮特 + Brain B (DeepSeek-v4-pro via Codex) | 2026-07-10 晚间存档*
*三连commit: 1eafe6e → 00213f5 → b5afabd*
