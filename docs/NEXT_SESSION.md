# NEXT_SESSION — 铁壁 (2026-07-11 深夜存档)

> v4.2完成 | 11 commits | 调用图Go+Python | Brain B v4.2 | Late Alpha评估

---

## 本轮完成 (7.11全天)

### 调用图 v4.1-4.2 ✅
- 调用图→TRACE集成 (Option C: validated taint chains + 5 guardrails)
- visited-key bug修复 — 同文件多函数链断裂 (关键修复!)
- Python调用图 — stdlib ast, 15 funcs, 24 taint chains
- callgraph_target测试夹具 (4文件/3包, LoginHandler→QueryUser→sqlQuery)
- Go entry points: 77 (strict handler detection). Python: 11 (Flask patterns)

### 管线优化 ✅
- HTTP timeout 120s→300s (DeepSeek R1), --deep auto-900s
- VERIFY批量 5x (was 1 trace/call → 5 traces/call)
- Verify prompt哲学统一 (PromptVerify + DeepVerify → adversarial by default)
- Python OBSERVE path resolution修复 (parse errors 36→1)

### Brain B v4.2 ✅
- KB压缩 13KB→4.5KB (-65%, -2135 tokens/session)
- 双模型默认: deepseek-chat(V3/triage) + deepseek-reasoner(R1/deep)
- SEARCH命令: [SEARCH: query] + DSML tag auto-detect
- Proxy system prompt: 5 critical rules
- Codex proxy已重启 (单实例, port 4000)

### 测试 ✅
- observe: 16 tests (0 skip!), ai: 5 tests, pipeline: 9 tests
- PythonObserve_Integration 不再skip: 5 files, 10 sections, 8 handlers
- secure-file-management fixture 从submodule转普通文件

---

## Brain B评估: LATE ALPHA

**Verdict**: 引擎sophisticated (research-grade), 验证thin (1个数据点)。

| 已验证 | 未验证 |
|--------|--------|
| Go target 12 vulns, 89% recall, $0.016 | Python端到端从未用AI跑过 |
| OBSERVE Go+Python | Python TRACE找漏洞能力未知 |
| Call graph 跨文件链 | VERIFY批量FP率未知 |
| TRACE prompt construction | MISSING在Python上行为未知 |
| Pipeline runs end-to-end | Call graph提升TRACE多少未知 |

**最大风险**: 虚假信心。工具看起来权威但Python管线未验证。

---

## 🔴 下个会话: Python端到端实战

### 启动指令

```
1. Codex proxy应已运行 (port 4000). 检查: curl -s http://localhost:4000/health
2. 读 docs/NEXT_SESSION.md (本文件)
3. DEEPSEEK_API_KEY应在env
4. 确认secure-file-management fixture: ls battle_test_candidates/secure-file-management/app/routes.py
```

### P0任务

**1. Python端到端 (secure-file-management, 544行Flask)**

```bash
cd f:/ClaudeFiles/_research/ironwall
go run ./cmd/ironwall/ scan ./battle_test_candidates/secure-file-management --ai --deep --format terminal
```

观察: TRACE产生几个finding? VERIFY通过几个? MISSING找到什么? 总成本?

**2. 建Python漏洞target** (Flask app, 5-10个已知漏洞)

SQL注入(cursor.execute拼接) + SSTI(render_template_string) + Auth bypass(缺@login_required) + Path traversal(os.path.join用户输入) + SSRF(requests.get用户URL)

目标: 测量Ironwall recall + FPR。

**3. Call Graph ON vs OFF消融实验**

同一target跑两次: 一次正常(--deep), 一次改代码跳过call graph注入。对比TRACE finding数量+质量。

### 关键文件

| 文件 | 说明 |
|------|------|
| `internal/ai/observe/callgraph.go` | Go调用图 + WalkTaint + entry points |
| `internal/ai/observe/python_callgraph.py` | Python调用图 |
| `internal/ai/observe/python_callgraph.go` | Python CG → Go bridge |
| `internal/ai/phaseb.go` | Phase B: TRACE/VERIFY/MISSING/CONFIG管线 |
| `internal/ai/prompts.go` | 所有AI prompt (已统一adversarial) |
| `internal/ai/client.go` | AI HTTP client (300s timeout) |
| `internal/ai/trace_test.go` | TRACE prompt 5测试 |
| `internal/ai/observe/callgraph_test.go` | 调用图 13测试 |
| `battle_test_candidates/callgraph_target/` | Go跨文件漏洞target |
| `battle_test_candidates/secure-file-management/` | Python Flask target |
| `docs/BRAIN_B_KNOWLEDGE_v4.2.md` | Brain B知识库 (4.5KB compact) |

### 新对话提示词

```
继续铁壁开发。上次会话完成v4.2 — 调用图Go+Python双语言、VERIFY批量、
Brain B KB压缩、visited-key修复、Python OBSERVE路径修复。16 observer tests + 5 ai tests + 9 pipeline tests全通过。

Brain B评估为Late Alpha: 引擎competent，验证只有1个Go数据点。Python管线从未用真实AI跑过。

DEEPSEEK_API_KEY在env。现在要做:
1. Python端到端实战 — 用--ai --deep跑secure-file-management (544行Flask)
2. 建Python漏洞target (5-10 planted vulns: SQLi/SSTI/auth bypass/path traversal/SSRF)
3. Call Graph ON vs OFF消融实验

启动: 确认proxy port 4000 OK, 读NEXT_SESSION.md, 直接开干。
```

---

*皮特 + Brain B (DeepSeek v4-pro via Codex) | 2026-07-11 深夜存档*
*11 commits: 7d8a921→c00cda8*
*Next: Python end-to-end with real AI.*
