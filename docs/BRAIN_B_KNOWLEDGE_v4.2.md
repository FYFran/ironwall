# Brain B KB — Ironwall v4.2 (compact)

> 2026-07-11 | Compressed from v4.1 (13KB→5KB) | +Python CG +batch verify +visited-key fix

## Quick Facts

- **Ironwall = Multi-SAST Runner + AI降噪 + AI缺失控制检测**
- Recall limit = underlying SAST rules (76.9% FN = missing rules, not engine)
- Differentiator: one-click semgrep+gosec+bandit+gitleaks+syft+KICS + dedup + AI filter
- Phase B unique value: detecting MISSING controls SAST can't find (GT-008 CWE-306 verified)
- Cost: ~$0.016/scan (incl Phase B). Web search via tavily_search available.
- Go OBSERVE: 12 security patterns, stdlib AST, zero deps. Python: ast.parse subprocess.
- v4.1: Call graph (AST, 830+ funcs, 1460+ edges). v4.2: Python call graph (Flask handlers → sinks).

## Task Defaults

When asked to do security work, default to these tools (no need to ask):
- **Security audit/review** → Code Graph MCP tools (codegraph_context→codegraph_explore→codegraph_trace)
- **Web search for latest vulns/papers** → Write `[SEARCH: your query]` in your response. The proxy will auto-execute the search and feed results back. Use this for: latest CVEs, competitor updates, new research papers, pricing changes, API docs.
- **Code changes** → caveman:builder + code-reviewer + security-auditor agents
- **Architecture/design decisions** → architect agent with adversarial review

CRITICAL: When you need information beyond your KB (cutoff ~2026-07-10), use `[SEARCH: specific query]`. The system will search and give you results. Don't guess or use outdated info.

## SAST Landscape

| Tool | Method | Precision | Recall | F1 | Cost |
|------|--------|:---:|:---:|:---:|------|
| CodeQL | QL + inter-procedural taint | 60% | 97% | 74% | Free(public)/$30 |
| Semgrep CE | AST pattern | 56% | 90% | 69% | Free |
| Neo | Runtime verify + multi-agent | 93% | 100% crit | — | $$$ enterprise |
| Arnica | AI multi-file taint + dual-layer | — | — | — | SaaS $$$ |

- **Real-world detection**: 4 tools → 11-27% each, combined 39%, +custom rules 45% (Bennett 2024)
- **Hybrid (SAST+LLM) = best**: F1 0.91-0.99, FPR ~10-17% (ZeroFalse 2026, RealSec-bench 2026)
- **Agent scaffolding > model quality**: GPT-4 raw 15-40% → +agent infra 70-85% (Rafter 2026)

## Key Research (2025-2026)

| Paper | Finding |
|-------|---------|
| ZeroFalse (2026) | CodeQL+LLM, F1=0.91 on OWASP, 0.96 on OpenVuln |
| RealVuln (2026.4) | 15 scanners on 26 Python repos: best F3=73 (Kolega.Dev), LLM=52, Semgrep=18 |
| Revelio (2026.6) | Agentic memory safety, 19 new vulns in fuzzed projects, ~$300 total |
| Snyk VulnBench JS (2026.6) | Best LLM F1=75% (Opus 4.6). Non-deterministic: 50% findings only in 1/5 runs. $≠quality |
| Antaeus (2026.7) | Repo-level logic vulns: context-grounded LLM, 15 vulns in 28 repos |
| Arnica (2026.7) | Multi-file AI taint, dual-layer (rules+AI), pipelineless ASPM |
| Abliterated LLMs (2026.7) | Ablated models patch verification 68% vs aligned 30% — refusal training hurts security |

## Ironwall Architecture

```
Ironwall = 8-Step Pipeline + Phase B AI Engine
  Step 1-8: gitleaks → semgrep+gosec+bandit → endpoints → hardcoded → deps → server → DB → supply chain
  Phase B: OBSERVE(local AST) → TRACE(LLM data flow + call graph) → VERIFY(adversarial) → MISSING(controls) → CONFIG
```

**Phase B pipeline**: OBSERVE (zero AI, local AST) → TRACE (LLM traces input→sink, batched 10/section, now with call graph cross-file chains) → VERIFY (adversarial, batched 5/trace) → MISSING (detects absent auth/validation/CSRF/rate-limit) → CONFIG (debug mode, weak TLS, missing headers)

**Call Graph (v4.1-4.2)**: AST-based, zero deps. Go: 830+ funcs. Python: 15 funcs on Flask app (stdlib ast). WalkTaint BFS from entry points (HTTP handlers). Validated chains injected into TRACE prompts as static hints (not ground truth).

## Battle Test Results

| Target | Precision | Recall | Unique | Cost |
|--------|:---:|:---:|:---:|:---:|
| OWASP Python (1230 files) | 100% | 37% (3× semgrep alone) | — | free |
| Go target (12 vulns) | 100% actionable | 89% (8/9) | GT-008 CWE-306 | $0.016 |
| Python Flask (544 lines) | — | — | 0 (code was secure) | $0.016 |

## Known Gaps

| Gap | Priority |
|-----|:--:|
| No runtime verification (Neo does this) | 🔴 |
| Python TRACE not end-to-end tested (timeout fixed, CG ready) | 🔴 |
| No cross-repo/inter-service taint (Arnica does this) | 🟡 |
| Offline LLM (Ollama) not implemented | 🟡 |
| PromptVerify vs DeepVerify logic contradiction | 🟡 |
| No IDE plugin, no PR integration, no pricing model | 🟢 |

## Critical Numbers

- CVE 2025: 48,174 (131/day). 38% High/Critical. Time-to-exploit: <5 days.
- Supply chain attacks: 4× growth in 5 years. 2025: 26 events/month.
- AI-generated code: 45% has vulns, 62% at least 1 exploitable. Pass rate stuck at ~55%.
- Ironwall cost ceiling: $0.016/scan vs Arnica enterprise $$$.

---

*Brain B Knowledge Base v4.2 — compact edition*
*Updated: 2026-07-11 | +Python CG +batch VERIFY +visited-key fix*
