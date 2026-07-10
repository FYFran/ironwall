# Ironwall Phase B — Real AI Audit Engine Architecture

> 2026-07-10 | Brain A + Brain B consensus | Status: DESIGN

---

## The Problem

Current AI engine (v0.7.0) does ONE thing: takes SAST finding → asks LLM "real or fake?" → returns verdict.

It does NOT:
- Find vulnerabilities SAST misses
- Understand code semantics
- Trace data flow
- Generate attack paths
- Work offline

Phase B builds the engine promised in v0.5.0: OBSERVE→TRACE→VERIFY→ASSESS.

---

## Architecture: 4-Phase Agent Pipeline

```
Source Code
    │
    ▼
┌──────────────────────────────────────────────┐
│ PHASE 1: OBSERVE                              │
│                                                │
│ CodeParser (Go AST / tree-sitter Python)       │
│   → Extract functions, routes, auth checks     │
│   → Identify security-relevant constructs      │
│   → Flag "interesting" sections for analysis   │
│                                                │
│ Output: List of {file, function, concern_type} │
└────────────────────┬─────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│ PHASE 2: TRACE                                │
│                                                │
│ LLM Analyst (DeepSeek, batched)               │
│   → For each interesting section:             │
│     "Trace data from input to sink.           │
│      Is there validation? Authorization?       │
│      Can an attacker control this input?"     │
│   → Cross-reference with route/endpoint map   │
│                                                │
│ Output: List of {trace_path, missing_checks}   │
└────────────────────┬─────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│ PHASE 3: VERIFY                               │
│                                                │
│ LLM Verifier (DeepSeek, adversarial prompt)   │
│   → "Try to prove this is NOT a vulnerability"│
│   → "If it IS a vuln, what's the exploit?"    │
│   → Check reachability (auth gates, config)   │
│                                                │
│ Output: List of {confirmed_vuln, confidence}   │
└────────────────────┬─────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────┐
│ PHASE 4: ASSESS                               │
│                                                │
│ Severity Calculator + Report Builder           │
│   → CVSS based on actual context              │
│   → Attack path narrative                     │
│   → Concrete fix recommendation               │
│   → Merge with SAST findings (dedup)          │
│                                                │
│ Output: Final report with prioritized findings │
└──────────────────────────────────────────────┘
```

---

## Key Design Decisions

### 1. Two-Pass Agent (not single DeepVerify)

Research consensus: multi-agent > single prompt. Minimum viable: 2 agents.

| Agent | Role | Prompt Strategy |
|-------|------|----------------|
| **Analyst** | TRACE phase | CWE-specific, code-context-rich |
| **Verifier** | VERIFY phase | Adversarial, "try to refute" |

### 2. AST Parser First, LLM Second

Don't send raw files to LLM. Parse AST first, extract security-relevant chunks, THEN send to LLM.

- Go: `go/parser` + `go/ast` (stdlib, zero dependency)
- Python: tree-sitter (single C library, Go bindings)
- Benefits: cheaper LLM calls (smaller context), structured output, offline pre-filter

### 3. Code Context Enrichment

Per the SastBench and ZeroFalse research, context matters more than model:
- Include: function signature, relevant imports, auth middleware, route definition
- Include: caller context (who calls this? with what params?)
- Include: configuration context (debug mode? CORS settings?)

### 4. CWE-Specific Prompting

ZeroFalse's key insight: different CWEs need different reasoning. Generic "find vulns" prompts perform worse.

```
SQL Injection → "Trace from user input to SQL query. Check for parameterization."
Auth Bypass → "Is this endpoint behind auth middleware? Can it be reached anonymously?"
Path Traversal → "Is the file path constructed from user input? Is there sanitization?"
```

### 5. Cost Budget per Scan

Target: <$0.50 per scan for AI analysis (25× current AI filter cost, justified by finding NEW vulns).

| Phase | Calls | Est. Cost |
|-------|-------|-----------|
| OBSERVE | 0 (local AST) | $0 |
| TRACE | ~10-30 (one per interesting section) | $0.05-0.15 |
| VERIFY | ~5-15 (only for suspicious traces) | $0.03-0.10 |
| ASSESS | 0 (local) | $0 |
| **Total** | **15-45 calls** | **~$0.08-0.25** |

### 6. Offline Mode (Phase B.2)

Architecture supports swapping DeepSeek with local LLM:
- Interface: `AIEngine` already abstract (`engine.Available()`)
- Local options: Ollama (Qwen 7B/14B), LM Studio
- Fallback: if no network, skip TRACE+VERIFY, only run OBSERVE (AST patterns)

---

## Implementation Plan

### Milestone B.1: OBSERVE (Week 1-2)

- [ ] `internal/ai/observe/parser.go` — Go AST parser
- [ ] `internal/ai/observe/python.go` — tree-sitter Python parser
- [ ] `internal/ai/observe/patterns.go` — Security-relevant pattern catalog
- [ ] Output: `[]ObservedSection{File, Func, ConcernType, CodeSnippet}`

### Milestone B.2: TRACE (Week 2-3)

- [ ] `internal/ai/trace/analyst.go` — LLM analyst with CWE-specific prompts
- [ ] `internal/ai/trace/context.go` — Context enrichment (imports, callers, config)
- [ ] `internal/ai/trace/batcher.go` — Batch API calls, rate limiting
- [ ] Output: `[]TraceResult{Section, DataFlow, MissingChecks, Suspicious}`

### Milestone B.3: VERIFY (Week 3-4)

- [ ] `internal/ai/verify/verifier.go` — Adversarial LLM verifier
- [ ] `internal/ai/verify/refute.go` — "Prove this is NOT a vuln" prompt
- [ ] `internal/ai/verify/exploit.go` — "If real, how to exploit?" prompt
- [ ] Output: `[]VerifiedFinding{TraceResult, IsReal, Confidence, ExploitPath}`

### Milestone B.4: ASSESS + Integration (Week 4-5)

- [ ] `internal/ai/assess/severity.go` — Context-aware CVSS calculator
- [ ] `internal/ai/assess/narrative.go` — Attack path narrative generator
- [ ] `internal/ai/assess/merge.go` — Merge AI findings with SAST pipeline findings
- [ ] Integration with existing pipeline (Step 2+8 replacement)

### Milestone B.5: Offline + Polish (Week 6-8)

- [ ] Local LLM support (Ollama interface)
- [ ] Benchmark on OWASP Python Benchmark (target: Recall >0.50)
- [ ] Battle test on real projects (target: find ≥1 SAST-missed vuln per project)
- [ ] Cost optimization (prompt caching, batch sizing)

---

## Success Criteria

| Metric | Current (v0.7.0) | Phase B Target |
|--------|:---:|:---:|
| Recall (OWASP Python) | 0.372 | >0.50 |
| New vulns found (AI-discovered, not in SAST) | 0 | ≥1 per project |
| AI Suppression Rate | 0% | <5% (must not kill real vulns) |
| Cost per scan | $0.02 | <$0.50 |
| Offline mode | SAST only | SAST + local LLM |

---

## What Phase B Does NOT Do

- ❌ Runtime verification (Neo's territory — requires sandbox infra)
- ❌ Interprocedural taint tracking (CodeQL's territory — years of engineering)
- ❌ Automated exploit generation (Revelio's territory — research-grade)
- ❌ Replace SAST (SAST rules still needed for systematic coverage)

Phase B makes Ironwall find things SAST misses. It doesn't make it Neo or CodeQL.

---

*Brain A (皮特) + Brain B (Codex DeepSeek-v4-pro) | 2026-07-10*
