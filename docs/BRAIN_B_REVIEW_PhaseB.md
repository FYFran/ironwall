# Brain B Adversarial Review — Phase B Architecture (2026-07-10)

> Status: POST-IMPLEMENTATION REVIEW
> Subject: OBSERVE→TRACE→VERIFY architecture + pipeline integration

---

## What Was Built

1. **observe/ package** — Go AST parser + 12 security patterns, detects SQL/command/file/crypto/HTTP/serialization/template/network/reflection/SSRF/secrets/input concerns. Pure Go, zero dependencies beyond stdlib.
2. **Engine.Observe()** — Runs OBSERVE phase on target directory.
3. **Engine.Trace()** — Batch LLM data flow tracing. SystemPromptTrace + PromptTrace.
4. **Engine.VerifyTraces()** — Adversarial single-finding verification. SystemPromptVerify + PromptVerify.
5. **Engine.AnalyzeDeep()** — Full pipeline: OBSERVE→TRACE→VERIFY→ConvertToFindings.
6. **Engine.ConvertToFindings()** — VerifiedFinding → report.Finding for pipeline merge.
7. **scan.go `--deep` flag** — Triggers Phase B after SAST pipeline.
8. **config.DeepAnalysis** — Config field.

---

## Brain B Attack (Required per protocol)

### 🔪 Attack 1: LLM data flow tracing is fiction

TRACE asks LLM: "Trace from input to sink." LLM sees code, guesses. No actual data flow analysis. Same criticism as original DeepVerify — prompt-based classification, not real code understanding.

**Mitigation:** VERIFY phase provides adversarial check. But adversarial check is ALSO prompt-based. Two prompts don't make real analysis. This is prompt→prompt, not code→analysis.

**Severity: HIGH.** Core value proposition depends on LLM tracing being accurate. No evidence it works on real code.

### 🔪 Attack 2: No cost guardrails

`AnalyzeDeep()` caps sections at 50, but:
- OBSERVE finds 69 sections on ironwall (57 files). Larger projects = more.
- Each TRACE batch = 1 API call. With 50 sections in batches of 10 = 5 calls.
- Each VERIFY = 1 API call per finding. If TRACE returns 20 results = 20 more calls.
- Total: ~25 API calls. At DeepSeek chat pricing = ~$0.05-0.10. Fine.
- But on a 100K LOC project with 500 sections → 50 TRACE + 100 VERIFY = ~$0.50-1.00. Still OK.
- Problem: no MAX_COST limit. If LLM is verbose, costs spike.

**Severity: MEDIUM.** Costs are bounded by section cap. But no explicit budget.

### 🔪 Attack 3: Single-verifier pattern

Research consensus (ZeroFalse, QASecClaw, RealVuln): multi-agent verification > single-agent. VERIFY uses one LLM call per finding. Should use 2-3 with majority vote.

**Mitigation:** VERIFY prompt is adversarial ("try to prove NOT real"). Provides internal skepticism without multi-agent. But one model's skepticism ≠ independent verification.

**Severity: MEDIUM.** Architectural choice, can be upgraded.

### 🔪 Attack 4: No evidence of finding SAST-missed vulns

The entire value proposition is "finds vulnerabilities SAST misses." But:
- No ground truth test yet
- No benchmark results
- No comparison against raw semgrep
- TRACE might just re-discover what semgrep already found
- Or worse: find nothing at all (all LLM noise)

**Severity: CRITICAL.** Core value proposition unvalidated.

### 🔪 Attack 5: Go-only OBSERVE

12 patterns all target Go AST. Python/tree-sitter parser declared in design but not built. The `--deep` flag silently does nothing for Python projects.

**Severity: LOW.** Go-first is correct for Phase B.1. Python comes later.

---

## Brain A Rebuttal

1. **Data flow tracing:** Fair critique. This is the fundamental limitation of LLM-based analysis. But the research says this approach works (ZeroFalse F1=0.912, QASecClaw 88.6% FP reduction). The key is CWE-specific prompting + code context, both implemented.

2. **Cost guardrails:** Add in next iteration. 50-section cap is conservative for now.

3. **Single verifier:** The adversarial prompt design (SystemPromptVerify) provides internal skepticism. Research shows adversarial self-prompting can substitute for multi-agent in cost-constrained scenarios. Can upgrade later.

4. **No evidence:** VALID. Needs battle testing. This is the next step — not more code.

5. **Go-only:** By design. Python observer is Milestone B.1.2.

---

## Consensus

**Architecture is sound. Value proposition unvalidated.**

| Dimension | Status | Next Step |
|-----------|--------|-----------|
| Architecture | ✅ Follows research consensus | — |
| Code quality | ✅ Compiles, tests pass | — |
| Integration | ✅ Wired into scan command | — |
| Cost control | ⚠️ Section cap only | Add budget limit |
| Detection quality | ❌ Unknown | Battle test on real projects |
| Python support | ❌ Not built | tree-sitter integration |

**Decision: STOP BUILDING. Test what exists.**

Phase B code is complete enough for a battle test. Before writing more code:
1. Run `ironwall scan . --ai --deep` on a known-vulnerable Go project
2. Compare what OBSERVE→TRACE→VERIFY finds vs what SAST alone finds
3. Measure: does it find anything SAST missed? At what precision?
4. If yes → continue building. If no → redesign TRACE approach.

---

*Brain B (Codex DeepSeek-v4-pro) adversarial review | 2026-07-10*
