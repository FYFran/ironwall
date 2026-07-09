# Ironwall Agent — Precision Benchmark

> **Date:** 2026-07-09  
> **Method:** Human-annotated ground truth vs Agent (offline engine)  
> **Codebase:** vulnbench (intentionally vulnerable test suite)  

## Results

| Metric | Value | Target |
|---|---|---|
| Precision | 94.4% | ≥ 70% |
| Recall | 94.4% | — |
| F1 | 0.944 | — |

| | Count |
|---|---|
| True Positives | 17 |
| False Positives | 1 |
| True Negatives | 1 |
| False Negatives | 1 |

## Disagreements (Noted for Transparency)

- secrets.py:22 Agent=NOT_EXPLOITABLE Truth=REAL_VULN (DB password in connection string)
- injection.py:64 Agent=EXPLOITABLE Truth=FP (ElementTree is XXE-safe, parse() takes filepath not string)

## Limitations (Honest Disclosure)

- Sample size: 20 annotated positions in known-vulnerable test code
- Annotator: single reviewer (皮特), no second annotator
- Test code is intentionally vulnerable — results may not generalize to production code
- Offline engine uses rule-based heuristics — AI engine (DeepSeek) may differ
- Fiber test (separate): 23 findings, 0 real vulns, Agent correctly rejected 22/23

