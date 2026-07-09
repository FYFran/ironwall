# Ironwall Agent Engine — Baseline Scores

> Generated: 2026-07-09 | Engine: Offline (rule-based, no LLM)  
> Validation Set: golden.json (10 findings)

## Confusion Matrix

|  | Predicted Exploitable | Predicted NOT Exploitable |
|---|---|---|
| **Actually Exploitable** | TP=6 | FN=1 |
| **Actually NOT Exploitable** | FP=0 | TN=3 |

## Metrics

| Metric | Value | Target |
|---|---|---|
| Precision | 1.000 | >0.7 |
| Recall | 0.857 | >0.7 |
| F1 | 0.923 | >0.7 |

## Per-Finding Results

| ID | Expected | Actual | Confidence | Correct? |
|---|---|---|---|---|
| GOLDEN-001 | confirm | exploitable | 0.70 | ✅ |
| GOLDEN-002 | confirm | exploitable | 0.70 | ✅ |
| GOLDEN-003 | confirm | not exploitable | 0.85 | ❌ |
| GOLDEN-004 | confirm | exploitable | 0.85 | ✅ |
| GOLDEN-005 | confirm | exploitable | 0.75 | ✅ |
| GOLDEN-006 | confirm | exploitable | 0.90 | ✅ |
| GOLDEN-007 | confirm | exploitable | 0.40 | ✅ |
| GOLDEN-008 | reject | not exploitable | 0.40 | ✅ |
| GOLDEN-009 | reject | not exploitable | 0.40 | ✅ |
| GOLDEN-010 | reject | not exploitable | 0.85 | ✅ |

## Analysis

✅ Offline engine meets target F1 > 0.7. Strong baseline for rule-based analysis.

### Observations

- Offline engine uses pattern matching + AST context heuristics
- No LLM/API calls — runs fully offline in <100ms per finding
- Expected improvement from AI: +10-20pp F1 via OBSERVE→TRACE→VERIFY→ASSESS reasoning
- GOLDEN-008 (TLS config), -009 (ElementTree XXE), -010 (placeholders) are adversarial samples that require semantic understanding

### Next Steps

1. Run AI Analyst on same golden.json → compare F1
2. Tune offline rules based on FP/FN patterns
3. Expand golden.json to 20+ samples for statistical significance
