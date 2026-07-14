# Ironwall Agent Engine — AI Baseline Scores

> **Model:** DeepSeek V3 (deepseek-chat)  
> **Validation Set:** golden.json (10 findings)  
> **Date:** 2026-07-09

## Confusion Matrix

|  | Predicted + | Predicted - |
|---|---|---|
| **Actual +** | TP=6 | FN=1 |
| **Actual -** | FP=1 | TN=2 |

## Metrics

| Metric | AI (DeepSeek V3) | Offline (Rules) | Delta |
|---|---|---|---|
| Precision | 0.857 | 1.000 | -0.143 |
| Recall | 0.857 | 1.000 | -0.143 |
| F1 | 0.857 | 1.000 | -0.143 |

## Per-Finding Comparison

| ID | Expected | AI Verdict | AI Conf | Offline | AI |
|---|---|---|---|---|---|
| GOLDEN-001 | confirm | exploit | 0.95 | ✅ | ✅ |
| GOLDEN-002 | confirm | exploit | 0.95 | ✅ | ✅ |
| GOLDEN-003 | confirm | NOT | 0.95 | ✅ | ❌ |
| GOLDEN-004 | confirm | exploit | 1.00 | ✅ | ✅ |
| GOLDEN-005 | confirm | exploit | 1.00 | ✅ | ✅ |
| GOLDEN-006 | confirm | exploit | 1.00 | ✅ | ✅ |
| GOLDEN-007 | confirm | exploit | 0.95 | ✅ | ✅ |
| GOLDEN-008 | reject | exploit | 0.95 | ✅ | ❌ |
| GOLDEN-009 | reject | NOT | 0.95 | ✅ | ✅ |
| GOLDEN-010 | reject | NOT | 1.00 | ✅ | ✅ |

## Analysis

⚠️ **AI needs prompt tuning.** Below offline baseline but above minimum threshold.

### Key Takeaways

- **Offline** (rules): 100% F1, <100ms, $0 cost, deterministic
- **AI** (DeepSeek V3): see above, 2-5s/finding, ~$0.01/finding, non-deterministic
- **Best strategy:** Offline pre-filter → AI deep-dive on CRITICAL/HIGH only
- AI adds value via: natural language narratives, novel pattern detection, attack path synthesis

### Recommendations

1. If F1 < 0.8: add few-shot examples to SystemPromptAnalyst
2. Try deepseek-reasoner (R1) for complex reasoning tasks
3. Run 3 trials for statistical significance
4. Expand golden.json to 20+ samples
