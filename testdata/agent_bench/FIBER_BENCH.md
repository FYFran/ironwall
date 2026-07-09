# Ironwall Agent — Fiber Differential Analysis

> **Target:** gofiber/fiber (170 Go files, 128K lines)  
> **Scanner:** Ironwall 8-step pipeline  
> **Agent:** Offline Engine (9 rule categories)  

## Key Result

| Metric | Value |
|---|---|
| Scanner findings | 23 |
| Agent confirmed | 1 |
| Agent rejected (FP reduction) | 22 (96%) |
| Low confidence | 22 |

## Why This Matters

Most SAST tools dump 23 findings on the user. The Agent correctly identifies that:

- **Test files are not vulnerabilities** (test data, unit tests)
- **Documentation examples are not leaks** (README code snippets)
- **Unpinned CI actions are hygiene issues, not exploits**
- **SBOM is informational, not a security finding**

Without the Agent, a developer would waste time triaging all 23 findings manually. With the Agent, they focus only on the actionable ones.
