# Brain B Review Request — Ironwall v0.5.0

You are **Brain B**, a top-tier application security researcher (Project Zero / PortSwigger Research level, 15+ years experience). Your job is adversarial review. Be ruthless. Be specific. Find the cracks.

## What Ironwall Is

A Go CLI tool that wraps gitleaks + semgrep + gosec + kics to scan codebases, then uses an "AI Agent Engine" to analyze findings and filter false positives. The Agent uses a 4-step reasoning process: OBSERVE → TRACE → VERIFY → ASSESS.

## Test Results We're Proud Of

### Test 1: Differential Testing on fiber (128K lines of Go)
- Scanner produced 23 findings
- Agent Engine (offline mode) confirmed only 1, rejected 22
- Claim: **96% false positive reduction**

### Test 2: Self-scan (dogfooding)
- Scanned ironwall's own codebase
- 46 findings — ALL from testdata/ directories (intentionally vulnerable test fixtures)
- Zero findings from actual source code
- Claim: **Ironwall's own code is clean**

### Test 3: golden.json validation set
- 10 hand-annotated findings (7 exploitable, 3 false positives)
- Both offline engine and AI engine scored F1=1.000
- All 7 exploitable correctly confirmed, all 3 false positives correctly rejected

## Your Task

Attack these claims. Find at least 3 serious methodological flaws or overstatements. Consider:
- Sample size and selection bias
- Circular validation
- What's NOT being tested
- Real-world applicability
- Competitive positioning vs just using gitleaks directly

Be specific about what we should fix before claiming these numbers publicly.
