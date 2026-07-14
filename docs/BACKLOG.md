# Ironwall Backlog

Non-trivial features deferred by Brain B consensus. Not TODO items — deliberate "not now" decisions.

## Deferred (Brain B 2026-07-14)

### Step9 library vs application mode
- **Request:** auto-detect if target is library (no `main`/`cmd/`) and suppress step9 endpoint findings
- **Why deferred:** Go ecosystem has no reliable heuristic. `vendor/`, `go.sum`, import paths, `func main()` — all ambiguous. A rough heuristic introduces new noise class (misclassification).
- **Better approach:** `.ironwall.yaml` config toggle `mode: library|application`. Manual but correct.
- **When to revisit:** After multi-project precision data shows step9 FP rate >50% on libraries AND a `.ironwall.yaml` schema is designed.

### Academic CVE benchmark
- **Request:** OSV API queries, CVE detection matrix per CWE, blind testing vs semgrep
- **Why deferred:** Engineering-first positioning. "Go vuln DB has 448 vulns, we call govulncheck" is honest and sufficient. 15 CVE cases already in benchmark.
- **When to revisit:** Post-launch, if accuracy claims need independent verification.

## Current Sprint (post-Brain B 2026-07-14)

- [x] Push 8 commits to GitHub (SSH key pending)
- [x] G104 safety net: defense-in-depth comment + warn log
- [x] chi.go 1 remaining: documented as known limitation
- [x] Step9 library: deferred to FUTURE.md
- [ ] Multi-project precision verification (5+ projects, per-finding analysis)
- [ ] Git push (SSH key setup)
