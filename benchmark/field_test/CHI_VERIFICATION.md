# Chi Project — Manual Finding Verification

**Date:** 2026-07-14
**Method:** Every non-test finding manually reviewed against source code
**Project:** go-chi/chi v5 (HTTP router/middleware library)

---

## Result: 2/20 True Positive — 10% Precision

| # | File | Line | Category | Severity | Finding | Verdict | Reason |
|---|------|------|----------|----------|---------|---------|--------|
| 1 | chi (root) | 0 | sbom | INFO | SBOM generation | FP | Informational, not security |
| 2 | chi (root) | 0 | supply-chain | INFO | OpenSSF not installed | FP | Informational, not security |
| 3 | chi.go | 21 | missing-defense | HIGH | Missing security_headers on GET / | FP | Library entry point, not app endpoint |
| 4 | compress.go | 346 | G104 | MEDIUM | Errors unhandled (Flush) | FP | Flush failure non-critical for compression |
| 5 | heartbeat.go | 18 | G104 | MEDIUM | Errors unhandled (Write dot) | FP | Heartbeat dot write failure non-critical |
| 6 | logger.go | 38 | missing-defense | HIGH | Missing security_headers | FP | Library middleware, not app endpoint |
| 7 | profiler.go | 30 | G710 | HIGH | Open redirect via taint | FP | Same-origin redirect (r.RequestURI), not exploitable |
| 8 | profiler.go | 27 | G710 | HIGH | Open redirect via taint | FP | Same-origin redirect, not exploitable |
| 9 | profiler.go | 26 | missing-defense | HIGH | Missing security_headers | FP | Library middleware, not app endpoint |
| 10 | recoverer.go | 69 | G104 | MEDIUM | os.Stderr.Write error unchecked | **TP** | Panic stack trace silently lost if stderr write fails |
| 11 | recoverer.go | 66 | G104 | MEDIUM | ErrorWriter.Write error unchecked | **TP** | Custom error output silently dropped on write failure |
| 12 | route_headers.go | 20 | missing-defense | HIGH | Missing security_headers | FP | Library middleware, not app endpoint |
| 13 | route_headers.go | 21 | missing-defense | HIGH | Missing security_headers | FP | Library middleware, not app endpoint |
| 14 | strip.go | 62 | G710 | HIGH | Open redirect via taint | FP | Same-origin redirect (path from StripPrefix), not exploitable |
| 15 | terminal.go | 61 | G104 | MEDIUM | w.Write(reset) error unchecked | FP | Color output to terminal, failure non-critical |
| 16 | terminal.go | 57 | G104 | MEDIUM | w.Write(color) error unchecked | FP | Color output to terminal, failure non-critical |
| 17 | timeout.go | 18 | missing-defense | HIGH | Missing security_headers on GET /long | FP | Library middleware, not app endpoint |
| 18 | url_format.go | 29 | missing-defense | HIGH | Missing security_headers on GET /articles/{id} | FP | Library middleware, not app endpoint |
| 19 | mux.go | 530 | G104 | MEDIUM | w.Write(nil) error unchecked | FP | Deliberate empty body in 405 response |
| 20 | sbom.cdx.json | 0 | sbom | INFO | SBOM generated | FP | Informational, not security |

---

## FP Root Cause Analysis

### Category 1: step9 "missing-defense" on library middleware (7 FP)

Chi is a router LIBRARY. Its middleware/* files ARE the library — they implement routing primitives, not application endpoints. Flagging `middleware/logger.go` for "missing security headers" is like flagging a hammer for "missing fingerprint scanner." Rate limiting and security headers belong in the APPLICATION layer, not the routing library.

**Fix needed:** step9 should exclude library code. Detection: no `main` package, no `cmd/` directory, module name doesn't end in a known library pattern → run step9 but mark all findings as `[LIBRARY]` with INFO severity.

### Category 2: G104 "Errors unhandled" on non-critical writes (4 FP)

`w.Write()` on ResponseWriter almost never fails in practice (it buffers in memory). When it does fail, the connection is already dead. Flagging every unchecked `Write()` as "error unhandled" generates noise without security value.

**Fix needed:** G104 severity downgrade when the unchecked call is on `http.ResponseWriter.Write` or `os.Stderr.Write` (which also rarely fails meaningfully).

### Category 3: G710 "Open redirect" on same-origin paths (3 FP)

`http.Redirect(w, r, somePath, 301)` where `somePath` is derived from request path manipulation (StripPrefix, RequestURI append). These redirect within the same origin — no external redirect possible. Gosec's taint analysis can't distinguish cross-origin from same-origin redirects.

**Fix needed:** G710 downgrade when redirect target doesn't contain `://` (same-origin). Only flag cross-origin redirects as HIGH.

---

## Corrected Metrics

| Metric | Before Verification | After Verification |
|--------|-------------------|-------------------|
| Total findings | 142 | 142 |
| Test/example tagged | 122 | 122 |
| Non-test findings | 20 | 20 |
| **True Positive** | unknown | **2** |
| **False Positive** | unknown | **18** |
| **Precision** | unknown | **10%** |

---

## Implications

1. **Test exclusion alone is not enough.** Even after removing `_examples/`, precision on library code is only 10%.
2. **step9 needs library detection.** 7/18 FP are from endpoint analysis on library code.
3. **G104 severity needs tuning.** `w.Write()` errors are never security-critical.
4. **G710 needs cross-origin check.** Same-origin redirects are not exploitable.
5. **For real application code (campus_go), precision should be higher** — campus_go IS an app with real endpoints, not a library.

---

*Verified by: 皮特 | 2026-07-14 | Each finding checked against source*
