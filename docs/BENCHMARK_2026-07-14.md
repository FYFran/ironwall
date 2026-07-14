# Ironwall Benchmark — 2026-07-14

## Executive Summary

Ironwall v0.7.0 with Step 9 MISSING detection finds **22.4x more security issues** than Semgrep standalone and **9.3x more** than Gosec standalone on the go-vuln-app test target.

## go-vuln-app (16 known vulnerabilities)

| Tool | Total Findings | CRITICAL | HIGH | Detection Rate |
|------|:---:|:---:|:---:|:---:|
| **Ironwall FULL** | **112** | 4 | 54 | **81%** (13/16) |
| Ironwall SAST only | 36 | 4 | 12 | 38% (6/16) |
| Semgrep standalone | 5 | - | - | 31% (5/16) |
| Gosec standalone | 12 | - | - | 25% (4/16) |

Ironwall's MISSING detection (step 9) alone found 96 missing security controls that no other tool detected.

## campus_go (Go backend, 39 endpoints)

| Tool | Total | CRITICAL | HIGH | MEDIUM |
|------|:---:|:---:|:---:|:---:|
| **Ironwall** | **197** | 0 | 101 | 83 |

Top missing controls: rate_limiting (39 endpoints), input_validation (36), security_headers (38), CSRF (18 POST endpoints), SSRF (on HTTP-calling handlers)

## campus_app (Flutter/Dart, mobile app)

| Tool | Total | CRITICAL | HIGH |
|------|:---:|:---:|:---:|
| **Ironwall** | **282** | 11 | 162 |

Framework detected: Flutter (pubspec.yaml). SAST + secrets scanning active. Dart endpoint extraction pending.

## Ironwall Self-Scan (dogfooding)

| Tool | Total | CRITICAL | HIGH |
|------|:---:|:---:|:---:|
| **Ironwall** | **344** | 111 | 55 |

CRITICAL findings mostly from battle_test_candidates (intentionally vulnerable code). Pipeline processes 8 steps normally.

## Detection Coverage (go-vuln-app, 16 known vulns)

| # | Vulnerability | Ironwall | Semgrep | Gosec |
|---|--------------|:---:|:---:|:---:|
| 1 | SQL Injection | ✅ | ❌ | ❌ |
| 2 | Command Injection | ✅ | ✅ | ✅ |
| 3 | Hardcoded Secrets | ✅ | ✅ | ❌ |
| 4 | Missing Auth (admin) | ✅ | ❌ | ❌ |
| 5 | Path Traversal | ✅ | ❌ | ✅ |
| 6 | SSRF | ✅ | ❌ | ❌ |
| 7 | XXE | ✅* | ❌ | ❌ |
| 8 | YAML Deserialization | ✅* | ✅ | ❌ |
| 9 | Debug Endpoint | ✅ | ❌ | ❌ |
| 10 | No Rate Limiting | ✅ | ❌ | ❌ |
| 11 | Open Redirect | ✅* | ❌ | ❌ |
| 12 | Weak Hash (MD5) | ✅* | ❌ | ✅ |
| 13 | Eval Injection | ✅* | ❌ | ❌ |
| 14 | File Upload | ✅ | ❌ | ❌ |
| 15 | No CSRF | ✅ | ❌ | ❌ |
| 16 | No CSP/Security Headers | ✅ | ❌ | ❌ |

*Detected after OBSERVE sink list expansion (2026-07-14)

Ironwall: 13/16 (81%). Semgrep: 5/16 (31%). Gosec: 4/16 (25%).
