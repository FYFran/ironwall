#!/usr/bin/env python3
"""
Ironwall vs Semgrep A/B Benchmark
===================================
Runs both tools against curated CVE test cases + real-world Go project.
Measures: recall, precision, unique findings, overlap.

CVE test cases: 10 files, each modeling a real Go CVE pattern.
Real-world target: campus_go

Output: benchmark_report.md with comparison tables
"""

import subprocess
import json
import re
import os
import sys
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# --- Config ---
BENCHMARK_DIR = Path(__file__).parent
CVE_CASES_DIR = BENCHMARK_DIR / "cve_cases"
CAMPUS_GO_DIR = Path("f:/ClaudeFiles/campus_go")
IRONWALL = Path("f:/ClaudeFiles/_research/ironwall/ironwall.exe")
SEMGREP = "semgrep"
REPORT_FILE = BENCHMARK_DIR / "benchmark_report.md"


# --- Data Classes ---
@dataclass
class CVEExpectation:
    """What we expect each tool to find for a given CVE case"""
    file: str
    cve_pattern: str
    cwe: str
    category: str
    expected_rule_keywords: List[str]  # keywords that a finding should contain


@dataclass
class ToolResult:
    tool: str
    target: str
    total_findings: int
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    detected_cves: List[str] = field(default_factory=list)
    missed_cves: List[str] = field(default_factory=list)
    raw_output: str = ""
    elapsed_ms: int = 0


# --- Expected CVEs ---
CVE_CASES: List[CVEExpectation] = [
    CVEExpectation("case01_sqli.go", "SQL Injection (CVE-2020-series)", "CWE-89",
                   "injection", ["sql", "injection", "fmt.Sprintf", "query", "concatenat"]),
    CVEExpectation("case02_path_traversal.go", "Path Traversal (CVE-2023-45283)", "CWE-22",
                   "path-traversal", ["path", "traversal", "filepath", "Clean", "../", "directory"]),
    CVEExpectation("case03_command_injection.go", "Command Injection (CVE-2021-series)", "CWE-78",
                   "injection", ["command", "injection", "exec.Command", "shell", "os/exec"]),
    CVEExpectation("case04_hardcoded_secrets.go", "Hardcoded Secrets (CVE-2019-series)", "CWE-798",
                   "secret", ["hardcoded", "secret", "password", "key", "token", "credential", "AKIA"]),
    CVEExpectation("case05_weak_crypto.go", "Weak Cryptography (CVE-2020-series)", "CWE-327",
                   "crypto", ["md5", "sha1", "des", "rc4", "weak", "crypto", "hash"]),
    CVEExpectation("case06_ssrf.go", "SSRF (CVE-2021-series)", "CWE-918",
                   "ssrf", ["ssrf", "request", "url", "forgery", "http.Get"]),
    CVEExpectation("case07_xss_template.go", "XSS via Templates (CVE-2023-29400)", "CWE-79",
                   "xss", ["xss", "template", "html", "escape", "text/template", "HTML"]),
    CVEExpectation("case08_tls_bypass.go", "TLS Verification Bypass (CVE-2021-series)", "CWE-295",
                   "tls", ["tls", "InsecureSkipVerify", "certificate", "verification", "ssl"]),
    CVEExpectation("case09_insecure_random.go", "Insecure Random (CVE-2023-series)", "CWE-338",
                   "crypto", ["random", "math/rand", "crypto/rand", "seed", "predictable"]),
    CVEExpectation("case10_open_redirect.go", "Open Redirect (CVE-2023-series)", "CWE-601",
                   "redirect", ["redirect", "open", "url", "http.Redirect"]),
]


def run_command(cmd: List[str], timeout: int = 120) -> Tuple[str, int, int]:
    """Run command, return (stdout, exit_code, elapsed_ms)"""
    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = int((time.time() - start) * 1000)
        return result.stdout + result.stderr, result.returncode, elapsed
    except subprocess.TimeoutExpired:
        elapsed = int((time.time() - start) * 1000)
        return "TIMEOUT", -1, elapsed
    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        return str(e), -1, elapsed


def classify_severity(line: str) -> str:
    """Classify a finding line by severity"""
    upper = line.upper()
    if "CRITICAL" in upper:
        return "CRITICAL"
    if "HIGH" in upper:
        return "HIGH"
    if "MEDIUM" in upper or "WARNING" in upper:
        return "MEDIUM"
    if "LOW" in upper or "INFO" in upper or "NOTE" in upper:
        return "LOW"
    return "UNKNOWN"


def find_cve_in_output(output: str, cve: CVEExpectation) -> bool:
    """Check if tool output mentions the CVE file or pattern keywords"""
    file_basename = cve.file.replace(".go", "")
    # Check if file is referenced
    if cve.file.lower() in output.lower():
        return True
    if file_basename.lower() in output.lower():
        return True
    # Check for at least 2 keyword matches
    matched = sum(1 for kw in cve.expected_rule_keywords if kw.lower() in output.lower())
    return matched >= 2


def count_findings(output: str) -> int:
    """Count distinct findings in output"""
    # Count finding markers
    patterns = [
        r'(?:FINDING|finding|Finding)[\s#]*\d+',
        r'(?:✗|❌|⚠|🔴|🟡|🔵)\s',
        r'(?:CRITICAL|HIGH|MEDIUM|LOW|WARNING)[\s:]+',
        r'ruleid:',
        r'check_id:',
    ]
    # Simpler: count lines that look like findings
    count = 0
    for line in output.split('\n'):
        stripped = line.strip()
        if not stripped:
            continue
        if any(re.search(p, stripped, re.IGNORECASE) for p in patterns):
            count += 1
    # Fallback: count severity lines
    if count == 0:
        count = len(re.findall(r'(CRITICAL|HIGH|MEDIUM|LOW)', output, re.IGNORECASE))
    return count


def count_by_severity(output: str) -> Dict[str, int]:
    """Count findings by severity"""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for line in output.split('\n'):
        sev = classify_severity(line)
        if sev != "UNKNOWN" and any(c in line.upper() for c in ["FINDING", "✗", "❌", "⚠", "🔴", "🟡", "🔵", "ruleid", "check_id"]):
            counts[sev] += 1
    return counts


def run_ironwall(target: str, label: str, extra_args: List[str] = None) -> ToolResult:
    """Run ironwall scan on target"""
    args = extra_args or []
    cmd = [str(IRONWALL), "scan", target, "--offline", "--format", "terminal", "--timeout", "120"] + args
    print(f"  [{label}] Running: {' '.join(cmd)}")
    stdout, exit_code, elapsed = run_command(cmd, timeout=180)
    result = ToolResult(
        tool="Ironwall",
        target=label,
        total_findings=count_findings(stdout),
        findings_by_severity=count_by_severity(stdout),
        raw_output=stdout,
        elapsed_ms=elapsed,
    )
    # Check each CVE
    for cve in CVE_CASES:
        if find_cve_in_output(stdout, cve):
            result.detected_cves.append(cve.file)
        else:
            result.missed_cves.append(cve.file)
    return result


def run_semgrep(target: str, label: str) -> ToolResult:
    """Run semgrep scan on target"""
    cmd = [SEMGREP, "--config=auto", "--no-git-ignore", "--quiet", target]
    print(f"  [{label}] Running: semgrep --config=auto {target}")
    stdout, exit_code, elapsed = run_command(cmd, timeout=180)
    result = ToolResult(
        tool="Semgrep",
        target=label,
        total_findings=count_findings(stdout),
        findings_by_severity=count_by_severity(stdout),
        raw_output=stdout,
        elapsed_ms=elapsed,
    )
    for cve in CVE_CASES:
        if find_cve_in_output(stdout, cve):
            result.detected_cves.append(cve.file)
        else:
            result.missed_cves.append(cve.file)
    return result


def compute_metrics(detected: int, total: int) -> Dict[str, float]:
    """Simple detection metrics"""
    recall = detected / total if total > 0 else 0
    return {
        "recall": round(recall * 100, 1),
        "detected": detected,
        "total": total,
        "missed": total - detected,
    }


def generate_report(cve_results: List[ToolResult], campus_results: List[ToolResult]) -> str:
    """Generate markdown benchmark report"""
    lines = []
    lines.append("# Ironwall vs Semgrep — Real CVE Detection Benchmark")
    lines.append(f"")
    lines.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"**Methodology:** 10 curated Go CVE patterns + 1 real-world Go project (campus_go)")
    lines.append(f"**Ironwall mode:** `--offline` (pure SAST, no AI)")
    lines.append(f"**Semgrep mode:** `--config=auto` (default community + Pro rules)")
    lines.append(f"")

    # CVE Detection Summary
    lines.append("## 1. CVE Detection Rate (10 Real CVE Patterns)")
    lines.append("")
    lines.append("| # | CVE Pattern | CWE | Ironwall | Semgrep |")
    lines.append("|---|------------|-----|----------|---------|")

    ironwall_cve = next((r for r in cve_results if r.tool == "Ironwall"), None)
    semgrep_cve = next((r for r in cve_results if r.tool == "Semgrep"), None)

    for i, cve in enumerate(CVE_CASES, 1):
        iw = "✅" if (ironwall_cve and cve.file in ironwall_cve.detected_cves) else "❌"
        sg = "✅" if (semgrep_cve and cve.file in semgrep_cve.detected_cves) else "❌"
        lines.append(f"| {i} | {cve.cve_pattern} | {cve.cwe} | {iw} | {sg} |")

    lines.append("")
    lines.append("### Detection Rate Summary")
    lines.append("")
    lines.append("| Metric | Ironwall | Semgrep |")
    lines.append("|--------|----------|---------|")

    if ironwall_cve:
        iw_metrics = compute_metrics(len(ironwall_cve.detected_cves), len(CVE_CASES))
        lines.append(f"| **CVE Recall** | **{iw_metrics['recall']}%** ({iw_metrics['detected']}/{iw_metrics['total']}) | — |")
    if semgrep_cve:
        sg_metrics = compute_metrics(len(semgrep_cve.detected_cves), len(CVE_CASES))
        lines.append(f"| **CVE Recall** | — | **{sg_metrics['recall']}%** ({sg_metrics['detected']}/{sg_metrics['total']}) |")

    lines.append("")

    # Finding counts
    lines.append("### Total Findings")
    lines.append("")
    lines.append("| Tool | Total Findings | CRITICAL | HIGH | MEDIUM | LOW |")
    lines.append("|------|---------------|----------|------|--------|-----|")

    for r in cve_results:
        sev = r.findings_by_severity
        lines.append(f"| {r.tool} | {r.total_findings} | {sev.get('CRITICAL', 0)} | {sev.get('HIGH', 0)} | {sev.get('MEDIUM', 0)} | {sev.get('LOW', 0)} |")

    lines.append("")

    # Real-world: campus_go
    lines.append("## 2. Real-World Project: campus_go")
    lines.append("")
    lines.append("| Tool | Total Findings | CRITICAL | HIGH | MEDIUM | LOW | Time (ms) |")
    lines.append("|------|---------------|----------|------|--------|-----|-----------|")

    for r in campus_results:
        sev = r.findings_by_severity
        lines.append(f"| {r.tool} | {r.total_findings} | {sev.get('CRITICAL', 0)} | {sev.get('HIGH', 0)} | {sev.get('MEDIUM', 0)} | {sev.get('LOW', 0)} | {r.elapsed_ms} |")

    lines.append("")

    # Unique findings analysis
    lines.append("## 3. Analysis")
    lines.append("")
    lines.append("### Key Observations")
    lines.append("")
    lines.append("1. **CVE Recall** — How many of the 10 CVE patterns each tool detected")
    lines.append("2. **False Positive Rate** — Fewer findings on focused CVE test cases = higher precision")
    lines.append("3. **Real-World Performance** — campus_go comparison shows production behavior")
    lines.append("4. **Tool Speed** — Elapsed time comparison")
    lines.append("")

    # Missed CVEs detail
    lines.append("### Missed CVEs — Detailed")
    lines.append("")

    for r in cve_results:
        if r.missed_cves:
            lines.append(f"**{r.tool} missed ({len(r.missed_cves)}/{len(CVE_CASES)}):**")
            for missed in r.missed_cves:
                cve = next(c for c in CVE_CASES if c.file == missed)
                lines.append(f"- `{missed}` — {cve.cve_pattern} ({cve.cwe})")
            lines.append("")

    # Recommendations
    lines.append("## 4. Recommendations")
    lines.append("")
    lines.append("### For Ironwall")
    lines.append("- Add rules for any missed CVE categories")
    lines.append("- Consider reducing false positives on LOW severity findings")
    lines.append("- Add Go-specific semgrep rule equivalents")
    lines.append("")
    lines.append("### For Benchmark")
    lines.append("- Expand to full CVEfixes DB for statistical significance (needs ~20GB disk)")
    lines.append("- Add OWASP Benchmark for web-specific CVEs")
    lines.append("- Add time-to-fix measurement (how long to understand + fix each finding)")
    lines.append("- Add CodeQL as third baseline for comparison")
    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by benchmark/run_benchmark.py on {time.strftime('%Y-%m-%d %H:%M:%S')}*")

    return "\n".join(lines)


def main():
    print("=" * 70)
    print("IRONWALL vs SEMGREP — A/B BENCHMARK")
    print("=" * 70)

    # Verify tools
    if not IRONWALL.exists():
        print(f"ERROR: ironwall not found at {IRONWALL}")
        sys.exit(1)

    try:
        subprocess.run([SEMGREP, "--version"], capture_output=True, timeout=10)
    except Exception:
        print("ERROR: semgrep not found")
        sys.exit(1)

    if not CVE_CASES_DIR.exists():
        print(f"ERROR: CVE cases dir not found at {CVE_CASES_DIR}")
        sys.exit(1)

    print(f"\nIronwall: {IRONWALL}")
    print(f"Semgrep: {SEMGREP}")
    print(f"CVE cases: {CVE_CASES_DIR} ({len(list(CVE_CASES_DIR.glob('*.go')))} files)")
    print(f"Real-world: {CAMPUS_GO_DIR}")
    print()

    cve_results: List[ToolResult] = []
    campus_results: List[ToolResult] = []

    # Phase 1: CVE Cases
    print("─" * 70)
    print("PHASE 1: CVE Pattern Detection (10 test cases)")
    print("─" * 70)

    print("\n>>> Running Ironwall on CVE cases...")
    iw_cve = run_ironwall(str(CVE_CASES_DIR), "CVE Cases (Ironwall)")
    cve_results.append(iw_cve)
    print(f"    Findings: {iw_cve.total_findings}, Detected: {len(iw_cve.detected_cves)}/{len(CVE_CASES)}, Time: {iw_cve.elapsed_ms}ms")

    print("\n>>> Running Semgrep on CVE cases...")
    sg_cve = run_semgrep(str(CVE_CASES_DIR), "CVE Cases (Semgrep)")
    cve_results.append(sg_cve)
    print(f"    Findings: {sg_cve.total_findings}, Detected: {len(sg_cve.detected_cves)}/{len(CVE_CASES)}, Time: {sg_cve.elapsed_ms}ms")

    # Phase 2: Real-world project
    print("\n" + "─" * 70)
    print("PHASE 2: Real-World Project (campus_go)")
    print("─" * 70)

    if CAMPUS_GO_DIR.exists():
        print("\n>>> Running Ironwall on campus_go...")
        iw_campus = run_ironwall(str(CAMPUS_GO_DIR), "campus_go (Ironwall)")
        campus_results.append(iw_campus)
        print(f"    Findings: {iw_campus.total_findings}, Time: {iw_campus.elapsed_ms}ms")

        print("\n>>> Running Semgrep on campus_go...")
        sg_campus = run_semgrep(str(CAMPUS_GO_DIR), "campus_go (Semgrep)")
        campus_results.append(sg_campus)
        print(f"    Findings: {sg_campus.total_findings}, Time: {sg_campus.elapsed_ms}ms")
    else:
        print(f"    SKIP: {CAMPUS_GO_DIR} not found")

    # Generate report
    print("\n" + "─" * 70)
    print("GENERATING REPORT")
    print("─" * 70)

    report = generate_report(cve_results, campus_results)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"\nReport saved to: {REPORT_FILE}")

    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    for r in cve_results:
        recall = len(r.detected_cves) / len(CVE_CASES) * 100
        print(f"\n{r.tool} (CVE Cases):")
        print(f"  Recall: {recall:.0f}% ({len(r.detected_cves)}/{len(CVE_CASES)})")
        print(f"  Missed: {', '.join(r.missed_cves) if r.missed_cves else 'None'}")
        print(f"  Findings: {r.total_findings}")
        print(f"  Time: {r.elapsed_ms}ms")

    for r in campus_results:
        print(f"\n{r.tool} (campus_go):")
        print(f"  Findings: {r.total_findings}")
        print(f"  Time: {r.elapsed_ms}ms")

    # Also save raw outputs for inspection
    raw_dir = BENCHMARK_DIR / "raw_outputs"
    raw_dir.mkdir(exist_ok=True)
    for r in cve_results + campus_results:
        fname = f"{r.tool.lower().replace(' ', '_')}_{r.target.lower().replace(' ', '_')}.txt"
        (raw_dir / fname).write_text(r.raw_output, encoding="utf-8")

    print(f"\nRaw outputs saved to: {raw_dir}")
    print("Done.")


if __name__ == "__main__":
    main()
