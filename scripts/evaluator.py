"""
OWASP Python Benchmark evaluator for Ironwall.

Usage:
  python evaluator.py \\
    --ground-truth testdata/BenchmarkPython/expectedresults-0.1.csv \\
    --findings ironwall-report-xxx.json \\
    --output report.json

Supports two modes:
  --mode strict   Per-finding CWE match (primary)
  --mode relaxed  Per-file match (auxiliary, any finding = TP)
"""

import argparse, csv, json, sys, os
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

# ── CWE mapping ──────────────────────────────────────────────
# benchmark_category → CWE number
CATEGORY_TO_CWE = {
    "pathtraver":    "22",
    "cmdi":          "78",
    "sqli":          "89",
    "xss":           "79",
    "hash":          "328",
    "weakrand":      "330",
    "xpathi":        "643",
    "deserialization": "502",
    "codeinj":       "94",
    "securecookie":  "614",
    "trustbound":    "501",
    "redirect":      "601",
    "ldapi":         "90",
    "xxe":           "611",
}

# ironwall_category → CWE number (for matching)
IRONWALL_CATEGORY_TO_CWE = {
    "sql-injection":          "89",
    "command-injection":      "78",
    "cross-site-scripting":   "79",
    "xss":                    "79",
    "path-traversal":         "22",
    "weak-cryptography":      "327",
    "weak-hash":              "328",
    "insecure-deserialization":"502",
    "xxe":                    "611",
    "ssrf":                   "918",
    "insecure-redirect":      "601",
    "ldap-injection":         "90",
    "xpath-injection":        "643",
    "code-injection":         "94",
    "hardcoded-secret":       "798",
    "hardcoded-credentials":  "798",
    "secret-detected":        "798",
    "missing-auth":           "306",
    "injection":              None,  # too generic, skip strict match
}


def parse_ground_truth(csv_path: str) -> Dict[str, dict]:
    """
    Parse expectedresults CSV.
    Returns: {filename: {vulnerable: bool, cwe: str, category: str}}
    """
    gt = {}
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)  # skip header
        for row in reader:
            if len(row) < 4:
                continue
            filename = row[0].strip() + ".py"  # CSV lacks .py extension
            category = row[1].strip()
            vulnerable = row[2].strip().lower() == "true"
            cwe = row[3].strip()
            gt[filename] = {
                "vulnerable": vulnerable,
                "cwe": cwe,
                "category": category,
            }
    return gt


def normalize_cwe(raw: str) -> Optional[str]:
    """Normalize CWE strings to bare number: 'CWE-89'→'89', '89'→'89'."""
    if not raw:
        return None
    raw = raw.strip()
    # Handle "CWE-89: ..." format
    if raw.upper().startswith("CWE-"):
        raw = raw[4:]
    # Take only digits before any non-digit
    digits = ""
    for ch in raw:
        if ch.isdigit():
            digits += ch
        else:
            break
    return digits if digits else None


def extract_basename(path: str) -> str:
    """Extract filename from any path format."""
    return os.path.basename(path.replace("\\", "/"))


def load_ironwall_findings(json_path: str) -> List[dict]:
    """Load ironwall JSON output, normalize to list of finding dicts."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Handle both formats: {findings: [...]} and {results: {findings: [...]}}
    if "findings" in data:
        raw = data["findings"]
    elif "results" in data and "findings" in data["results"]:
        raw = data["results"]["findings"]
    else:
        print(f"WARNING: unexpected JSON structure, keys: {list(data.keys())}")
        return []

    # Normalize each finding
    findings = []
    for f in raw:
        file_path = f.get("file_path") or f.get("file") or f.get("path", "")
        cwe_raw = f.get("cwe", "") or f.get("CWE", "")
        category = f.get("category", "")

        # Try to infer CWE from category if CWE field is empty
        if not cwe_raw or not normalize_cwe(cwe_raw):
            cwe_raw = IRONWALL_CATEGORY_TO_CWE.get(category, "")

        findings.append({
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "file": extract_basename(file_path),
            "line": int(f.get("line") or f.get("line_number") or 0),
            "cwe": normalize_cwe(str(cwe_raw)),
            "category": str(category),
            "severity": str(f.get("severity", "")),
        })
    return findings


def load_semgrep_findings(json_path: str) -> List[dict]:
    """Load semgrep JSON output, normalize."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for r in data.get("results", []):
        cwe_list = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwe = ""
        if cwe_list:
            cwe = normalize_cwe(cwe_list[0])

        findings.append({
            "id": r.get("check_id", ""),
            "title": r.get("extra", {}).get("message", ""),
            "file": os.path.basename(r.get("path", "")),
            "line": int(r.get("start", {}).get("line", 0)),
            "cwe": cwe,
            "category": r.get("extra", {}).get("metadata", {}).get("category", ""),
            "severity": r.get("extra", {}).get("severity", ""),
        })
    return findings


def evaluate_strict(gt: dict, findings: List[dict]) -> dict:
    """
    Strict matching: finding's CWE must match expected CWE for the file.
    One TP per correct file-CWE pair. Multiple findings for same file-CWE count as 1 TP.
    """
    # Build set of (filename, cwe) pairs that were correctly identified
    found_pairs = set()
    all_fps = []

    for f in findings:
        fname = f["file"]
        fcwe = f["cwe"]
        if fname not in gt:
            continue  # finding in file not in benchmark

        expected = gt[fname]
        if expected["vulnerable"] and fcwe and fcwe == expected["cwe"]:
            found_pairs.add((fname, fcwe))
        else:
            all_fps.append(f)

    tp = len(found_pairs)
    fp = len(all_fps)

    # Count FN: vulnerable files where ironwall didn't report the expected CWE
    fn = 0
    for fname, info in gt.items():
        if info["vulnerable"]:
            if (fname, info["cwe"]) not in found_pairs:
                fn += 1

    # TN: safe files with no ironwall findings
    files_with_findings = set(f["file"] for f in findings)
    tn = sum(1 for fname, info in gt.items()
             if not info["vulnerable"] and fname not in files_with_findings)

    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def evaluate_relaxed(gt: dict, findings: List[dict]) -> dict:
    """
    Relaxed matching: any finding in a vulnerable file counts as TP.
    """
    files_with_findings = set(f["file"] for f in findings)

    tp, fp, fn, tn = 0, 0, 0, 0
    for fname, info in gt.items():
        has_finding = fname in files_with_findings
        if info["vulnerable"]:
            if has_finding:
                tp += 1
            else:
                fn += 1
        else:
            if has_finding:
                fp += 1
            else:
                tn += 1

    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def compute_metrics(counts: dict) -> dict:
    """Compute all metrics from TP/FP/FN/TN counts."""
    tp, fp, fn, tn = counts["tp"], counts["fp"], counts["fn"], counts["tn"]
    total = tp + fp + fn + tn

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    f3   = 10 * prec * rec / (9 * prec + rec) if (9 * prec + rec) > 0 else 0.0
    acc  = (tp + tn) / total if total > 0 else 0.0

    # MCC
    denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc = ((tp * tn) - (fp * fn)) / (denom ** 0.5) if denom > 0 else 0.0

    return {
        "precision": round(prec, 4),
        "recall":    round(rec, 4),
        "f1":        round(f1, 4),
        "f3":        round(f3, 4),
        "accuracy":  round(acc, 4),
        "mcc":       round(mcc, 4),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "total": total,
    }


def per_cwe_breakdown(gt: dict, findings: List[dict]) -> dict:
    """Compute per-CWE strict metrics."""
    cwe_set = set(info["cwe"] for info in gt.values())
    breakdown = {}
    for cwe in sorted(cwe_set):
        # Filter GT to this CWE
        gt_cwe = {fn: info for fn, info in gt.items() if info["cwe"] == cwe}
        # Filter findings to this CWE
        f_cwe = [f for f in findings if f["cwe"] == cwe]
        counts = evaluate_strict(gt_cwe, f_cwe)
        breakdown[cwe] = compute_metrics(counts)
        breakdown[cwe]["category"] = next(
            (info["category"] for info in gt.values() if info["cwe"] == cwe), "unknown"
        )
    return breakdown


def ai_suppression_rate(noai_findings: List[dict], ai_findings: List[dict], gt: dict) -> dict:
    """
    Compute AI Suppression Rate.
    Finds findings present in no-AI but absent in AI run.
    Checks if suppressed findings were on vulnerable files.
    """
    noai_keys = set()
    for f in noai_findings:
        noai_keys.add((f["file"], f.get("line", 0), f.get("category", "")))

    ai_keys = set()
    for f in ai_findings:
        ai_keys.add((f["file"], f.get("line", 0), f.get("category", "")))

    suppressed = noai_keys - ai_keys

    tp_suppressed = 0  # AI killed a real finding = BAD
    fp_suppressed = 0  # AI killed a false finding = GOOD
    unknown = 0

    for key in suppressed:
        fname = key[0]
        if fname in gt:
            if gt[fname]["vulnerable"]:
                tp_suppressed += 1
            else:
                fp_suppressed += 1
        else:
            unknown += 1

    total_noai = len(noai_keys)
    rate = tp_suppressed / total_noai if total_noai > 0 else 0.0

    return {
        "ai_suppression_count": tp_suppressed,
        "ai_suppression_rate": round(rate, 4),
        "fp_correctly_suppressed": fp_suppressed,
        "unknown_suppressed": unknown,
        "total_noai_findings": total_noai,
        "total_ai_findings": len(ai_keys),
        "total_suppressed": len(suppressed),
    }


def print_report(metrics: dict, label: str = "OVERALL"):
    """Print metrics table."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  TP={metrics['tp']}  FP={metrics['fp']}  FN={metrics['fn']}  TN={metrics['tn']}")
    print(f"  Precision:  {metrics['precision']:.4f}")
    print(f"  Recall:     {metrics['recall']:.4f}")
    print(f"  F1:         {metrics['f1']:.4f}")
    print(f"  F3:         {metrics['f3']:.4f}")
    print(f"  Accuracy:   {metrics['accuracy']:.4f}")
    print(f"  MCC:        {metrics['mcc']:.4f}")


def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark Evaluator")
    parser.add_argument("--ground-truth", required=True, help="Path to expectedresults CSV")
    parser.add_argument("--findings", required=True, help="Path to ironwall JSON output")
    parser.add_argument("--semgrep", help="Path to semgrep JSON output (optional)")
    parser.add_argument("--noai-findings", help="Path to ironwall no-AI JSON (for suppression rate)")
    parser.add_argument("--output", default="evaluation_report.json", help="Output JSON path")
    parser.add_argument("--mode", choices=["strict", "relaxed", "both"], default="both")
    args = parser.parse_args()

    # Load ground truth
    gt = parse_ground_truth(args.ground_truth)
    vuln_count = sum(1 for v in gt.values() if v["vulnerable"])
    safe_count = sum(1 for v in gt.values() if not v["vulnerable"])
    print(f"Ground truth: {len(gt)} files ({vuln_count} vulnerable, {safe_count} safe)")

    # Load ironwall findings
    findings = load_ironwall_findings(args.findings)
    print(f"Ironwall findings: {len(findings)}")

    report = {
        "ground_truth": {"total": len(gt), "vulnerable": vuln_count, "safe": safe_count},
        "ironwall_findings_count": len(findings),
    }

    # Strict evaluation
    if args.mode in ("strict", "both"):
        strict_counts = evaluate_strict(gt, findings)
        strict_metrics = compute_metrics(strict_counts)
        print_report(strict_metrics, "STRICT (per-finding CWE match)")
        report["strict"] = strict_metrics

        # Per-CWE breakdown
        report["per_cwe"] = per_cwe_breakdown(gt, findings)
        print(f"\n{'─'*60}")
        print(f"  Per-CWE Breakdown (strict)")
        print(f"{'─'*60}")
        for cwe, m in report["per_cwe"].items():
            cat = m.pop("category", "?")
            print(f"  CWE-{cwe} ({cat:12s}): P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} F3={m['f3']:.3f}")

    # Relaxed evaluation
    if args.mode in ("relaxed", "both"):
        relaxed_counts = evaluate_relaxed(gt, findings)
        relaxed_metrics = compute_metrics(relaxed_counts)
        print_report(relaxed_metrics, "RELAXED (per-file match)")
        report["relaxed"] = relaxed_metrics

    # Semgrep comparison
    if args.semgrep and os.path.exists(args.semgrep):
        semgrep_findings = load_semgrep_findings(args.semgrep)
        print(f"\nSemgrep findings: {len(semgrep_findings)}")
        semgrep_strict = evaluate_strict(gt, semgrep_findings)
        semgrep_metrics = compute_metrics(semgrep_strict)
        print_report(semgrep_metrics, "SEMGREP (strict)")
        report["semgrep"] = semgrep_metrics

    # AI Suppression Rate
    if args.noai_findings and os.path.exists(args.noai_findings):
        noai_findings = load_ironwall_findings(args.noai_findings)
        print(f"\nNo-AI findings: {len(noai_findings)}")
        suppression = ai_suppression_rate(noai_findings, findings, gt)
        report["ai_suppression"] = suppression
        print(f"\n{'─'*60}")
        print(f"  AI Suppression Analysis")
        print(f"{'─'*60}")
        print(f"  Total no-AI findings:    {suppression['total_noai_findings']}")
        print(f"  Total AI findings:       {suppression['total_ai_findings']}")
        print(f"  Total suppressed:        {suppression['total_suppressed']}")
        print(f"  TP KILLED by AI (BAD):   {suppression['ai_suppression_count']}")
        print(f"  FP killed by AI (GOOD):  {suppression['fp_correctly_suppressed']}")
        print(f"  Unknown suppressed:      {suppression['unknown_suppressed']}")
        print(f"  AI Suppression Rate:     {suppression['ai_suppression_rate']:.4f}")

    # Save report
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Report saved: {args.output}")

    # Summary line
    if "strict" in report:
        m = report["strict"]
        print(f"\n=== FINAL: P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f} F3={m['f3']:.4f} MCC={m['mcc']:.4f}")


if __name__ == "__main__":
    main()
