"""Full OWASP Python Benchmark evaluation for Ironwall."""
import json, csv, os
from collections import defaultdict

# Load ground truth
gt = {}
with open(r'f:\ClaudeFiles\_research\ironwall\testdata\BenchmarkPython\expectedresults-0.1.csv', 'r') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        name = row[0]
        gt[name] = {
            'category': row[1],
            'vuln': row[2] == 'true',
            'cwe': row[3],
        }

# Load ironwall findings
with open(r'f:\ClaudeFiles\_research\ironwall\ironwall-report-testcode.json', 'r', encoding='utf-8') as f:
    report = json.load(f)

findings = report.get('findings', [])

# Map findings to benchmark test names
def extract_test_name(filepath):
    basename = os.path.basename(filepath)
    return os.path.splitext(basename)[0]

# Per-CWE tracking
cwe_stats = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0})

# Track which test files were flagged
flagged_files = defaultdict(set)  # test_name → {cwe, ...}
for finding in findings:
    cwe = finding.get('cwe', '')
    filename = finding.get('file', '')
    test_name = extract_test_name(filename)
    if test_name in gt:
        flagged_files[test_name].add(cwe)

# Match findings to ground truth
for test_name, info in gt.items():
    cwe = f"CWE-{info['cwe']}"
    flagged = test_name in flagged_files

    if info['vuln']:
        if flagged:
            cwe_stats[cwe]['tp'] += 1
        else:
            cwe_stats[cwe]['fn'] += 1
    else:
        if flagged:
            cwe_stats[cwe]['fp'] += 1
        else:
            cwe_stats[cwe]['tn'] += 1

# Compute metrics
def metrics(tp, fp, fn, tn):
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    f3 = 10 * p * r / (9 * p + r) if (9 * p + r) > 0 else 0
    acc = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) > 0 else 0
    return p, r, f1, f3, acc

print("=== Ironwall v0.5.0 — OWASP Python Benchmark Results ===\n")
print(f"{'CWE':<12} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Prec':>7} {'Recall':>7} {'F1':>7} {'F3':>7} {'Acc':>7}")
print("-" * 80)

total_tp = total_fp = total_fn = total_tn = 0
priority_cwes = ['CWE-501', 'CWE-90', 'CWE-89', 'CWE-78', 'CWE-79', 'CWE-22',
                 'CWE-327', 'CWE-328', 'CWE-330', 'CWE-502', 'CWE-601',
                 'CWE-611', 'CWE-614', 'CWE-643', 'CWE-94']

for cwe in sorted(cwe_stats.keys()):
    s = cwe_stats[cwe]
    p, r, f1, f3, acc = metrics(s['tp'], s['fp'], s['fn'], s['tn'])
    total_tp += s['tp']; total_fp += s['fp']; total_fn += s['fn']; total_tn += s['tn']
    marker = "★" if cwe in ('CWE-501', 'CWE-90') else " "
    print(f"{marker}{cwe:<11} {s['tp']:>4} {s['fp']:>4} {s['fn']:>4} {s['tn']:>4} {p:>7.3f} {r:>7.3f} {f1:>7.3f} {f3:>7.3f} {acc:>7.3f}")

print("-" * 80)
p, r, f1, f3, acc = metrics(total_tp, total_fp, total_fn, total_tn)
print(f"{'TOTAL':<12} {total_tp:>4} {total_fp:>4} {total_fn:>4} {total_tn:>4} {p:>7.3f} {r:>7.3f} {f1:>7.3f} {f3:>7.3f} {acc:>7.3f}")

# CWE coverage
covered = {s for s in cwe_stats if cwe_stats[s]['tp'] > 0}
print(f"\nCWE Coverage: {len(covered)}/15 CWE detected")
print(f"★ New in v0.5.0: CWE-501={cwe_stats['CWE-501']['tp']>0}, CWE-90={cwe_stats['CWE-90']['tp']>0}")

# Compare vs previous
print(f"\n=== Comparison: v0.5.0-alpha3 vs v0.5.0 ===")
print(f"CWE-501: was F1=0.000 → now F1={metrics(**{k:v for k,v in cwe_stats['CWE-501'].items()})[2]:.3f}")
print(f"CWE-90:  was F1=0.000 → now F1={metrics(**{k:v for k,v in cwe_stats['CWE-90'].items()})[2]:.3f}")
