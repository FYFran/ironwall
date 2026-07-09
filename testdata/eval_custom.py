"""Evaluate custom scanner CWE-501/CWE-90 detection against ground truth."""
import csv, json, os, subprocess, sys

# Run custom scanner
result = subprocess.run([
    sys.executable,
    r'f:\ClaudeFiles\_research\ironwall\internal\scanner\bandit_plugins\ironwall_custom_scanner.py',
    r'f:\ClaudeFiles\_research\ironwall\testdata\focused_cwe'
], capture_output=True, text=True)

findings = json.loads(result.stdout) if result.stdout.strip() else []
print(f"Custom scanner raw findings: {len(findings)}")

# Load ground truth
gt = {}
with open(r'f:\ClaudeFiles\_research\ironwall\testdata\BenchmarkPython\expectedresults-0.1.csv', 'r') as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        if row[1] in ('trustbound', 'ldapi'):
            gt[row[0]] = {
                'cwe': 'CWE-501' if row[1] == 'trustbound' else 'CWE-90',
                'vuln': row[2] == 'true'
            }

# Match findings to ground truth
tp_501 = fp_501 = fn_501 = tp_90 = fp_90 = fn_90 = 0
matched_files = set()
fn_501_list = []
fn_90_list = []
fp_501_list = []
fp_90_list = []

for f in findings:
    basename = os.path.basename(f['filename']).replace('.py', '')
    test_id = f['test_id']
    expected_cwe = 'CWE-501' if test_id == 'B901' else 'CWE-90'

    if basename not in gt:
        continue

    if gt[basename]['cwe'] == expected_cwe and gt[basename]['vuln']:
        if test_id == 'B901':
            tp_501 += 1
        else:
            tp_90 += 1
        matched_files.add(basename)
    elif gt[basename]['cwe'] == expected_cwe and not gt[basename]['vuln']:
        if test_id == 'B901':
            fp_501 += 1
            fp_501_list.append(basename)
        else:
            fp_90 += 1
            fp_90_list.append(basename)
        matched_files.add(basename)

# Find FNs
for name, info in gt.items():
    if info['vuln'] and name not in matched_files:
        if info['cwe'] == 'CWE-501':
            fn_501 += 1
            fn_501_list.append(name)
        else:
            fn_90 += 1
            fn_90_list.append(name)

def calc_metrics(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    f3 = 10 * p * r / (9 * p + r) if (9 * p + r) > 0 else 0
    return p, r, f1, f3

print("\n=== CWE-501 Trust Boundary (GT: 18 true / 19 false) ===")
p, r, f1, f3 = calc_metrics(tp_501, fp_501, fn_501)
print(f"TP={tp_501} FP={fp_501} FN={fn_501}")
print(f"Precision={p:.3f} Recall={r:.3f} F1={f1:.3f} F3={f3:.3f}")
if fn_501_list:
    print(f"FN (missed): {fn_501_list[:10]}")
if fp_501_list:
    print(f"FP (false alarm): {fp_501_list[:10]}")

print(f"\n=== CWE-90 LDAP Injection (GT: 16 true / 13 false) ===")
p, r, f1, f3 = calc_metrics(tp_90, fp_90, fn_90)
print(f"TP={tp_90} FP={fp_90} FN={fn_90}")
print(f"Precision={p:.3f} Recall={r:.3f} F1={f1:.3f} F3={f3:.3f}")
if fn_90_list:
    print(f"FN (missed): {fn_90_list[:10]}")
if fp_90_list:
    print(f"FP (false alarm): {fp_90_list[:10]}")

# Combined
print(f"\n=== Combined ===")
total_tp = tp_501 + tp_90
total_fp = fp_501 + fp_90
total_fn = fn_501 + fn_90
p, r, f1, f3 = calc_metrics(total_tp, total_fp, total_fn)
print(f"Total GT: 34 true / 32 false")
print(f"TP={total_tp} FP={total_fp} FN={total_fn}")
print(f"Precision={p:.3f} Recall={r:.3f} F1={f1:.3f} F3={f3:.3f}")
