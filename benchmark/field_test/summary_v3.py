"""Compare v1 (before fix) vs v3 (after fix) across all 5 projects."""
import json, os
from collections import Counter

BASE = os.path.dirname(__file__)
PROJECTS = ["jwt", "chi", "websocket", "mysql", "cli"]

v1_data = {}
batch_file = os.path.join(BASE, 'batch_results.json')
if os.path.exists(batch_file):
    with open(batch_file, 'r', encoding='utf-8') as f:
        v1_data = json.load(f)

print("=" * 80)
print("BEFORE vs AFTER - Test/Example Exclusion Fix")
print("=" * 80)
header = f"{'Project':<12} {'V1 Total':>10} {'V3 Total':>10} {'V3 Tagged':>10} {'V3 Real':>10} {'Noise Cut':>10}"
print(header)
print("-" * len(header))

totals = {'v1': 0, 'v3': 0, 'tagged': 0, 'real': 0}

rows = []
for proj in PROJECTS:
    v3_file = os.path.join(BASE, 'iw_' + proj + '_v3.json')
    if not os.path.exists(v3_file):
        continue
    with open(v3_file, 'r', encoding='utf-8') as f:
        v3_data = json.load(f)
    v3_findings = v3_data.get('findings', [])
    v3_total = len(v3_findings)
    v3_tagged = sum(1 for f in v3_findings if '[TEST/EXAMPLE]' in f.get('title', ''))
    v3_real = v3_total - v3_tagged
    v1_total = v1_data.get(proj, {}).get('ironwall', {}).get('findings', 0)
    cut_pct = (1 - v3_real / v1_total) * 100 if v1_total > 0 else 0

    row = f"{proj:<12} {v1_total:>10} {v3_total:>10} {v3_tagged:>10} {v3_real:>10} {cut_pct:>9.0f}%"
    print(row)
    rows.append((proj, v3_real, v3_findings))

    totals['v1'] += v1_total
    totals['v3'] += v3_total
    totals['tagged'] += v3_tagged
    totals['real'] += v3_real

overall_cut = (1 - totals['real'] / totals['v1']) * 100 if totals['v1'] > 0 else 0
print("-" * len(header))
print(f"{'TOTAL':<12} {totals['v1']:>10} {totals['v3']:>10} {totals['tagged']:>10} {totals['real']:>10} {overall_cut:>9.0f}%")

# Real findings breakdown
print("\n" + "=" * 80)
print("REAL FINDINGS (non-test) BY PROJECT")
print("=" * 80)

for proj, count, findings in rows:
    real = [f for f in findings if '[TEST/EXAMPLE]' not in f.get('title', '')]
    if not real:
        continue
    by_cat = Counter(f.get('category', '?') for f in real)
    print("\n  " + proj + " (" + str(len(real)) + " findings):")
    for cat, cnt in by_cat.most_common(6):
        print("    " + cat + ": " + str(cnt))
    for f in real[:3]:
        title = f.get('title', '?')[:90]
        fp = f.get('file_path', '?')[:60]
        sev = str(f.get('severity', '?'))
        print("    ex: [" + sev + "] " + title)
        print("        " + fp)
