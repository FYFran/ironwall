"""Analyze field test results: categorize findings, estimate precision."""
import json, os
from collections import defaultdict, Counter

BASE = os.path.dirname(__file__)
PROJECTS = ["jwt", "chi", "websocket", "mysql", "cli"]

print("=" * 70)
print("FIELD TEST ANALYSIS — 5 Go Projects")
print("=" * 70)

for proj in PROJECTS:
    print(f"\n{'─'*60}")
    print(f"  {proj}")
    print(f"{'─'*60}")

    # Ironwall
    iw_file = os.path.join(BASE, f"iw_{proj}.json")
    iw_by_category = Counter()
    iw_by_step = Counter()
    iw_by_severity = Counter()
    iw_sample = []

    if os.path.exists(iw_file):
        with open(iw_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        findings = data.get('findings', [])
        for fd in findings:
            cat = fd.get('category', 'unknown')
            step = fd.get('step', 0)
            sev = fd.get('severity', 'unknown')
            iw_by_category[cat] += 1
            iw_by_step[f"step{step}"] += 1
            iw_by_severity[str(sev)] += 1
            if len(iw_sample) < 5:
                iw_sample.append(f"  [{sev}] {fd.get('title', '?')[:100]} | {fd.get('file_path', '?')}")

        print(f"  Ironwall: {len(findings)} findings")
        print(f"    By category: {dict(iw_by_category.most_common(8))}")
        print(f"    By step: {dict(iw_by_step)}")
        print(f"    By severity: {dict(iw_by_severity)}")
        print(f"    Sample:")
        for s in iw_sample:
            print(s)

    # Semgrep
    sg_file = os.path.join(BASE, f"sg_{proj}.json")
    sg_by_rule = Counter()
    sg_sample = []
    if os.path.exists(sg_file):
        with open(sg_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        results = data.get('results', [])
        for r in results:
            sg_by_rule[r.get('check_id', '?')] += 1
            if len(sg_sample) < 5:
                sg_sample.append(f"  [{r.get('extra',{}).get('severity','?')}] {r.get('check_id','?')} | {r.get('path','?')}:{r.get('start',{}).get('line','?')}")

        print(f"  Semgrep: {len(results)} findings")
        print(f"    By rule: {dict(sg_by_rule.most_common(8))}")
        print(f"    Sample:")
        for s in sg_sample:
            print(s)

# Overall summary
print(f"\n{'='*70}")
print("OVERALL SUMMARY")
print(f"{'='*70}")
print(f"{'Project':<12} {'IW':>6} {'SG':>6} {'IW cats':>30}")
for proj in PROJECTS:
    iw_file = os.path.join(BASE, f"iw_{proj}.json")
    sg_file = os.path.join(BASE, f"sg_{proj}.json")
    iw_n = sg_n = 0
    iw_cats = ""
    if os.path.exists(iw_file):
        with open(iw_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        findings = data.get('findings', [])
        iw_n = len(findings)
        cats = Counter(fd.get('category', '?') for fd in findings)
        iw_cats = ", ".join(f"{k}:{v}" for k,v in cats.most_common(4))
    if os.path.exists(sg_file):
        with open(sg_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        sg_n = len(data.get('results', []))
    print(f"{proj:<12} {iw_n:>6} {sg_n:>6} {iw_cats:>30}")

# Precision estimation: auto-classify by category
print(f"\n{'='*70}")
print("PRECISION ESTIMATE (by category)")
print(f"{'='*70}")
category_likely_tp = {
    'secret-detected': 'high',        # gitleaks is reliable
    'hardcoded-secret': 'high',       # custom patterns match well
    'hardcoded-credentials': 'high',
    'security': 'medium',             # semgrep/gosec SAST — needs review
    'missing-control': 'medium',      # endpoint analysis — needs review
    'insecure-configuration': 'medium',
    'supply-chain': 'low',            # often informational
    'sbom': 'low',                    # purely informational
    'cors-misconfiguration': 'high',
    'debug-mode-enabled': 'high',
    'missing-security-header': 'medium',
    'csrf': 'high',
}

all_findings = []
for proj in PROJECTS:
    iw_file = os.path.join(BASE, f"iw_{proj}.json")
    if os.path.exists(iw_file):
        with open(iw_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for fd in data.get('findings', []):
            fd['_project'] = proj
            all_findings.append(fd)

total = len(all_findings)
high_tp = sum(1 for f in all_findings if category_likely_tp.get(f.get('category',''), 'medium') == 'high')
medium_tp = sum(1 for f in all_findings if category_likely_tp.get(f.get('category',''), 'medium') == 'medium')
low_tp = sum(1 for f in all_findings if category_likely_tp.get(f.get('category',''), 'medium') == 'low')

print(f"Total findings: {total}")
print(f"  High confidence TP:  {high_tp} ({high_tp/total*100:.0f}%) — secrets, credentials, debug, CORS")
print(f"  Medium (needs check): {medium_tp} ({medium_tp/total*100:.0f}%) — SAST, endpoints, config")
print(f"  Low (informational): {low_tp} ({low_tp/total*100:.0f}%) — SBOM, supply chain")
print(f"  Estimated TP range:  {high_tp}–{high_tp+medium_tp} ({high_tp/total*100:.0f}%–{(high_tp+medium_tp)/total*100:.0f}%)")
