import json
from collections import Counter

for proj, label in [('iw_chi_v3.json', 'chi v3'), ('iw_jwt_v3.json', 'jwt v3')]:
    with open(proj, 'r', encoding='utf-8') as f:
        data = json.load(f)
    findings = data.get('findings', [])

    by_cat = Counter()
    by_step = Counter()
    sev_count = Counter()
    test_count = 0
    for fd in findings:
        by_cat[fd.get('category','?')] += 1
        by_step[str(fd.get('step',0))] += 1
        sev_count[str(fd.get('severity','?'))] += 1
        title = fd.get('title','')
        if '[TEST/EXAMPLE]' in title:
            test_count += 1

    print(f'--- {label}: {len(findings)} findings ---')
    print(f'  [TEST/EXAMPLE] tagged: {test_count}')
    print(f'  By category: {dict(by_cat.most_common(8))}')
    print(f'  By step: {dict(by_step)}')
    print(f'  By severity: {dict(sev_count)}')

    non_test = [f for f in findings if '[TEST/EXAMPLE]' not in f.get('title','')]
    print(f'  Non-test findings: {len(non_test)}')
    for f in non_test[:8]:
        title = f.get('title','?')[:100]
        fp = f.get('file_path','?')
        sev = f.get('severity','?')
        print(f'    [{sev}] {title} | {fp}')
    print()
