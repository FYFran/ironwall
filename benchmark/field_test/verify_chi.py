"""Manual verification of chi's 20 non-test findings."""
import json, os

with open('iw_chi_v3.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

findings = [f for f in data.get('findings', [])
            if '[TEST/EXAMPLE]' not in f.get('title', '')]

# Group by file
from collections import defaultdict
by_file = defaultdict(list)
for f in findings:
    fp = f.get('file_path', '?')
    by_file[fp].append(f)

print(f"Total non-test findings: {len(findings)}")
print(f"Unique files: {len(by_file)}")
print()

for fp, fds in sorted(by_file.items()):
    print(f"FILE: {fp} ({len(fds)} findings)")
    for f in fds:
        title = f.get('title', '?')
        sev = f.get('severity', '?')
        cat = f.get('category', '?')
        code = (f.get('code_snippet', '') or '')[:120]
        line = f.get('line_number', '?')
        desc = (f.get('description', '') or '')[:150]
        print(f"  L{line} [{sev}] [{cat}] {title[:100]}")
        print(f"       Code: {code.strip()}")
        print(f"       Desc: {desc.strip()[:120]}")
        print()
    print()
