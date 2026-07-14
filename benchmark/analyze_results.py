"""Quick analysis of semgrep + ironwall results"""
import json

# Semgrep on CVE cases
with open('semgrep_cve.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
results = data.get('results', [])
print(f'Semgrep on CVE cases: {len(results)} findings')

# By file
from collections import Counter
by_file = Counter()
for r in results:
    fname = r['path'].replace('cve_cases\\', '').replace('cve_cases/', '')
    by_file[fname] += 1

print('By file:')
for fname, count in sorted(by_file.items()):
    print(f'  {fname}: {count}')

# Semgrep on campus_go
with open('semgrep_campus.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
results = data.get('results', [])
print(f'\nSemgrep on campus_go: {len(results)} findings')
for r in results:
    print(f'  {r["check_id"]}: {r["path"]}:{r["start"]["line"]}')
    print(f'    {r["extra"]["message"][:150]}')
