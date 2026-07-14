import json

# Check the latest chi scan
import glob
files = sorted(glob.glob('iw_chi_v*.json'))
latest = files[-1]
print('Reading:', latest)

with open(latest, 'r', encoding='utf-8') as f:
    data = json.load(f)
findings = data.get('findings',[])

all_tags = ['[TEST/EXAMPLE]', '[LOW-RISK]', '[SAME-ORIGIN]', '[LIBRARY]', '[INFO]']
all_tagged = sum(1 for f in findings if any(t in f.get('title','') for t in all_tags))
non_tagged = len(findings) - all_tagged

print('Total:', len(findings))
print('Any tag:', all_tagged)
print('Non-tagged:', non_tagged)
print()

real = [f for f in findings if not any(t in f.get('title','') for t in all_tags)]
if real:
    print('NON-TAGGED:')
    for f in real:
        sev = f.get('severity','?')
        cat = f.get('category','?')
        title = f.get('title','?')
        code = (f.get('code_snippet','') or '')[:80]
        fp = f.get('file_path','?')
        print('  [' + str(sev) + '] [' + str(cat) + '] ' + title)
        print('    Code: ' + code.strip())
        print('    File: ' + str(fp))
        print()
else:
    print('ALL FINDINGS TAGGED - precision filters working!')

# Also show tagged breakdown
for tag in all_tags:
    cnt = sum(1 for f in findings if tag in f.get('title',''))
    if cnt > 0:
        print(tag + ': ' + str(cnt))
