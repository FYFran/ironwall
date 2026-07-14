import json

with open('iw_chi_v5.json','r',encoding='utf-8') as f:
    data = json.load(f)
findings = data.get('findings',[])

tags = ['[TEST/EXAMPLE]', '[LOW-RISK]', '[SAME-ORIGIN]', '[LIBRARY]']
counts = {}
for tag in tags:
    counts[tag] = sum(1 for f in findings if tag in f.get('title',''))

all_tagged = sum(1 for f in findings if any(t in f.get('title','') for t in tags))
non_tagged = len(findings) - all_tagged

print('Total:', len(findings))
for tag, cnt in counts.items():
    print(' ', tag, ':', cnt)
print('  Any tag:', all_tagged)
print('  Non-tagged:', non_tagged)

real = [f for f in findings if not any(t in f.get('title','') for t in tags)]
print('\nNon-tagged findings:')
for f in real:
    sev = f.get('severity','?')
    cat = f.get('category','?')
    title = f.get('title','?')[:100]
    fp = f.get('file_path','?')
    ln = f.get('line_number','?')
    print('  [' + str(sev) + '] [' + str(cat) + '] ' + title)
    print('    ' + str(fp) + ':' + str(ln))
