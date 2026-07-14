import json

with open('iw_mysql_v3.json','r',encoding='utf-8') as f:
    data = json.load(f)
findings = data.get('findings',[])
hcs = [f for f in findings if 'hardcoded-credentials' in f.get('category','')]
print('Total hardcoded-credentials:', len(hcs))
for f in hcs[:10]:
    print('  Title:', f.get('title','?')[:100])
    print('  File:', f.get('file_path','?'))
    print('  Code:', (f.get('code_snippet','?') or '')[:150])
    print()
