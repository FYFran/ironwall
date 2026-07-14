"""Verify which CVE cases ironwall now detects after semgrep auto fix"""
import json

with open('ironwall_cve_fixed.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

findings = data.get('findings', [])
print(f'Total findings after fix: {len(findings)}')

# Map CVE files
cve_files = [
    ('case01_sqli.go', 'SQL Injection'),
    ('case02_path_traversal.go', 'Path Traversal'),
    ('case03_command_injection.go', 'Command Injection'),
    ('case04_hardcoded_secrets.go', 'Hardcoded Secrets'),
    ('case05_weak_crypto.go', 'Weak Cryptography'),
    ('case06_ssrf.go', 'SSRF'),
    ('case07_xss_template.go', 'XSS Templates'),
    ('case08_tls_bypass.go', 'TLS Bypass'),
    ('case09_insecure_random.go', 'Insecure Random'),
    ('case10_open_redirect.go', 'Open Redirect'),
]

from collections import defaultdict
by_file = defaultdict(list)
for f in findings:
    fp = f.get('file_path', '')
    for cve_file, _ in cve_files:
        if cve_file in fp:
            by_file[cve_file].append(f.get('category', 'unknown'))
            break

detected = 0
print('\nCVE Detection (AFTER fix):')
for cve_file, cve_name in cve_files:
    cats = by_file.get(cve_file, [])
    status = 'YES' if cats else 'NO '
    if cats:
        detected += 1
    print(f'  {status} {cve_file} ({cve_name}): {len(cats)} findings - {cats[:3]}')

print(f'\nRecall: {detected}/{len(cve_files)} ({detected/len(cve_files)*100:.0f}%)')
