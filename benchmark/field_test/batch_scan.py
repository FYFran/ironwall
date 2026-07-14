"""Batch scan 5 Go projects with ironwall + semgrep, compare results."""
import subprocess, json, time, os
from pathlib import Path
from collections import defaultdict

BASE = Path(__file__).parent
IRONWALL = r"f:\ClaudeFiles\_research\ironwall\ironwall.exe"
SEMGREP = "semgrep"

PROJECTS = ["jwt", "chi", "websocket", "mysql", "cli"]

def run(cmd, timeout=180):
    start = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                          encoding='utf-8', errors='replace')
        stdout = r.stdout or ''
        stderr = r.stderr or ''
        return stdout + stderr, int((time.time()-start)*1000), r.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT", int((time.time()-start)*1000), -1

results = {}

for proj in PROJECTS:
    target = str(BASE / proj)
    print(f"\n{'='*60}")
    print(f"Scanning: {proj}")
    print(f"{'='*60}")

    # Ironwall
    print(f"  Ironwall...")
    iw_out, iw_ms, iw_rc = run([IRONWALL, "scan", target, "--format", "json", "--timeout", "120", "-o", str(BASE / f"iw_{proj}.json")], 180)
    # Parse JSON output
    iw_findings = 0
    iw_sev = defaultdict(int)
    try:
        iw_json = str(BASE / f"iw_{proj}.json")
        if os.path.exists(iw_json):
            with open(iw_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            iw_findings = len(data.get('findings', []))
            for fd in data.get('findings', []):
                iw_sev[fd.get('severity', 'unknown')] += 1
    except: pass

    # Semgrep
    print(f"  Semgrep...")
    sg_out, sg_ms, sg_rc = run([SEMGREP, "--config=auto", "--no-git-ignore", "--json", "-o", str(BASE / f"sg_{proj}.json"), target], 180)
    sg_findings = 0
    sg_sev = defaultdict(int)
    try:
        sg_json = str(BASE / f"sg_{proj}.json")
        if os.path.exists(sg_json):
            with open(sg_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            sg_findings = len(data.get('results', []))
            for fd in data.get('results', []):
                sg_sev[fd.get('extra', {}).get('severity', 'unknown')] += 1
    except: pass

    results[proj] = {
        'ironwall': {'findings': iw_findings, 'severity': dict(iw_sev), 'ms': iw_ms},
        'semgrep': {'findings': sg_findings, 'severity': dict(sg_sev), 'ms': sg_ms},
    }
    print(f"  Ironwall: {iw_findings} findings, {iw_ms}ms")
    print(f"  Semgrep:  {sg_findings} findings, {sg_ms}ms")

# Summary table
print(f"\n{'='*70}")
print(f"SUMMARY: 5-Project Field Test")
print(f"{'='*70}")
print(f"{'Project':<15} {'IW Findings':>12} {'SG Findings':>12} {'IW Time':>10} {'SG Time':>10}")
print(f"{'-'*15} {'-'*12} {'-'*12} {'-'*10} {'-'*10}")
for proj in PROJECTS:
    r = results[proj]
    print(f"{proj:<15} {r['ironwall']['findings']:>12} {r['semgrep']['findings']:>12} {r['ironwall']['ms']:>9}ms {r['semgrep']['ms']:>9}ms")

# Save results
with open(str(BASE / 'batch_results.json'), 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=2, ensure_ascii=False)
print(f"\nResults saved to batch_results.json")
