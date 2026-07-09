"""Sample N representative files from the benchmark, stratified by category."""
import csv, shutil, os, sys
from collections import defaultdict

def sample_benchmark(benchmark_dir: str, csv_path: str, output_dir: str, n: int = 50):
    """Sample n files from benchmark, preserving category distribution."""
    # Group files by category
    by_cat = defaultdict(list)
    with open(csv_path, "r") as f:
        reader = csv.reader(f)
        next(reader)  # skip header
        for row in reader:
            if len(row) < 3:
                continue
            fname = row[0].strip()
            cat = row[1].strip()
            vuln = row[2].strip().lower() == "true"
            by_cat[cat].append((fname, vuln))

    total = sum(len(v) for v in by_cat.values())
    # Sample proportionally
    sampled = []
    for cat, files in by_cat.items():
        k = max(1, round(n * len(files) / total))
        sampled.extend(files[:k])

    sampled = sampled[:n]

    # Copy files
    os.makedirs(output_dir, exist_ok=True)
    src_dir = os.path.join(benchmark_dir, "testcode")
    for fname, _ in sampled:
        src = os.path.join(src_dir, fname)
        dst = os.path.join(output_dir, fname)
        if os.path.exists(src):
            shutil.copy2(src, dst)

    # Write mini expected results
    sampled_names = set(f[0] for f in sampled)
    mini_csv = os.path.join(output_dir, "expectedresults.csv")
    with open(csv_path, "r") as fin, open(mini_csv, "w", newline="") as fout:
        reader = csv.reader(fin)
        header = next(reader)
        writer = csv.writer(fout)
        writer.writerow(header)
        for row in reader:
            if len(row) >= 3 and row[0].strip() in sampled_names:
                writer.writerow(row)

    print(f"Sampled {len(sampled)} files → {output_dir}")
    print(f"Categories: {[(c, len([x for x in sampled if x[0] in set(v[0] for v in by_cat[c])])) for c in sorted(by_cat)]}")
    vuln_count = sum(1 for _, v in sampled if v)
    safe_count = len(sampled) - vuln_count
    print(f"Vulnerable: {vuln_count}, Safe: {safe_count}")

if __name__ == "__main__":
    benchmark_dir = sys.argv[1] if len(sys.argv) > 1 else "testdata/BenchmarkPython"
    csv_path = os.path.join(benchmark_dir, "expectedresults-0.1.csv")
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "testdata/benchmark_50"
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    sample_benchmark(benchmark_dir, csv_path, output_dir, n)
