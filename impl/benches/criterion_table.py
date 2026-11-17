"""Print the split bench results as a Markdown table.

Reads target/criterion/split_n{5,9,17,33}/<row>[/<param>]/new/estimates.json and
prints the median point estimate with its 95% interval for each row.
Run from impl/: python3 -I benches/criterion_table.py [target/criterion]
"""
import json
import pathlib
import sys

args = [a for a in sys.argv[1:] if not a.startswith("--")]
root = pathlib.Path(args[0] if args else "target/criterion")


def fmt(ns):
    if ns >= 1e6:
        return f"{ns / 1e6:.3f} ms"
    if ns >= 1e3:
        return f"{ns / 1e3:.1f} µs"
    return f"{ns:.0f} ns"


rows = {}
for est in sorted(root.glob("split_n*/**/new/estimates.json")):
    rel = est.relative_to(root).parts[:-2]
    n, name = rel[0].removeprefix("split_"), "/".join(rel[1:])
    med = json.loads(est.read_text())["median"]
    ci = med["confidence_interval"]
    rows.setdefault(name, {})[n] = (med["point_estimate"], ci["lower_bound"], ci["upper_bound"])

sizes = sorted({n for r in rows.values() for n in r}, key=lambda n: int(n[1:]))
print("| Row | " + " | ".join(f"n = {n[1:]} median [95% CI]" for n in sizes) + " |")
print("|---|" + "---:|" * len(sizes))
for name in sorted(rows):
    cells = []
    for n in sizes:
        v = rows[name].get(n)
        cells.append(f"{fmt(v[0])} [{fmt(v[1])}, {fmt(v[2])}]" if v else "-")
    print(f"| `{name}` | " + " | ".join(cells) + " |")
if "--json" in sys.argv:
    print(json.dumps({k: {n: v[0] for n, v in r.items()} for k, r in rows.items()}))
