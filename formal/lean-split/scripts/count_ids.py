#!/usr/bin/env python3
"""Every EARS ID of the change has a row in exactly one capability table.

usage: count_ids.py LEAN_SPLIT_DIR   (exit 1 unless the capability tables hold every EARS ID of
the change's specs, each once; the specs give the count, so a new sentence needs a row)
"""
import pathlib, re, sys

root = pathlib.Path(sys.argv[1]).resolve()
specs = root.parents[1] / "openspec/changes/add-split-line-dealing/specs"
want = set()
for f in sorted(specs.glob("*/spec.md")):
    want |= set(re.findall(r"\*\*([A-Z]{2}-\d{3})\*\*", f.read_text()))
caps = ["envelope", "request", "slots", "authorization", "checkpoint", "shard-holders", "handoff"]
ids = []
for c in caps:
    readme = (root / c / "README.md").read_text()
    m = re.search(r"<!-- req-table -->\n(.*?)<!-- /req-table -->", readme, flags=re.S)
    ids += re.findall(r"^\| ([A-Z]{2}-\d{3}) \|", m.group(1), flags=re.M)
if not want or len(ids) != len(set(ids)) or set(ids) != want:
    missing, extra = sorted(want - set(ids)), sorted(set(ids) - want)
    sys.exit(f"trace: {len(ids)} rows, {len(set(ids))} distinct IDs; the specs hold {len(want)}"
             f"; missing {missing[:10]}, not in the specs {extra[:10]}")
print(f"trace: {len(want)} EARS IDs, one row each, in {len(caps)} capability tables")
