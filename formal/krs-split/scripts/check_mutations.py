#!/usr/bin/env -S python3 -I
"""Content checks of a `krs kink run --full --output json` report (gate `mutations`).

Usage: check_mutations.py CAPDIR

Reads CAPDIR/.kink-run.json, CAPDIR/kink/mutations/*.toml, CAPDIR/gaps.toml and the
requirement table of the Lean oracle's README (../lean-split/<cap>/README.md).
Fails when
  * a mutation has no `expect`;
  * a mutation's status is not `killed`, or `survived` with expect = "survive";
  * a rule of the definition is untargeted;
  * an EARS ID of the capability is neither named by a mutation's `misunderstanding`
    nor listed in gaps.toml with the check that covers it.
"""
import json
import pathlib
import re
import sys
import tomllib

cap = pathlib.Path(sys.argv[1]).resolve()
run = json.loads((cap / ".kink-run.json").read_text())
muts = {}
for p in sorted((cap / "kink" / "mutations").glob("*.toml")):
    for m in tomllib.loads(p.read_text()).get("mutation", []):
        muts[f"{p.stem}/{m['id']}"] = m
        muts.setdefault(m["id"], m)
bad = []
for mid, m in muts.items():
    if "/" in mid and "expect" not in m:
        bad.append(f"{mid}: no expect")
rows = run.get("mutations") or run.get("run", {}).get("mutation", [])
if not rows:
    bad.append("the run report lists no mutation")
for r in rows:
    mid, st = r.get("id"), r.get("status")
    m = muts.get(mid) or muts.get(str(mid).split("/")[-1])
    if m is None:
        bad.append(f"{mid}: in the report but not in the mutation files")
        continue
    exp = m.get("expect", "kill")
    if st == "killed" and exp == "kill":
        continue
    if st == "survived" and exp == "survive":
        continue
    bad.append(f"{mid}: status {st}, expect {exp}")
if run.get("untargeted_rules"):
    bad.append(f"untargeted rules: {run['untargeted_rules']}")
readme = (cap.parent.parent / "lean-split" / cap.name / "README.md").read_text()
prefix = {"envelope": "EN", "request": "RQ", "slots": "SL", "authorization": "AU",
          "checkpoint": "CP", "shard-holders": "SH"}[cap.name]
ears = set(re.findall(rf"^\| ({prefix}-\d{{3}}) \| [A-Z]", readme, flags=re.M))
named = set(re.findall(rf"{prefix}-\d{{3}}", " ".join(m.get("misunderstanding", "") for m in muts.values())))
gaps = {}
gp = cap / "gaps.toml"
if gp.exists():
    for g in tomllib.loads(gp.read_text()).get("gap", []):
        if not g.get("covered_by"):
            bad.append(f"gap {g.get('id')}: no covered_by")
        gaps[g["id"]] = g
missing = sorted(ears - named - set(gaps))
if missing:
    bad.append(f"EARS IDs no mutation names and no gap lists: {missing}")
needless = sorted(set(gaps) & named)
if needless:
    bad.append(f"gaps that a mutation names (remove the gap): {needless}")
if bad:
    sys.exit("mutations:\n  " + "\n  ".join(bad))
print(f"mutations: {len(rows)} mutations killed or argued; {len(ears & named)} EARS IDs named, "
      f"{len(ears & set(gaps))} listed as gaps")
