import sys, re, pathlib, yaml
root = pathlib.Path(sys.argv[1]); ref = root / "specs/refinement"
spec = (root / "openspec/changes/add-seald-sessions/specs/seald-sessions/spec.md").read_text()
qi = pathlib.Path(sys.argv[2]).read_text()
SS = set(re.findall(r"^### Requirement: (SS-\d{3})", spec, re.M))
QI = set(re.findall(r"^\| (QI-\d\d) ", qi, re.M))
err = []
B = yaml.safe_load((ref/"baseline.yaml").read_text()); T = yaml.safe_load((ref/"traceability.yaml").read_text())
for name, doc in (("baseline", B), ("traceability", T)):
    for k in ("protocol", "project_id", "artifact_id", "revision"):
        if k not in doc: err.append(f"{name}: missing {k}")
ids = set()
for key, v in B.items():
    if isinstance(v, list):
        for e in v:
            if isinstance(e, dict) and "id" in e:
                if e["id"] in ids: err.append(f"dup id {e['id']}")
                ids.add(e["id"])
known = ids | SS | QI | {"G1","G2","G3","G4","G5"}
def walk(o, where):
    if isinstance(o, dict):
        for k, v in o.items(): walk(v, f"{where}.{k}")
    elif isinstance(o, list):
        for v in o: walk(v, where)
    elif isinstance(o, str):
        for t in re.findall(r"\b(?:SS-\d{3}|QI-\d\d|D-\d{3}|CTX-\d{3}|AGG-\d{3}|MOD-\d{3}|CON-\d{3}|INV-\d{3}|JNY-\d{3}|ASM-\d{3}|Q-\d{3}|SRC-\d{3}|GLO-\d{3})\b", o):
            if t not in known: err.append(f"{where}: unknown {t}")
walk(B, "baseline"); walk(T, "trace")
req_ids = {r["id"] for r in B["requirements"] if r.get("state") != "superseded"}
for r in B["requirements"]:
    if r.get("state") == "superseded" and (r["id"] in SS or not r.get("superseded_by")): err.append(f"{r['id']}: superseded but in spec or without superseded_by")
if req_ids != SS: err.append(f"requirements != spec SS: {sorted(SS ^ req_ids)}")
for d in B["decisions"]:
    for f in ("record_ref","driver_refs","consumed_items","obligation_refs","confirmation","revisit_when"):
        if f not in d or d[f] is None: err.append(f"{d['id']}: missing {f}")
    if not (ref / d["record_ref"]).exists(): err.append(f"{d['id']}: no record")
    if not d["obligation_refs"]: err.append(f"{d['id']}: no obligation")
    for c in d["confirmation"]:
        if c["kind"] not in ("conformance","outcome"): err.append(f"{d['id']}: kind")
    md = (ref / d["record_ref"]).read_text()
    for h in ("## Context and Problem Statement","## Decision Drivers","## Considered Options","## Decision Outcome","### Consequences","### Confirmation","### Reconsideration"):
        if h not in md: err.append(f"{d['id']}: no {h}")
    if f"state: {d['state']}" not in md: err.append(f"{d['id']}: state mismatch")
tD = {e["id"]: e for e in T["decisions"]}
for d in B["decisions"]:
    e = tD.get(d["id"])
    if not e: err.append(f"{d['id']} not traced"); continue
    if e["obligation_refs"] != d["obligation_refs"]: err.append(f"{d['id']} obligations differ")
    if not e["checks"]: err.append(f"{d['id']} no checks")
    for c in e["checks"]:
        if c["status"] not in ("planned", "passed"): err.append(f"{d['id']} bad status {c['status']}")
        if c["status"] == "passed" and c["item"] != 20: err.append(f"{d['id']} passed status outside item 20")
# markdown links
for md in [ref/"architecture.md", *sorted((ref/"decisions").glob("*.md")), root/"openspec/changes/add-seald-sessions/design.md"]:
    for l in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", md.read_text()):
        if l.startswith("http"): continue
        if not (md.parent / l).exists(): err.append(f"{md.name}: broken link {l}")
print("\n".join(err) if err else f"OK: {len(B['decisions'])} D, {len(req_ids)} SS, {len(ids)} ids, QI known {len(QI)}")
sys.exit(1 if err else 0)
