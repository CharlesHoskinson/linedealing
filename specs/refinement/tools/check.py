"""Check the refinement artifacts of add-split-line-dealing against the specs.

Usage: python3 -I specs/refinement/tools/check.py <repo root>
Exit 0 when every check passes, 1 otherwise.
"""
import hashlib
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(sys.argv[1]).resolve()
REF = ROOT / "specs/refinement"
CHANGE = ROOT / "openspec/changes/add-split-line-dealing"
QS = "aa038fa"
REQ_RE = r"\b(?:RQ|SL|AU|CP|EN|SH)-\d{3}\b"
err = []

# ---- specs
spec_text = {p.parent.name: p.read_text(encoding="utf-8") for p in sorted((CHANGE / "specs").glob("*/spec.md"))}
defined = {}
for cap, t in spec_text.items():
    for rid in re.findall(r"^### Requirement: (\S+)", t, re.M):
        if rid in defined:
            err.append(f"duplicate requirement {rid}")
        defined[rid] = cap
    for rid in re.findall(r"^\*\*(\S+?)\*\*", t, re.M):
        if rid not in defined:
            err.append(f"{cap}: bold id {rid} without heading")
cited = {m for t in spec_text.values() for m in re.findall(REQ_RE, t)}
for m in sorted(cited - set(defined)):
    err.append(f"spec cites undefined requirement {m}")

# DECISIONS cited by the specs (independent of gen.py)
dec_cited = set()
for t in spec_text.values():
    for grp in re.findall(r"DECISIONS? (\d+(?:(?: item \(\d+\)| D\d+)?(?:, | and )\d+)*(?: item \(\d+\)| D\d+)?)", t):
        dec_cited |= {int(n) for n in re.findall(r"\d+", re.sub(r"item \(\d+\)|D\d+", "", grp))}
claims_cited = {int(c) for t in spec_text.values() for c in re.findall(r"\bC(\d+)\b", t)}
q_cited = {q for t in spec_text.values() for q in re.findall(r"\bQ-\d{3}\b", t)}
o_cited = {int(o) for t in spec_text.values() for o in re.findall(r"\bO(\d+)\b", t)}

# ---- DECISIONS records
# The files of quint-split at QS, kept in the tree so the check runs without git (drwatt runs
# it in a copy that has no .git). Each snapshot must equal the blob that QS holds; the pins are
# its git blob IDs (`git rev-parse QS:PATH`).
QS_SNAPSHOT = ROOT / "specs/refinement/sources/quint-split-aa038fa"
QS_BLOBS = {
    "design/enhancement/DECISIONS.md": "37da85bd208bfb3d1d85485253f64ae85a344dd4",
    "design/enhancement/DESIGN.md": "4e5394c21c63af8b94d3f7aea125187dcf582e49",
}


def git_show(rev, path):
    assert rev == QS, rev
    data = (QS_SNAPSHOT / pathlib.PurePosixPath(path).name).read_bytes()
    blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if blob != QS_BLOBS[path]:
        sys.exit(f"snapshot of {QS}:{path} has blob {blob}, want {QS_BLOBS[path]}")
    return data.decode("utf-8")

dec_main = (ROOT / "design/enhancement/DECISIONS.md").read_text(encoding="utf-8")
dec_qs = git_show(QS, "design/enhancement/DECISIONS.md")

def entry(text, n):
    m = re.search(rf"^{n}\. .*?(?=^\d+\. |^## |\Z)", text, re.M | re.S)
    return m.group(0) if m else None

MADR_OLD = ["Drivers:", "Considered options:", "Outcome and authority:", "Consequences:", "Confirmation:", "Revisit when:"]
for n in sorted(dec_cited):
    e = entry(dec_main, n) or entry(dec_qs, n)
    if e is None:
        err.append(f"DECISIONS {n} cited but absent on main and quint-split")
        continue
    if n <= 41:
        for f in MADR_OLD:
            if f"   - {f}" not in e:
                err.append(f"DECISIONS {n}: consumed entry lacks MADR field {f}")

# ---- design open items
design = (ROOT / "design/enhancement/DESIGN.md").read_text(encoding="utf-8") + git_show(QS, "design/enhancement/DESIGN.md")
o_defined = {int(o) for o in re.findall(r"^\| O(\d+) ", design, re.M)}
for o in sorted(o_cited - o_defined):
    err.append(f"spec cites open item O{o} that DESIGN does not define")

# ---- baseline and traceability
B = yaml.safe_load((REF / "baseline.yaml").read_text(encoding="utf-8"))
T = yaml.safe_load((REF / "traceability.yaml").read_text(encoding="utf-8"))
for name, doc in (("baseline", B), ("traceability", T)):
    for k in ("protocol", "project_id", "artifact_id", "revision"):
        if k not in doc:
            err.append(f"{name}: missing {k}")
ids = set()
for key, v in B.items():
    if isinstance(v, list):
        for e in v:
            if isinstance(e, dict) and "id" in e:
                if e["id"] in ids:
                    err.append(f"duplicate id {e['id']}")
                ids.add(e["id"])
known = ids | set(defined)
# Fields that quote DECISIONS or DESIGN text; their IDs belong to other documents.
QUOTED = {"choice", "rationale", "method", "revisit_when", "authority", "title", "drivers_text", "question", "reason",
          "statement", "meaning", "rule", "success", "failure", "purpose", "revision_note", "status_note", "claim", "holds",
          "atomic_scope", "trigger", "if_false", "validation", "alternatives", "role", "responsibilities"}
ID_RE = r"\b(?:D|CTX|AGG|MOD|CON|INV|JNY|ASM|Q|SRC|GLO|ACT)-\d{3}\b|\bG\d\b"

def walk(o, where, key=None):
    if isinstance(o, dict):
        for k, v in o.items():
            walk(v, f"{where}.{k}", k)
    elif isinstance(o, list):
        for v in o:
            walk(v, where, key)
    elif isinstance(o, str) and key not in QUOTED:
        for t in re.findall(ID_RE + "|" + REQ_RE, o):
            if t not in known:
                err.append(f"{where}: unknown {t}")

walk(B, "baseline")
walk(T, "trace")

req_ids = {r["id"] for r in B["requirements"]}
if req_ids != set(defined):
    err.append(f"baseline requirements differ from specs: {sorted(req_ids ^ set(defined))}")
d_ids = {d["id"] for d in B["decisions"]}
want = {f"D-{n:03d}" for n in dec_cited}
if d_ids != want:
    err.append(f"D items differ from DECISIONS cited by the specs: {sorted(d_ids ^ want)}")
inv_claims = {int(i["claim"][1:]) for i in B["invariants"]}
for c in sorted(claims_cited - inv_claims):
    err.append(f"claim C{c} cited in specs has no invariant")
q_ids = {q["id"] for q in B["questions"]}
for q in sorted(q_cited - q_ids):
    err.append(f"spec cites {q} that baseline does not define")
for d in B["decisions"]:
    for f in ("record_ref", "driver_refs", "consumed_items", "obligation_refs", "confirmation", "revisit_when"):
        if d.get(f) is None:
            err.append(f"{d['id']}: missing {f}")
    if not d["obligation_refs"]:
        err.append(f"{d['id']}: no obligation")
    if not d["driver_refs"]:
        err.append(f"{d['id']}: no driver")
    kinds = {c["kind"] for c in d["confirmation"]}
    if not kinds <= {"conformance", "outcome"} or not kinds:
        err.append(f"{d['id']}: bad confirmation kinds {kinds}")
    n = int(d["id"][2:])
    on_main = entry(dec_main, n) is not None
    if on_main != d["record_ref"].startswith("design/"):
        err.append(f"{d['id']}: record_ref does not match where the entry lives")
    if not on_main and "Q-004" not in d.get("unresolved", []):
        err.append(f"{d['id']}: unmerged record without Q-004")
tD = {e["id"]: e for e in T["decisions"]}
for d in B["decisions"]:
    e = tD.get(d["id"])
    if not e:
        err.append(f"{d['id']} not traced")
        continue
    if e["obligation_refs"] != d["obligation_refs"]:
        err.append(f"{d['id']}: obligations differ between baseline and traceability")
    for c in e["checks"]:
        if c["status"] != "planned":
            err.append(f"{d['id']}: check status {c['status']} (no check of these specs has run)")
for r in T["requirements"]:
    for c in r["checks"]:
        if c["status"] != "planned":
            err.append(f"{r['id']}: check status {c['status']}")
if {r["id"] for r in T["requirements"]} != set(defined):
    err.append("traceability requirements differ from specs")

# ---- markdown links in architecture.md and design.md
for md in [REF / "architecture.md", CHANGE / "design.md"]:
    if not md.exists():
        err.append(f"missing {md.relative_to(ROOT)}")
        continue
    for link in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", md.read_text(encoding="utf-8")):
        if link.startswith("http"):
            continue
        if not (md.parent / link).exists():
            err.append(f"{md.name}: broken link {link}")

if err:
    print("\n".join(err))
    sys.exit(1)
print(f"OK: {len(defined)} requirements, {len(d_ids)} D items (DECISIONS {', '.join(str(n) for n in sorted(dec_cited))}), "
      f"{len(inv_claims)} invariants, {len(q_ids)} questions, {len(o_cited)} open items, {len(ids)} baseline ids")
