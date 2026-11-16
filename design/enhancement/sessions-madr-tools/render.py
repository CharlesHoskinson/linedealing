"""Render D records, the baseline decisions and traceability.yaml from ddata.py.

Usage: python3 -I render.py <refinement-dir> <baseline-head.yaml>
"""
import sys, pathlib, importlib.util, yaml

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ddata", here / "ddata.py")
ddata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ddata)
D = ddata.D

out = pathlib.Path(sys.argv[1])
head = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
SPEC = "../../openspec/changes/add-seald-sessions/specs/seald-sessions/spec.md"
DESIGN = "../../../openspec/changes/add-seald-sessions/design.md"


def madr(d):
    status = "accepted" if d["state"] == "confirmed" else "proposed"
    makers = "the owner" if d["state"] == "confirmed" else "the lead, under owner AFK delegation"
    L = ["---",
         f"id: {d['id']}",
         f"status: {status}",
         f"state: {d['state']}",
         f"basis: {d['basis']}",
         "date: 2026-11-14",
         f"decision-makers: {makers}",
         "baseline: BASE-001 revision 3",
         "---", "",
         f"# {d['id']}: {d['title']}", "",
         "## Context and Problem Statement", "", d["context"], ""]
    if d.get("design_decision"):
        L += [f"This record gives the reasons for decision {d['design_decision']} of [design.md]({DESIGN}#decisions). The text of that decision stays as the owner confirmed it.", ""]
    L += ["## Decision Drivers", ""]
    for i, t in d["drivers"]:
        L.append(f"* {i}: {t}")
    L += ["", "## Considered Options", ""]
    for o in d["options"]:
        L.append(f"* {o[0]}")
    L += ["", "## Decision Outcome", "",
          f"Chosen option: \"{d['chosen']}\", because {d['rationale'][0].lower() + d['rationale'][1:]}", "",
          f"Authority: {d['authority']}", "",
          f"Binding requirements: {', '.join(d['obligations'])} in `spec.md` of `add-seald-sessions`. This record creates no obligation of its own.", "",
          "### Consequences", ""]
    for k, t in d["consequences"]:
        L.append(f"* {k}: {t}")
    ran_any = any(c.get("status", "planned") != "planned" for _, _, _, c in d["confirmation"])
    L += ["", "### Confirmation", "",
          ("Each entry is a planned check unless it states a result. Results are prototype runs of item 20 on the fixed rules."
           if ran_any else "Each entry is a planned check. None has run."), ""]
    for kind, method, targets, chk in d["confirmation"]:
        st = chk.get("status", "planned")
        tail = "" if st == "planned" else f" Result: {st}."
        L.append(f"* {kind}: {method} Targets: {', '.join(targets)}. Check: item {chk['item']}, {chk['check']} ({chk['what']}).{tail}")
    L += ["", "## Pros and Cons of the Options", ""]
    for title, desc, pros, cons in d["options"]:
        L += [f"### {title}", "", desc, ""]
        L += [f"* Good: {p}" for p in pros]
        L += [f"* Bad: {c}" for c in cons]
        L.append("")
    L += ["## More Information", "", "### Reconsideration", ""]
    L += [f"* {r}" for r in d["revisit_when"]]
    L += ["", "### Links", "",
          "* Baseline: [baseline.yaml](../baseline.yaml), decision " + d["id"] + ".",
          "* Trace to checks: [traceability.yaml](../traceability.yaml).",
          "* Model: [architecture.md](../architecture.md)."]
    if d["consumed"]:
        L.append("* Builds on: " + ", ".join(f"[{c['id']}]({c['id']}.md)" for c in d["consumed"]) + ".")
    L.append("")
    return "\n".join(L)


def ditem(d):
    return {
        "id": d["id"], "version": d.get("version", 1), "state": d["state"], "basis": d["basis"],
        "source_refs": d["source_refs"], "title": d["title"],
        "choice": next(o[1] for o in d["options"] if o[0] == d["chosen"]),
        "rationale": d["rationale"], "authority": d["authority"],
        "evidence_refs": d["source_refs"],
        "affected_ids": d["affected"], "record_ref": f"decisions/{d['id']}.md",
        "driver_refs": [i for i, _ in d["drivers"]],
        "consumed_items": d["consumed"],
        "obligation_refs": d["obligations"],
        "confirmation": [{"kind": k, "method": m, "target_refs": t,
                          "check": {"item": c["item"], "ref": c["check"]}}
                         for k, m, t, c in d["confirmation"]],
        "revisit_when": d["revisit_when"],
        "supersedes": None,
    }


class Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def str_rep(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


Dumper.add_representer(str, str_rep)


def dump(obj):
    return yaml.dump(obj, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=110, default_flow_style=None)


(out / "decisions").mkdir(parents=True, exist_ok=True)
for d in D:
    (out / "decisions" / f"{d['id']}.md").write_text(madr(d), encoding="utf-8")

import re
spec_text = (out / SPEC).resolve().read_text(encoding="utf-8")
PEER = {3, *range(12, 20), *range(25, 30), 38, 39, 91, 95, 96, 101, 102, 108, 109, 110, 126, 127}
CONTRACT = {103, 104, 117, 121, 122, 136}
CONSTRAINT = {4, 8, 109}
CONTRIB = {5: ["MOD-003", "MOD-004"], 63: ["MOD-003"], 64: ["MOD-004"], 67: ["MOD-004"], 68: ["MOD-003"],
           70: ["MOD-003", "MOD-004"], 104: ["MOD-001", "MOD-003"], 103: ["MOD-003"], 111: ["MOD-002"],
           112: ["MOD-003", "MOD-004"], 113: ["MOD-004"], 114: ["MOD-003"], 116: ["MOD-002"],
           117: ["MOD-001"], 120: ["MOD-003", "MOD-004"], 121: ["MOD-001", "MOD-003"], 122: ["MOD-003"],
           123: ["MOD-004"], 124: ["MOD-004"], 125: ["MOD-004"], 30: ["MOD-002"], 102: ["MOD-001"],
           128: ["MOD-003"], 129: ["MOD-003"], 130: ["MOD-003"], 131: ["MOD-003"], 136: ["MOD-001", "MOD-003"],
           137: ["MOD-003", "MOD-004"], 138: ["MOD-003"], 139: ["MOD-003"], 140: ["MOD-003"], 141: ["MOD-003"],
           133: ["MOD-004"], 126: ["MOD-001"]}
AMENDED = {88, 89, 90, 102}  # requirement text changed in BASE-001 revision 2 (item 28)
AMENDED3 = {4, 5, 23, 55, 56, 64, 68, 70, 71, 72, 73, 75, 80, 89, 90, 92, 104, 108, 112, 114, 117, 119, 120, 121, 122, 123,
            124, 125, 128, 129, 130, 131}  # requirement text changed in BASE-001 revision 3 (item 29)
RETIRED = [  # requirements removed from spec.md in revision 3; the IDs are never reused
    ("SS-105", "One anchor for each nonce slot", ["SS-072", "SS-119", "SS-136"], "D-033"),
    ("SS-132", "One put record for each share", ["SS-131", "SS-136"], "D-027"),
]
reqs = []
for m in re.finditer(r"^### Requirement: (SS-(\d{3})) (.+)$", spec_text, re.M):
    n = int(m.group(2))
    mod = "MOD-002" if n in PEER else "MOD-004" if n in CONTRACT else "MOD-001"
    reqs.append({"id": m.group(1), "version": 1 + (n in AMENDED) + (n in AMENDED3), "state": "provisional", "basis": "explicit",
                 "source_refs": ["SRC-002"], "title": m.group(3),
                 "kind": "constraint" if n in CONSTRAINT else "functional",
                 "statement_ref": f"spec.md#{m.group(1)}", "module": mod,
                 "contributors": CONTRIB.get(n, []),
                 "acceptance_ref": f"spec.md scenarios of {m.group(1)}"})
for rid, title, by, dec in RETIRED:
    reqs.append({"id": rid, "version": 2, "state": "superseded", "basis": "explicit", "source_refs": ["SRC-011"], "title": title,
                 "kind": "functional", "statement_ref": None, "module": "MOD-004", "contributors": [],
                 "acceptance_ref": None, "superseded_by": by, "superseded_note": f"Retired in BASE-001 revision 3 by {dec}: Midnight keeps no per-event record."})
base = head.rstrip("\n") + "\n" + dump({"requirements": reqs}) + dump({"decisions": [ditem(d) for d in D]})
(out / "baseline.yaml").write_text(base, encoding="utf-8")

ITEM = {20: "discovery prototype", 21: "Lean oracle", 22: "Quint check", 24: "production seald"}
tr = {
    "protocol": "spec-refinement/v1",
    "project_id": "veritee-seald-sessions",
    "artifact_id": "TRACE-001",
    "revision": 3,
    "baseline_ref": {"artifact_id": "BASE-001", "revision": 3},
    "spec_ref": "openspec/changes/add-seald-sessions/specs/seald-sessions/spec.md",
    "status_note": ("Every check below is planned unless its status is passed. A passed check is a run of the item 20 prototype on the "
                    "fixed rules of items 28 and 29, rerun by the lead. Items 21, 22 and 24 have not run."),
    "check_items": {f"item-{k}": v for k, v in ITEM.items()},
    "decisions": [],
}
for d in D:
    e = {
        "id": d["id"], "state": d["state"], "record_ref": f"decisions/{d['id']}.md",
        "driver_refs": [i for i, _ in d["drivers"]],
        "affected_ids": d["affected"],
        "binding": True,
        "obligation_refs": d["obligations"],
        "checks": [{"kind": k, "item": c["item"], "ref": c["check"], "claim": c["what"],
                    "target_refs": t, "status": c.get("status", "planned")} for k, m, t, c in d["confirmation"]],
    }
    tr["decisions"].append(e)
tail = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8") if len(sys.argv) > 3 else ""
(out / "traceability.yaml").write_text(dump(tr) + tail, encoding="utf-8")
print("rendered", len(D))
