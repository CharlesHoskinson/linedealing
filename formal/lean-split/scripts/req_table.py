#!/usr/bin/env python3
"""Build or check the requirement table of one capability's README.

Each row quotes the sentence after **ID** in the capability's spec, lists the
Lean declarations whose doc comment or body names the ID (ranges "X-a to X-b"
included), and gives the state:

* `proved` when trace.json maps the ID to theorems (the map is read by hand
  against each theorem statement, not taken from a docstring);
* `exception: REASON` from trace.json, for an ID that the oracle does not state;
* `defined` when only definitions name it.

An ID that is neither named by a declaration nor listed as an exception fails.
The table sits between `<!-- req-table -->` and `<!-- /req-table -->` in the
README. `--check` compares the README with a fresh build, so a changed spec
sentence fails the trace gate until the table is rebuilt and read again.

usage: req_table.py PACKAGE_DIR           (rewrite the README table)
       req_table.py --check PACKAGE_DIR   (exit 1 when the README differs)
"""
import json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parents[3]   # the repository root
norm = lambda s: " ".join(s.split())
DECL = re.compile(r"^(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+)?(def|theorem|structure|inductive|abbrev|instance)\s+([A-Za-z0-9_'.]+)")

def sentences(spec, prefix):
    pat = rf"\*\*({prefix}-\d{{3}})\*\* (.*?)(?=\n\s*\n|\Z)"
    return {m[0]: norm(m[1]) for m in re.findall(pat, spec, flags=re.S)}

def expand(text, prefix):
    out = set()
    for a, b in re.findall(rf"{prefix}-(\d{{3}})\s+to\s+{prefix}-(\d{{3}})", text):
        out |= {f"{prefix}-{i:03d}" for i in range(int(a), int(b) + 1)}
    out |= set(re.findall(rf"{prefix}-\d{{3}}", text))
    return out

def lean_names(pkg, ns, prefix):
    names = {}
    for f in sorted((pkg / ns).glob("**/*.lean")):
        if f.name == "Audit.lean":
            continue
        cur, kind, pending, in_doc, in_mod, doc_inner = None, None, set(), False, False, False
        for line in f.read_text().splitlines():
            s = line.strip()
            if s.startswith("/-!"):
                in_mod = "-/" not in s[3:]
                continue
            if in_mod:
                in_mod = "-/" not in s
                continue
            if s.startswith("/--"):
                in_doc = "-/" not in s[3:]
                # an indented doc comment (a constructor or a field) belongs to
                # the enclosing declaration; one at column 0 to the next
                doc_inner = cur is not None and not line.startswith("/--")
                if doc_inner:
                    for i in expand(s, prefix):
                        names.setdefault(i, {})[cur] = kind
                else:
                    pending |= expand(s, prefix)
                continue
            if in_doc:
                if doc_inner:
                    for i in expand(s, prefix):
                        names.setdefault(i, {})[cur] = kind
                else:
                    pending |= expand(s, prefix)
                in_doc = "-/" not in s
                continue
            if line.startswith("--"):
                # a comment at column 0 introduces the next declaration
                pending |= expand(s, prefix)
                continue
            m = DECL.match(s)
            if m:
                kind, cur = m.group(1), m.group(2)
                for i in pending:
                    names.setdefault(i, {})[cur] = kind
                pending = set()
            if cur:
                for i in expand(line, prefix):
                    names.setdefault(i, {})[cur] = kind
    return names

def build(pkg):
    cfg = json.loads((pkg / "trace.json").read_text())
    prefix, ns = cfg["prefix"], cfg["namespace"]
    sent = sentences((ROOT / cfg["spec"]).read_text(), prefix)
    if len(sent) != cfg["count"]:
        sys.exit(f"req_table: {len(sent)} {prefix} sentences in {cfg['spec']}, trace.json says {cfg['count']}")
    names = lean_names(pkg, ns, prefix)
    proved, exc, ledger = cfg.get("proved", {}), cfg.get("exceptions", {}), cfg.get("ledger", {})
    for k in list(proved) + list(exc) + list(ledger):
        if k not in sent:
            sys.exit(f"req_table: trace.json names {k}, which the spec does not hold")
    decls = set()
    for f in (pkg / ns).glob("**/*.lean"):
        decls |= set(re.findall(r"^theorem\s+([A-Za-z0-9_'.]+)", f.read_text(), flags=re.M))
    for i, ts in proved.items():
        for t in ts:
            if t not in decls:
                sys.exit(f"req_table: {i}: theorem {t} is not a declaration of {ns}")
    rows = ["| ID | Sentence | Lean name | State | Ledger |", "|---|---|---|---|---|"]
    bad = []
    order = sorted(sent, key=lambda i: int(i.split("-")[1]))
    for i in order:
        ns_ = dict(names.get(i, {}))
        for t in proved.get(i, []):
            ns_[t] = "theorem"
        if i in proved:
            state = "proved"
        elif i in exc:
            state = f"exception: {exc[i]}"
        elif ns_:
            state = "defined"
        else:
            bad.append(i)
            continue
        lean = ", ".join(f"`{n}`" for n in sorted(ns_)) or "none"
        cell = sent[i].replace("|", "\\|")
        rows.append(f"| {i} | {cell} | {lean} | {state} | {ledger.get(i, '')} |")
    if bad:
        sys.exit(f"req_table: untraced IDs (no declaration, no exception): {bad}")
    return "\n".join(rows) + "\n", len(order)

def main():
    check = sys.argv[1] == "--check"
    pkg = pathlib.Path(sys.argv[-1]).resolve()
    table, n = build(pkg)
    readme = pkg / "README.md"
    text = readme.read_text()
    m = re.search(r"(<!-- req-table -->\n)(.*?)(<!-- /req-table -->)", text, flags=re.S)
    if not m:
        sys.exit("req_table: README has no <!-- req-table --> block")
    if check:
        if m.group(2) != table:
            sys.exit(f"trace: {pkg.name}: the README requirement table differs from the spec and the Lean names; rebuild it with req_table.py and read the changed rows")
        print(f"trace: {pkg.name}: {n} sentences pinned, every ID traced")
    else:
        readme.write_text(text[:m.start(2)] + table + text[m.end(2):])
        print(f"req_table: {pkg.name}: {n} rows written")

main()
