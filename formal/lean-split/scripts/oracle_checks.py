#!/usr/bin/env python3
"""The scripted parts of the oracle gate for one capability package.

  oracle_checks.py words   PACKAGE_DIR   word search on comment-stripped code
  oracle_checks.py cases   PACKAGE_DIR   codec and refusal cases of cases.json through the binary
  oracle_checks.py mutants PACKAGE_DIR   Spec mutants of mutants.json must fail the build
  oracle_checks.py ledger  PACKAGE_DIR   the ambiguity ledger has no open entry

words: every module under the spec root (nested directories included) gets the
full word list, and the codec package and Main.lean the base list (Main and the
codec loop with `partial`). Audit modules are the audit and are skipped.

cases: each case is {"args": [...], "input": TEXT or JSON, "rc": EXIT,
"expect": JSON or null}; `input` that is not a string is serialized; for
`--step` the input is a list of lines and `expect` a list of answers. Every
oracle process runs with LEAN_ABORT_ON_PANIC=1; non-empty stderr on exit 0 fails.

mutants: each mutant {"name", "file", "old", "new"} replaces one occurrence of
`old` in `file` in a copy of the codec and the package (the layout is kept, so
`../codec` resolves) and must make `lake build --wfail` fail on a Lean error in
a module of the package. compare and golden vectors come from the oracle and
cannot kill a mutant of it.
"""
import json, os, pathlib, re, shutil, subprocess, sys, tempfile

def strip(t):
    t = re.sub(r"/-.*?-/", "", t, flags=re.S)
    return re.sub(r"--.*", "", t)

BASE = r"sorry|admit|axiom|native_decide|bv_decide|implemented_by|extern|csimp|partial_fixpoint"
SPEC = BASE + r"|partial|unsafe|HashMap|HashSet|TreeMap|Float|Float32"

def words(pkg):
    cfg = json.loads((pkg / "trace.json").read_text())
    ns = cfg["namespace"]
    codec = pkg.parent / "codec"
    files = [(p, True) for p in (pkg / ns).glob("**/*.lean")]
    files += [(pkg / "Main.lean", False)] + [(p, False) for p in (codec / "SplitCodec").glob("**/*.lean")]
    bad = []
    for p, spec in files:
        if p.name in ("Audit.lean", "AuditCmd.lean"):
            continue
        text = strip(p.read_text())
        rel = p.relative_to(pkg.parent)
        w = SPEC if spec else BASE
        bad += [f"{rel}: {m}" for m in re.findall(rf"\b({w})\b", text)]
        bad += [f"{rel}: decide +native" for _ in re.findall(r"\+native", text)]
        if spec:
            bad += [f"{rel}: {m}" for m in re.findall(r"\b(?:get|panic|unreachable)!|\]!", text)]
            if re.search(r"^\s*import\s+Lean", text, flags=re.M) and p.name == "Spec.lean":
                bad.append(f"{rel}: import Lean")
    if bad:
        sys.exit("oracle: escape hatch: " + ", ".join(bad))
    print(f"oracle: {pkg.name}: word search clean ({len(files)} files)")

def cases(pkg):
    oracle = pkg / ".lake/build/bin/oracle"
    env = {**os.environ, "LEAN_ABORT_ON_PANIC": "1"}
    cs = json.loads((pkg / "cases.json").read_text())
    for c in cs:
        args = c.get("args", [])
        if args == ["--step"]:
            text = "".join((l if isinstance(l, str) else json.dumps(l)) + "\n" for l in c["input"])
        else:
            text = c["input"] if isinstance(c["input"], str) else json.dumps(c["input"])
        p = subprocess.run([str(oracle), *args], input=text, capture_output=True, text=True, timeout=120, env=env)
        if p.returncode != c.get("rc", 0):
            sys.exit(f"oracle: case {c['name']}: exit {p.returncode}, want {c.get('rc', 0)}; stderr {p.stderr[-500:]!r}")
        if p.returncode == 0 and p.stderr:
            sys.exit(f"oracle: case {c['name']}: stderr {p.stderr[-500:]!r}")
        if c.get("expect") is not None:
            got = [json.loads(l) for l in p.stdout.splitlines()]
            want = c["expect"] if args == ["--step"] else [c["expect"]]
            if c.get("match") == "keys":
                ok = len(got) == len(want) and all(sorted(g) == sorted(w) for g, w in zip(got, want))
            elif c.get("match") == "subset":
                ok = len(got) == len(want) and all(sub(w, g) for g, w in zip(got, want))
            else:
                ok = got == want
            if not ok:
                sys.exit(f"oracle: case {c['name']}: answered {json.dumps(got)[:1500]}, want {json.dumps(want)[:1500]}")
    print(f"oracle: {pkg.name}: {len(cs)} codec and refusal cases hold")

def sub(w, g):
    """`w` is contained in `g`: every key of an object, recursively; other values equal."""
    if isinstance(w, dict):
        return isinstance(g, dict) and all(k in g and sub(v, g[k]) for k, v in w.items())
    return w == g

def mutants(pkg):
    ms = json.loads((pkg / "mutants.json").read_text())
    ns = json.loads((pkg / "trace.json").read_text())["namespace"]
    alive = []
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        shutil.copytree(pkg.parent / "codec", root / "codec", ignore=shutil.ignore_patterns(".lake"))
        work = root / pkg.name
        shutil.copytree(pkg, work, ignore=shutil.ignore_patterns(".lake"))
        def build():
            return subprocess.run(["lake", "build", "--wfail", ns], cwd=work, capture_output=True, text=True, timeout=3600)
        r = build()
        if r.returncode != 0:
            sys.exit("oracle: mutants: the unmutated copy does not build:\n" + (r.stdout + r.stderr)[-3000:])
        for m in ms:
            f = work / m["file"]
            orig = f.read_text()
            if orig.count(m["old"]) != 1:
                sys.exit(f"oracle: mutant '{m['name']}': `{m['old']}` occurs {orig.count(m['old'])} times in {m['file']}, not once")
            f.write_text(orig.replace(m["old"], m["new"]))
            r = build()
            f.write_text(orig)
            out = r.stdout + r.stderr
            if r.returncode == 0:
                alive.append(m["name"])
                print(f"oracle: mutant '{m['name']}': ALIVE")
                continue
            killers = sorted(set(re.findall(rf"error: ({re.escape(ns)}/[\w/]+\.lean):(\d+)", out)))
            if not killers:
                sys.exit(f"oracle: mutant '{m['name']}' failed the build without a Lean error:\n" + out[-2000:])
            print(f"oracle: mutant '{m['name']}' killed at {', '.join(f + ':' + n for f, n in killers[:4])}")
    if alive:
        sys.exit("oracle: mutants alive: " + ", ".join(alive))
    print(f"oracle: {pkg.name}: {len(ms)} Spec mutants killed")

def ledger(pkg):
    p = pkg / "ambiguity-ledger.md"
    if not p.exists():
        sys.exit(f"oracle: no ambiguity ledger at {p}")
    rows = [[c.strip() for c in re.split(r"(?<!\\)\|", l.strip().strip("|"))]
            for l in p.read_text().splitlines() if l.lstrip().startswith("|")]
    if not rows or "Status" not in rows[0]:
        sys.exit("oracle: the ambiguity ledger has no table with a Status column")
    col = rows[0].index("Status")
    entries = [r for r in rows[1:] if not re.fullmatch(r"[-: ]*", "".join(r))]
    statuses = [r[col].strip("` ") if col < len(r) else "" for r in entries]
    if any(s not in ("open", "ruled", "held") for s in statuses):
        sys.exit(f"oracle: ledger status must be open, ruled or held: {statuses}")
    if "open" in statuses:
        sys.exit("oracle: open ambiguity ledger entries: " + ", ".join(r[0] for r, s in zip(entries, statuses) if s == "open"))
    print(f"oracle: {pkg.name}: ambiguity ledger has {len(entries)} entries, none open")

{"words": words, "cases": cases, "mutants": mutants, "ledger": ledger}[sys.argv[1]](pathlib.Path(sys.argv[2]).resolve())
