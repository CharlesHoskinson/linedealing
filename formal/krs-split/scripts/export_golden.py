#!/usr/bin/env python3
"""Export golden vectors for a kink corpus from a kink-implementation/1 oracle.

Golden vectors are the corpus's typed cases with the end the spec oracle gives.
Export them only after `krs kink compare` showed the KRS reference definition
and the oracle agree on every program (verdict `equal`), so each vector is
backed by two independent semantics.

Usage:
  export_golden.py --cases 'krs/kink/cases/*/case.toml' --oracle lean/.lake/build/bin/oracle \
      --source spec/capability.md --source lean/Capability/Spec.lean \
      --toolchain lean/lean-toolchain --out golden/vectors.json [--check]

The header of the file records where the vectors come from: the sha256 of each
--source file (the spec and the oracle's semantic module), keyed by the path as
given, and the toolchain string read from --toolchain. The oracle binary's digest
is host-local and is not recorded.

--check compares with the existing file, header included, and exits 1 on drift
(for CI and dw checks).
"""
import argparse
import glob
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tomllib


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", required=True, help="glob of case.toml files, as FLOW.toml's [[program]] cases")
    ap.add_argument("--oracle", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default=".", help="program ids are case paths relative to this directory")
    ap.add_argument("--source", action="append", default=[],
                    help="a file whose sha256 goes in the header (the spec, the oracle's semantic module); repeatable")
    ap.add_argument("--toolchain", help="a file holding the oracle's toolchain string (lean-toolchain)")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()

    header = {"sources": {s: hashlib.sha256(pathlib.Path(s).read_bytes()).hexdigest() for s in a.source}}
    if a.toolchain:
        header["toolchain"] = pathlib.Path(a.toolchain).read_text().strip()

    files = sorted(glob.glob(a.cases))
    if not files:
        print(f"export_golden: no cases match {a.cases}", file=sys.stderr)
        return 2
    vectors = []
    for f in files:
        inputs = tomllib.loads(pathlib.Path(f).read_text())["inputs"]
        program = str(pathlib.Path(f).resolve().relative_to(pathlib.Path(a.base).resolve()))
        req = {"protocol": "kink-implementation/1", "program": program, "inputs": inputs}
        out = subprocess.run(a.oracle, input=json.dumps(req), capture_output=True, text=True, check=True,
                             env={**os.environ, "LEAN_ABORT_ON_PANIC": "1"}, timeout=60)
        ans = json.loads(out.stdout)
        vectors.append({"program": program, "inputs": inputs, **ans})
    doc = {"schema": "formal-golden-vectors/1", "header": header, "vectors": vectors}
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    out = pathlib.Path(a.out)
    if a.check:
        old = json.loads(out.read_text()) if out.exists() else {}
        if old.get("header") != header:
            print(f"export_golden: {out} header differs: recorded {old.get('header')}, computed {header}; "
                  "rerun without --check after the oracle is checked against the changed sources",
                  file=sys.stderr)
            return 1
        if out.read_text() != text:
            print(f"export_golden: {out} is stale; rerun without --check", file=sys.stderr)
            return 1
        print(f"export_golden: {out} current ({len(vectors)} vectors)")
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(f"export_golden: wrote {len(vectors)} vectors to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
