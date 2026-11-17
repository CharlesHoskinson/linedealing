#!/usr/bin/env python3
"""Flatten splitspec ITF traces for quint_replay.py.

The model keeps its protocol state in one record variable `st`, its history (ghost) state
in `g` and the replay contract in `lastOp`. quint_replay.py compares top-level fields, so
this tool hoists every field of `st` to a top-level variable with the spec's name
(`requests`, `cslots`, `cp`, ...), renames every field of `g` to `g_<field>` (send them to
the oracle with `--drop`, or leave them out of `--compare`), and keeps `lastOp`.

Usage: flatten_itf.py SRC_DIR DST_DIR
"""
import json
import pathlib
import sys


def short(name):
    return name.rsplit("::", 1)[-1]


def flatten_state(state):
    out = {}
    for k, v in state.items():
        if k.startswith("#"):
            out[k] = v
            continue
        s = short(k)
        if s == "st":
            for f, fv in v.items():
                out[f] = fv
        elif s == "g":
            for f, fv in v.items():
                out["g_" + f] = fv
        else:
            out[s] = v
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    dst.mkdir(parents=True, exist_ok=True)
    files = sorted(src.glob("*.itf.json"))
    if not files:
        print(f"flatten_itf: no *.itf.json under {src}", file=sys.stderr)
        return 2
    for f in files:
        doc = json.loads(f.read_text())
        # A test that ends in `.fail()` (a blocked step) writes a last state with no variables;
        # drop it, the trace then ends at the state the blocked event left unchanged.
        doc["states"] = [flatten_state(s) for s in doc["states"]
                         if any(not k.startswith("#") for k in s)]
        if "vars" in doc:
            doc["vars"] = sorted({k for s in doc["states"] for k in s if not k.startswith("#")})
        (dst / f.name).write_text(json.dumps(doc))
    print(f"flatten_itf: {len(files)} traces -> {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
