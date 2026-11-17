#!/usr/bin/env python3
"""Replay Quint ITF traces through a Lean oracle's --step mode.

The Quint model is written from the spec and its EARS requirements; the Lean
oracle is the executable reference. Replaying the model's traces through the
oracle checks the oracle against the spec: every transition the model takes
must be the transition the oracle computes.

Protocol of the oracle's --step mode (JSON Lines on stdin/stdout):
  request  {"state": {...}, "op": <int>}
  answer   {"state": {...}}, {"refused": [CODE, ...]} or {"error": "..."}

"refused" answers a decoded line that the spec refuses, with the list of the
spec's refusal codes. "error" answers a line that does not decode.

A refusal of a state the model reached is a disagreement (exit 1): the model
and the oracle disagree on the domain. An error is a protocol failure (exit 2).
The oracle runs with LEAN_ABORT_ON_PANIC=1, so a Lean panic ends it instead of
returning a default value, and each answer must arrive within --timeout seconds.

Usage:
  quint_replay.py --oracle CMD... --traces DIR \
      --op-var lastOp --compare tokens,served,rejected \
      --const cap=3 --const rate=2 [--fill ops=0,len=0]

State fields the oracle needs but the model does not have are filled from
--const (fixed per instance) and --fill (defaults). Model-only variables are
left out with --drop. Only --compare fields are
compared; values may be nested (records, tuples, sets, maps; see itf_value). Exit 0 when every transition agrees, 1 on the first disagreement,
2 on a usage or protocol error.

--whole-run OPS,LEN also checks whole runs, for an oracle whose input is a
sequence of operations encoded as bits: operation i of the trace is bit i of
input OPS and the trace length is input LEN. Each trace becomes one
kink-implementation/1 request to the oracle's default mode (inputs: --const
plus OPS and LEN); the answer's cells must equal the trace's last state on the
--compare fields. This checks init, the stop condition and the input decoding,
which --step does not reach.
"""
import argparse
import json
import os
import pathlib
import select
import subprocess
import sys


def itf_value(v):
    """Decode an ITF value to plain JSON: integers, lists for tuples and lists,
    sorted lists for sets, objects for records, and objects or [key, value]
    lists for maps (objects when every key is a string or an integer)."""
    if isinstance(v, list):
        return [itf_value(x) for x in v]
    if not isinstance(v, dict):
        return v
    if "#bigint" in v:
        return int(v["#bigint"])
    if "#tup" in v:
        return [itf_value(x) for x in v["#tup"]]
    if "#set" in v:
        return sorted((itf_value(x) for x in v["#set"]), key=lambda x: json.dumps(x, sort_keys=True))
    if "#map" in v:
        pairs = [(itf_value(k), itf_value(x)) for k, x in v["#map"]]
        if all(isinstance(k, (str, int)) for k, _ in pairs):
            return {str(k): x for k, x in pairs}
        return sorted(([k, x] for k, x in pairs), key=lambda kv: json.dumps(kv, sort_keys=True))
    if "#unserializable" in v:
        raise ValueError(f"unserializable ITF value: {v['#unserializable']}")
    return {k: itf_value(x) for k, x in v.items() if not k.startswith("#")}


def short(name):
    """Quint qualifies instance variables (`inst::module::var`); keep the last part."""
    return name.rsplit("::", 1)[-1]


def pairs(spec):
    out = {}
    for item in spec or []:
        for kv in item.split(","):
            if kv:
                k, _, v = kv.partition("=")
                out[k.strip()] = int(v)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", nargs="+", required=True, help="oracle command; --step is appended")
    ap.add_argument("--traces", required=True, help="directory of *.itf.json files")
    ap.add_argument("--op-var", required=True)
    ap.add_argument("--compare", required=True)
    ap.add_argument("--const", action="append", default=[])
    ap.add_argument("--fill", action="append", default=[])
    ap.add_argument("--map", action="append", default=[], help="model=oracle field renames")
    ap.add_argument("--drop", action="append", default=[],
                    help="model-only variables not sent to the oracle (a strict oracle refuses unknown keys)")
    ap.add_argument("--whole-run", metavar="OPS,LEN", help="also replay each trace as one run (see above)")
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds per oracle answer")
    a = ap.parse_args()

    consts, fill = pairs(a.const), pairs(a.fill)
    rename = dict(m.split("=", 1) for m in a.map)
    compare = [c.strip() for c in a.compare.split(",") if c.strip()]
    files = sorted(pathlib.Path(a.traces).glob("*.itf.json"))
    if not files:
        print(f"quint_replay: no *.itf.json under {a.traces}", file=sys.stderr)
        return 2

    env = {**os.environ, "LEAN_ABORT_ON_PANIC": "1"}
    proc = subprocess.Popen(a.oracle + ["--step"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
    assert proc.stdin is not None and proc.stdout is not None
    checked = 0
    try:
        for f in files:
            states = json.loads(f.read_text())["states"]
            for i in range(len(states) - 1):
                names = [short(k) for k in states[i] if not k.startswith("#")]
                if len(names) != len(set(names)):
                    print(f"quint_replay: {f.name}: two variables share a short name {sorted(names)}; rename one", file=sys.stderr)
                    return 2
                cur = {rename.get(short(k), short(k)): itf_value(v) for k, v in states[i].items() if not k.startswith("#")}
                nxt = {rename.get(short(k), short(k)): itf_value(v) for k, v in states[i + 1].items() if not k.startswith("#")}
                op = nxt.pop(a.op_var, None)
                if op is None:
                    print(f"quint_replay: {f.name}: state {i + 1} has no {a.op_var}", file=sys.stderr)
                    return 2
                state = {**fill, **consts, **{k: v for k, v in cur.items() if k != a.op_var and k not in a.drop}}
                proc.stdin.write(json.dumps({"state": state, "op": op}) + "\n")
                proc.stdin.flush()
                ready, _, _ = select.select([proc.stdout], [], [], a.timeout)
                if not ready:
                    print(f"quint_replay: oracle gave no answer within {a.timeout}s at {f.name} step {i}", file=sys.stderr)
                    proc.kill()
                    return 2
                line = proc.stdout.readline()
                if not line:
                    print("quint_replay: oracle closed its output", file=sys.stderr)
                    return 2
                got = json.loads(line)
                if "error" in got:
                    print(f"quint_replay: oracle error at {f.name} step {i}: {got['error']}", file=sys.stderr)
                    return 2
                if "refused" in got:
                    print(f"DISAGREE {f.name} step {i} op={op}: the oracle refuses a state the model reached: "
                          f"{'|'.join(map(str, got['refused'])) if isinstance(got['refused'], list) else got['refused']}")
                    print(f"  from state {state}")
                    return 1
                missing = [k for k in compare if k not in nxt or k not in got["state"]]
                if missing:
                    # a misspelt or absent field would otherwise compare None with None and agree
                    print(f"quint_replay: --compare field(s) {missing} missing from the trace or the oracle state", file=sys.stderr)
                    return 2
                diff = {k: (nxt[k], got["state"][k]) for k in compare if nxt[k] != got["state"][k]}
                if diff:
                    print(f"DISAGREE {f.name} step {i} op={op}: model vs oracle {diff}")
                    print(f"  from state {state}")
                    return 1
                checked += 1
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    runs = 0
    if a.whole_run:
        ops_in, _, len_in = a.whole_run.partition(",")
        if not len_in:
            print("quint_replay: --whole-run needs OPS,LEN", file=sys.stderr)
            return 2
        for f in files:
            states = json.loads(f.read_text())["states"]
            seq = [itf_value(v) for st in states[1:] for k, v in st.items() if short(k) == a.op_var]
            if len(seq) != len(states) - 1 or any(o not in (0, 1) for o in seq):
                print(f"quint_replay: {f.name}: {a.op_var} is not a 0/1 sequence", file=sys.stderr)
                return 2
            inputs = {**consts, ops_in: sum(o << i for i, o in enumerate(seq)), len_in: len(seq)}
            req = {"protocol": "kink-implementation/1", "program": f.name, "inputs": inputs}
            out = subprocess.run(a.oracle, input=json.dumps(req), capture_output=True, text=True, env=env, timeout=a.timeout)
            if out.returncode != 0:
                print(f"quint_replay: oracle failed on whole run {f.name}: {out.stderr.strip()}", file=sys.stderr)
                return 2
            ans = json.loads(out.stdout)
            last = {rename.get(short(k), short(k)): itf_value(v) for k, v in states[-1].items() if not k.startswith("#")}
            cells = ans.get("cells", {})
            if ans.get("end") != "final" or any(k not in cells or k not in last for k in compare):
                print(f"quint_replay: whole run {f.name}: answer {ans} lacks the --compare fields", file=sys.stderr)
                return 2
            diff = {k: (last[k], cells[k]) for k in compare if last[k] != cells[k]}
            if diff:
                print(f"DISAGREE whole run {f.name} ({len(seq)} ops): model vs oracle {diff}")
                return 1
            runs += 1
    if checked == 0:
        print("quint_replay: no transition was checked (empty or one-state traces)", file=sys.stderr)
        return 2
    extra = f", and {runs} whole runs" if a.whole_run else ""
    print(f"quint_replay: {checked} transitions in {len(files)} traces{extra} agree on {','.join(compare)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
