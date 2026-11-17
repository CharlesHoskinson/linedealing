#!/usr/bin/env python3
"""Replay passportShard Quint ITF traces through the shard oracle's --step mode.

Adapted from the factory's quint_replay.py
(software-factory/plugins/formal/scripts/quint_replay.py) for the interface of
SHARD-SPEC §4:

  in   {"state": S, "op": O}            (one JSON line; S and O as in §3-4)
  out  {"state": S', "obs": {"accepted": true}}
       {"refused": [CODES]}             (codes in ascending order)
       {"error": TEXT}

The differences from the factory script:
- the operation is an object built from the model's `lastOp` record, with the
  parameters §4 lists for that op name;
- a refusal is specified behaviour: the model records it in `lastRefused` and
  keeps `s` unchanged (PS-057); the replay compares the code list exactly;
- every key of S' is compared with the model's next `s` (cfg included, PS-001);
- sets are sorted natively (ascending integers, lexicographic tuples), as §3
  requires, not by JSON text;
- `pending` maps PNone -> null and PSome(r) -> {"succ", "adv"};
- `ghost`, `lastOp` and `lastRefused` are model-only and never sent.

Exit 0: every transition agrees. 1: a disagreement (first one, or all with
--keep-going). 2: usage, protocol or oracle error.

Usage:
  passport_replay.py --oracle PATH --traces DIR [DIR...] [--keep-going]
      [--regressions DIR] [--census]
      [--perturb-cfg KEY=JSON]   negative control: send a wrong cfg value and
                                 compare every key but cfg (must DISAGREE)
  passport_replay.py --oracle PATH --probe-domain
"""
import argparse
import json
import os
import pathlib
import select
import subprocess
import sys
import time

STATE_KEYS = [
    "cfg", "readers", "creds", "r_wrap", "r_wrap_ever", "pending", "unlock_log",
    "prf_log", "approved", "asserts", "hijacked", "authorized", "used_nf", "sigs",
    "adv_root", "adv_xf", "via_origin_leak", "via_recovery_leak", "via_theft",
    "via_provider", "via_quorum", "adv_cred", "adv_guard", "origin_corrupt",
    "committee_corrupt", "e_corrupt", "epoch",
]
CFG_KEYS = ["quorum", "n_guard", "native", "synced", "overlap"]

# §4: parameters of each operation
PARAMS = {
    "ENROLL": ["by", "d"], "REMOVE_DEVICE": ["by", "d"], "UNLOCK": ["d", "ic"],
    "APPROVE": ["d", "ic", "nf"], "AUTHORIZE": ["d", "ic", "nf"], "RELEASE": ["ic", "nf"],
    "PUBLISH_RWRAP": ["by"], "RECOVER_SUBMIT": ["succ"], "RECOVER_CANCEL": ["by"],
    "RECOVER_FINALISE": [], "E_REPROVISION": [], "ADV_RECOVER_SUBMIT": ["succ"],
    "CORRUPT_COMMITTEE": [], "CORRUPT_E": [], "CORRUPT_ORIGIN": [],
    "CORRUPT_GUARDIAN": ["g"], "STEAL_DEVICE": ["d", "unlocked"],
    "PROVIDER_TAKEOVER": ["d"], "ADV_ASSERT": ["d", "ic", "nf"],
    "ORIGIN_ASSERT": ["d", "ic", "nf"], "ADV_SIGN": ["ic"],
}


def sort_key(v):
    # integers ascending; tuples lexicographic; strings after numbers
    if isinstance(v, bool):
        return (0, int(v))
    if isinstance(v, int):
        return (1, v)
    if isinstance(v, list):
        return (2, [sort_key(x) for x in v])
    return (3, json.dumps(v, sort_keys=True))


def itf(v):
    if isinstance(v, list):
        return [itf(x) for x in v]
    if not isinstance(v, dict):
        return v
    if "#bigint" in v:
        return int(v["#bigint"])
    if "#tup" in v:
        return [itf(x) for x in v["#tup"]]
    if "#set" in v:
        return sorted((itf(x) for x in v["#set"]), key=sort_key)
    if "tag" in v and "value" in v and set(v) == {"tag", "value"}:
        if v["tag"] == "PNone":
            return None
        if v["tag"] == "PSome":
            return itf(v["value"])
        raise ValueError(f"unknown variant {v['tag']}")
    if "#map" in v or "#unserializable" in v:
        raise ValueError(f"unexpected ITF value {v}")
    return {k: itf(x) for k, x in v.items() if not k.startswith("#")}


def short(name):
    return name.rsplit("::", 1)[-1]


def load_trace(path):
    raw = json.loads(path.read_text())
    states = []
    for st in raw["states"]:
        named = {short(k): v for k, v in st.items() if not k.startswith("#")}
        s = itf(named["s"])
        if list(sorted(s)) != sorted(STATE_KEYS) or sorted(s["cfg"]) != sorted(CFG_KEYS):
            raise ValueError(f"{path.name}: model state keys differ from SHARD-SPEC §3")
        states.append({"s": s, "op": itf(named["lastOp"]), "refused": itf(named["lastRefused"])})
    if len(states) < 2:
        raise ValueError(f"{path.name}: no transition")
    return raw, states


def op_object(rec):
    name = rec["op"]
    if name not in PARAMS:
        raise ValueError(f"unknown op {name}")
    out = {"op": name}
    for p in PARAMS[name]:
        out[p] = rec[p]
    return out


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"))


class Oracle:
    def __init__(self, path, timeout):
        env = {**os.environ, "LEAN_ABORT_ON_PANIC": "1"}
        self.p = subprocess.Popen([path, "--step"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  env=env)
        self.timeout = timeout

    def ask(self, obj):
        self.p.stdin.write((json.dumps(obj, separators=(",", ":")) + "\n").encode())
        self.p.stdin.flush()
        deadline = time.monotonic() + self.timeout
        data = b""
        while b"\n" not in data:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.p.stdout], [], [], left)[0]:
                raise ValueError("oracle gave no answer in time")
            chunk = os.read(self.p.stdout.fileno(), 1 << 20)
            if not chunk:
                raise ValueError("oracle closed its output")
            data += chunk
        line, _, rest = data.partition(b"\n")
        if rest.strip():
            raise ValueError("oracle sent extra output")
        return json.loads(line)

    def close(self):
        self.p.stdin.close()
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            raise ValueError("oracle did not exit")
        if self.p.returncode != 0:
            raise ValueError(f"oracle exited {self.p.returncode}")


def write_regression(dirpath, src, raw, i, why):
    """Keep the shrunk trace: the one transition (state i -> i+1) that disagrees."""
    dirpath.mkdir(parents=True, exist_ok=True)
    out = dict(raw)
    out["states"] = [raw["states"][i], raw["states"][i + 1]]
    for k, st in enumerate(out["states"]):
        st = dict(st)
        st["#meta"] = {"index": k}
        out["states"][k] = st
    out["#meta"] = {"source": src.name, "step": i, "why": why}
    name = f"{src.parent.name}-{src.stem.replace('.itf', '')}-step{i}.itf.json"
    (dirpath / name).write_text(json.dumps(out, indent=1))
    return name


def replay(a):
    files = []
    for d in a.traces:
        files += sorted(pathlib.Path(d).glob("*.itf.json"))
    if not files:
        print("passport_replay: no traces", file=sys.stderr)
        return 2
    perturb = {}
    for kv in a.perturb_cfg or []:
        k, _, v = kv.partition("=")
        perturb[k] = json.loads(v)
    oracle = Oracle(a.oracle, a.timeout)
    agree = disagree = 0
    census = {}
    try:
        for f in files:
            raw, states = load_trace(f)
            for i in range(len(states) - 1):
                cur, nxt = states[i], states[i + 1]
                state = cur["s"]
                if perturb:
                    state = {**state, "cfg": {**state["cfg"], **perturb}}
                op = op_object(nxt["op"])
                got = oracle.ask({"state": state, "op": op})
                if "error" in got:
                    raise ValueError(f"oracle error at {f} step {i}: {got['error']}")
                model_refused = sorted(nxt["refused"])
                if model_refused:
                    expected = {"refused": model_refused}
                    if canon(nxt["s"]) != canon(cur["s"]):
                        raise ValueError(f"{f} step {i}: model changed state on a refusal")
                else:
                    after = nxt["s"]
                    if perturb:  # compare behaviour only: the oracle echoes the sent cfg
                        after = {**after, "cfg": state["cfg"]}
                    expected = {"state": after, "obs": {"accepted": True}}
                kind = "refused" if model_refused else "accepted"
                row = census.setdefault(op["op"], {"accepted": 0, "refused": 0, "disagree": 0})
                if canon(got) == canon(expected):
                    agree += 1
                    row[kind] += 1
                    continue
                disagree += 1
                row["disagree"] += 1
                if "state" in got and "state" in expected:
                    diff = {k: {"model": expected["state"][k], "oracle": got["state"].get(k)}
                            for k in STATE_KEYS if canon(expected["state"].get(k)) != canon(got["state"].get(k))}
                    extra = sorted(set(got["state"]) - set(STATE_KEYS))
                    why = {"diff": diff, "oracle_extra_keys": extra, "obs": got.get("obs")}
                else:
                    why = {"model": expected if "refused" in expected else "accepted",
                           "oracle": got if "refused" in got else "accepted"}
                print(f"DISAGREE {f.parent.name}/{f.name} step {i} op={canon(op)}: {canon(why)}")
                if a.regressions:
                    print(f"  kept {write_regression(pathlib.Path(a.regressions), f, raw, i, why)}")
                if not a.keep_going:
                    return 1
    finally:
        oracle.close()
    if a.census:
        print("CENSUS " + canon(census))
        unvisited = sorted(set(PARAMS) - {k for k, r in census.items() if r["accepted"]})
        unrefused = sorted(k for k in PARAMS if not census.get(k, {}).get("refused"))
        print(f"ops never accepted: {unvisited}; ops never refused: {unrefused}")
    print(f"passport_replay: {agree} agreeing, {disagree} disagreeing transitions in {len(files)} traces")
    return 1 if disagree else 0


def initial(cfg, d0=0):
    s = {k: [] for k in STATE_KEYS}
    s.update({"cfg": cfg, "readers": [d0], "creds": [d0], "prf_log": [d0], "pending": None,
              "epoch": 0})
    for k in ["r_wrap", "r_wrap_ever", "adv_root", "adv_xf", "via_quorum", "origin_corrupt",
              "committee_corrupt", "e_corrupt"]:
        s[k] = False
    return s


def probe_domain(a):
    """PS-002, PS-003, PS-005: a cfg outside the domain is refused for every op.
    Also a valid cfg is accepted (control)."""
    good = {"quorum": 2, "n_guard": 3, "native": [], "synced": [0], "overlap": []}
    cases = [
        ("valid cfg (control)", good, {"accepted": True}),
        ("quorum 0", {**good, "quorum": 0}, ["outside-state-domain"]),
        ("quorum > n_guard", {**good, "quorum": 4}, ["outside-state-domain"]),
        ("overlap non-empty", {**good, "overlap": [1]}, ["outside-state-domain"]),
        ("quorum 0 and overlap", {**good, "quorum": 0, "overlap": [0]}, ["outside-state-domain"]),
    ]
    oracle = Oracle(a.oracle, a.timeout)
    bad = 0
    try:
        for name, cfg, want in cases:
            for op in [{"op": "CORRUPT_ORIGIN"}, {"op": "UNLOCK", "d": 0, "ic": 0}]:
                got = oracle.ask({"state": initial(cfg), "op": op})
                ok = (got.get("obs") == want) if isinstance(want, dict) else (got.get("refused") == want)
                print(f"{'ok ' if ok else 'BAD'} {name} {op['op']}: {canon(got)[:160]}")
                bad += not ok
    finally:
        oracle.close()
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--traces", nargs="*", default=[])
    ap.add_argument("--keep-going", action="store_true")
    ap.add_argument("--regressions")
    ap.add_argument("--census", action="store_true")
    ap.add_argument("--perturb-cfg", action="append")
    ap.add_argument("--probe-domain", action="store_true")
    ap.add_argument("--timeout", type=float, default=30.0)
    a = ap.parse_args()
    if a.probe_domain:
        return probe_domain(a)
    return replay(a)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as e:
        print(f"passport_replay: {e}", file=sys.stderr)
        sys.exit(2)
