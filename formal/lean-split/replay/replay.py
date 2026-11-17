#!/usr/bin/env python3
"""Replay the item 14 Quint traces (formal/quint-spec) through the request oracle and the
authorization, slots, envelope and shard-holders lanes.

The Quint model is written from the spec only. Each trace step names its event in
`lastOp`. This driver maps the event to request-oracle operations (README.md, "Event
map"), sends them to the oracle's `--step` mode, threads the oracle's own state from step
to step (the oracle state is never reset from the model), and compares the request
projection of the model state with the oracle state after every step.

  replay.py --oracle PATH --traces DIR [DIR ...] [--expect-disagree DIR@EVENT@TEXT ...] [--json OUT]

The mode and profile of a trace directory come from its name (`tee_p2_...`,
`nontee_p1_...`). Exit 0 only when every trace of every --traces directory agrees and
every trace of every --expect-disagree directory disagrees first at a step of model event
EVENT with TEXT in the disagreement (a negative control); exit 1 otherwise; exit 2 on
a usage, decode or protocol error (an oracle `error` answer, a timeout, stderr output or
a nonzero oracle exit). The oracle runs with LEAN_ABORT_ON_PANIC=1.
"""
import argparse
import collections
import json
import os
import pathlib
import re
import select
import subprocess
import sys

N, F, DELTA_C, DELTA_HOLD = 4, 1, 4, 1
Q = (N + F + 2) // 2
W = N - 1 - F
TERMINAL = {"FINAL", "VOID", "EXPIRED"}
# Events that the request oracle has no part in: their model step must leave every
# compared request field unchanged (authorization, ECDSA slots and Midnight facts).
NO_REQUEST_OP = {"authorize", "finalize_auth", "revoke", "tick_midnight", "ecdsa_prec"}
# Revision 6 (DECISIONS 67): the asset record of one address with a network-created shard.
# Only the shard-holders lane drives them; every other lane takes them as stutter steps.
ADDR_OPS = {"register_addr", "holder_ack", "creator_ack", "ack_ok", "acknowledge", "pay_addr"}
NO_REQUEST_OP |= ADDR_OPS
# Refusal events whose codes belong to another package's oracle.
OTHER_REFUSALS = {("authorize", "nf_used"): "authorization", ("revoke", "not_revocable"): "authorization",
                  ("reissue", "bad_carry"): "authorization", ("checkpoint", "pending_gap"): "checkpoint",
                  ("checkpoint", "h_lowered"): "checkpoint", ("checkpoint", "restart_jump"): "checkpoint",
                  ("checkpoint", "pending_min_lowered"): "checkpoint",
                  ("ack_ok", "ack_refused"): "shard-holders", ("acknowledge", "no_ack_certificate"): "shard-holders"}


class ProtocolError(Exception):
    pass


class Disagree(Exception):
    def __init__(self, cls, text):
        super().__init__(text)
        self.cls = cls
        self.text = text


def itf(v):
    """ITF to plain values: ints, lists for tuples, sorted lists for sets, dicts for
    records and maps (map keys decoded)."""
    if isinstance(v, list):
        return [itf(x) for x in v]
    if not isinstance(v, dict):
        return v
    if "#bigint" in v:
        return int(v["#bigint"])
    if "#tup" in v:
        return tuple(itf(x) for x in v["#tup"])
    if "#set" in v:
        return sorted((itf(x) for x in v["#set"]), key=lambda x: json.dumps(x, sort_keys=True, default=list))
    if "#map" in v:
        return {itf(k) if not isinstance(itf(k), list) else tuple(itf(k)): itf(x) for k, x in v["#map"]}
    if "#unserializable" in v:
        raise ProtocolError("unserializable ITF value")
    return {k: itf(x) for k, x in v.items() if k != "#meta"}


def opt(x):
    """The model writes an absent value as -1 or 0 (heights, variants); the oracle as null."""
    return None if x is None or x < 0 else x


def opt0(x):
    return None if x is None or x <= 0 else x


class Oracle:
    def __init__(self, path, timeout):
        env = {**os.environ, "LEAN_ABORT_ON_PANIC": "1"}
        self.err = open(os.devnull, "w") if False else None
        self.proc = subprocess.Popen([path, "--step"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, env=env, bufsize=1)
        self.timeout = timeout
        self.calls = 0

    def ask(self, line):
        self.calls += 1
        self.proc.stdin.write(json.dumps(line) + "\n")
        self.proc.stdin.flush()
        ready, _, _ = select.select([self.proc.stdout, self.proc.stderr], [], [], self.timeout)
        if not ready:
            raise ProtocolError(f"oracle gave no answer within {self.timeout}s")
        if self.proc.stderr in ready and self.proc.stdout not in ready:
            raise ProtocolError("oracle wrote to stderr: " + self.proc.stderr.readline().strip())
        out = self.proc.stdout.readline()
        if not out:
            raise ProtocolError(f"oracle ended (exit {self.proc.poll()})")
        ans = json.loads(out, parse_constant=lambda c: (_ for _ in ()).throw(ProtocolError(c)))
        if "error" in ans:
            raise ProtocolError("oracle error: " + ans["error"])
        return ans

    def step(self, state, op):
        ans = self.ask({"state": state, "op": op})
        if "refused" in ans:
            return None, ans["refused"]
        return ans["state"], ans["obs"]

    def node(self, state, eid, view):
        ans = self.ask({"node": {"state": state, "eid": eid, "view": view}})
        if "refused" in ans:
            raise ProtocolError(f"node query refused: {ans['refused']}")
        return ans["acts"]

    def close(self):
        self.proc.stdin.close()
        rc = self.proc.wait(timeout=10)
        err = self.proc.stderr.read()
        if rc != 0 or err:
            raise ProtocolError(f"oracle exit {rc}, stderr {err[:200]!r}")


def instance(d):
    m = re.search(r"(nontee|tee)_(p1|p2)", d.name)
    if not m:
        raise ProtocolError(f"{d}: directory name names no instance (tee|nontee)_(p1|p2)")
    return ("NON_TEE" if m.group(1) == "nontee" else "TEE"), m.group(2).upper()


def init_state(mode):
    return {"params": {"n": N, "f": F, "delta_c": DELTA_C, "delta_hold": DELTA_HOLD, "mode": mode},
            "height": 0, "cp_height": 0, "epochs": [{"e": 1, "n": N, "f": F}], "host_med": [], "requests": []}


# ---------------------------------------------------------------- projections

def model_proj(r, posts):
    return {
        "phase": r["phase"], "reason": r["reason"], "outcome": r["outcome"],
        "any_release": r["any_release"], "restart_end": r["restart_end"],
        "anchor": [opt0(r["anchor"][1]), opt0(r["anchor"][2])],
        "released": [opt0(r["released"][1]), opt0(r["released"][2])],
        "order_pos": opt(r["order_pos"]), "exp_c": opt(r["exp_c"]), "end_height": opt(r["end_height"]),
        "exp": r["exp"], "early_complaint": r["complaint"] == "early", "dealer_fault": r["complaint"] == "late",
        "filled": r["filled"] and r["collecting"],
        "posts": sorted((p["kind"], p["epoch"], p["member"] - 1, p["reason"]) for p in posts if p["eid"] == r["eid"]),
    }


def oracle_proj(r):
    pad = lambda xs: (list(xs) + [None, None])[:2]
    return {
        "phase": r["phase"], "reason": r["reason"], "outcome": r["outcome"],
        "any_release": r["any_release"], "restart_end": r["restart_end"],
        "anchor": pad(r["anchor"]), "released": pad(r["released"]),
        "order_pos": r["order_pos"], "exp_c": r["exp_c"], "end_height": r["end_height"], "exp": r["exp"],
        "early_complaint": r["early_complaint"], "dealer_fault": r["dealer_fault"],
        "filled": bool(r["positions"]) and r["positions"][0] is not None,
        "posts": sorted([("FINAL", p["epoch"], p["member"], "NONE") for p in r["final_posts"]]
                        + [("VOID", p["epoch"], p["member"], p["reason"]) for p in r["void_posts"]]),
    }


def diff(a, b):
    return {k: (a[k], b[k]) for k in a if a[k] != b[k]}


# ---------------------------------------------------------------- views for node queries

def view(**kw):
    v = {"share_ok": True, "sent_header": True, "hdr": "OK", "auth": "IN_FORCE", "revoked_at": None,
         "mid_final": 0, "obs_mid": [0, 0], "hold_age": 0, "slots": "OK", "admission_ok": True,
         "voted_opened": False, "voted_admit": False, "rel_check": True, "acks": [0, 0], "bound": True,
         "sent_gens": [], "contrib_fail": False, "sees_confirm": False, "posted_final": False,
         "pin_spent": False, "settled": False, "signed_leaf": None}
    v.update(kw)
    return v


def release_view(ms, e, mode):
    """The node's view at a model release step: the model's guards of sendRelease and
    recordRelease hold (in force, not revoked, release check passed, RQ-033 hold age)."""
    a = ms["auths"][e]
    age = max(0, ms["midnight_height"] - a["final_height"])
    acks = [W, W] if mode == "TEE" else [0, 0]
    return view(hold_age=age, acks=acks)


class Run:
    def __init__(self, oracle, mode, profile, census, cover, relax=False):
        self.relax = relax
        self.relaxed = {}
        self.o, self.mode, self.profile = oracle, mode, profile
        self.census, self.cover = census, cover
        self.hseq = 1000

    def apply(self, ost, op, e=None, pending=()):
        new, obs = self.o.step(ost, op)
        if new is None:
            e = op.get("eid", e)
            if e is not None and e in pending and "terminal" in obs:
                raise Disagree("RQ-046 timing", f"oracle refuses {op['op']} on request {e} it expired at the height tick; the model still acts on it")
            raise Disagree("oracle refuses", f"oracle refuses {op} with {obs}")
        return new

    def ops_for(self, kind, e, arg, ms0, ms1):
        """The oracle operations of one model event (README, "Event map")."""
        h0 = ms0["board_height"]
        r0 = ms0["requests"].get(e)
        r1 = ms1["requests"].get(e)
        if kind in NO_REQUEST_OP or kind == "expire":
            return []
        if kind == "post":
            return [{"op": "post", "eid": e, "epoch": r1["epoch"], "exp": r1["exp"], "type": r1["req_type"],
                     "profile": r1["profile"]}]
        if kind == "order":
            return [{"op": "tick", "height": h0 + 1}, {"op": "order", "eid": e, "qc": True, "p": arg}]
        if kind == "tick":
            return [{"op": "tick", "height": arg}]
        if kind == "checkpoint":
            return [{"op": "land_checkpoint", "height": h0}, {"op": "tick", "height": h0 + 1}]
        if kind == "complain":
            return [{"op": "complaint", "eid": e}]
        if kind == "open":
            if arg == 0:      # RQ-014: a malformed header leaves the request ORDERED
                return []
            k = r1["K"]
            return [{"op": "open", "eid": e, "K": k, "L": r1["L"], "collecting": r1["collecting"],
                     "positions": 1 if r1["collecting"] else 0, "rates": list(range(1, k + 1))}]
        if kind == "opened_vote":
            return [{"op": "vote_opened", "eid": e, "node": n, "hash": 1} for n in range(Q)]
        if kind == "frame":
            self.hseq += 1
            return [{"op": "frame", "eid": e, "frame": {"position": 0, "token_ok": True, "lengths_ok": True,
                                                         "height": h0, "cid": self.hseq}}]
        if kind == "frame_complaint":
            return [{"op": "detach", "eid": e, "position": 0}]
        if kind == "admit":
            self.hseq += 1
            hh = self.hseq
            return [{"op": "host_fee", "h": hh, "m": arg}] + \
                   [{"op": "vote_admit", "eid": e, "node": n, "hash": 1, "h": hh} for n in range(Q)]
        if kind == "anchor2":
            self.hseq += 1
            hh = self.hseq
            return [{"op": "host_fee", "h": hh, "m": arg},
                    {"op": "obs2", "eid": e, "gen1_missed": True, "heights": [hh] * (F + 1)}]
        if kind == "send_release":
            g, j = divmod(arg, 10)
            return [{"op": "release", "eid": e, "g": g, "j": j}] if self.mode == "TEE" else []
        if kind == "record_release":
            return [{"op": "release", "eid": e, "g": arg, "j": r1["released"][arg]}]
        if kind == "host_confirm":
            return [{"op": "confirm", "eid": e}]
        if kind in ("post_final", "post_void"):
            ep, m = divmod(arg, 10)
            if kind == "post_final":
                return [{"op": "post_final", "eid": e, "epoch": ep, "member": m - 1, "ct": 0}]
            new = [p for p in ms1["posts"] if p not in ms0["posts"]]
            if len(new) != 1:
                raise ProtocolError(f"post_void step adds {len(new)} posts")
            return [{"op": "post_void", "eid": e, "epoch": ep, "member": m - 1, "reason": new[0]["reason"]}]
        if kind == "rotate":
            return [{"op": "rotate", "e": arg, "n": N, "f": F}]
        if kind == "restart":
            hit = sorted(x for x in ms1["requests"] if ms1["requests"][x]["restart_end"]
                         and not ms0["requests"][x]["restart_end"])
            return [{"op": "restart_burn", "eid": x} for x in hit]
        if kind == "reissue":
            return [{"op": "carry", "eid": e}]
        raise ProtocolError(f"unmapped event {kind}")

    def refusal(self, kind, e, code, ms, ost):
        """A refused model event: the oracle must refuse it with the model's code among
        its codes. The probe leaves the threaded oracle state unchanged."""
        h = ms["board_height"]
        if (kind, code) in OTHER_REFUSALS:
            return "other:" + OTHER_REFUSALS[(kind, code)]
        if kind == "admit" and code in ("unknown_request", "terminal"):
            ops = [{"op": "vote_admit", "eid": e, "node": 0, "hash": 1, "h": 1}]
        elif kind == "order":
            ops = [{"op": "tick", "height": h + 1}, {"op": "order", "eid": e, "qc": code != "no_qc", "p": h + 1}]
        elif kind == "frame":
            ops = [{"op": "frame", "eid": e, "frame": {"position": 0, "token_ok": True, "lengths_ok": True,
                                                        "height": h, "cid": 1}}]
        elif kind == "post_void" and code == "unknown_epoch":
            ops = [{"op": "post_void", "eid": e, "epoch": 2, "member": 0, "reason": "REVOKED"}]
        elif kind == "admit" and code in ("not_in_force", "above_window", "settled"):
            a = ms["auths"].get(e)
            inforce = a is not None and a["final_height"] >= 0
            settled = a is not None and a["settled"] != "NONE"
            r = ms["requests"][e]
            above = r["suite"] == "SCHNORR" and any(
                r["cslot"][g] > ms["cp"]["h"] + 2 for g in range(1, r["G"] + 1))
            v = view(auth="IN_FORCE" if inforce else "NOT_IN_FORCE", settled=settled,
                     slots="ABOVE_WINDOW" if above else "OK")
            acts = self.o.node(ost, e, v)
            got = [x["code"] for x in acts if x["act"] == "refuse"]
            if code not in got:
                raise Disagree("refusal code", f"model refuses {kind} with {code}; the honest node gives {acts}")
            return "node"
        else:
            raise ProtocolError(f"unmapped refusal {kind}/{code}")
        st = ost
        for op in ops[:-1]:
            st = self.apply(st, op)
        new, obs = self.o.step(st, ops[-1])
        if new is not None:
            raise Disagree("refusal code", f"model refuses {kind} with {code}; oracle accepts {ops[-1]}")
        if code not in obs:
            raise Disagree("refusal code", f"model refuses {kind} with {code}; oracle refuses with {obs}")
        return "board"

    def node_release(self, kind, e, arg, ms0, ost, pending):
        """RQ-030, RQ-037, RQ-069: before a model release step the honest node's acts hold
        the act the model takes (TEE and NON_TEE send: `release`; NON_TEE record:
        `release_record`)."""
        if kind == "send_release":
            g, j = divmod(arg, 10)
            want = {"act": "release", "g": g, "j": j}
        else:
            g = arg
            want = {"act": "release_record", "g": g, "j": ms0["requests"][e]["anchor"][g]}
        acts = self.o.node(ost, e, release_view(ms0, e, self.mode))
        if want not in acts and e in pending:
            raise Disagree("RQ-046 timing", f"model {kind} on request {e} after its expiry height; the oracle expired it at the tick")
        if want not in acts:
            raise Disagree("node release", f"model {kind} {want}; honest node acts {acts}")
        if kind == "send_release" and self.mode == "NON_TEE":
            self.hits.append("RQ-069 send after record (node)")
        if kind == "record_release":
            self.hits.append("RQ-069 record before send (node)")

    def compare(self, ms, ost, pending, kind, e):
        mreq = ms["requests"]
        oreq = {r["eid"]: r for r in ost["requests"]}
        if set(mreq) != set(oreq):
            raise Disagree("request set", f"model eids {sorted(mreq)}, oracle eids {sorted(oreq)}")
        if ms["board_height"] != ost["height"]:
            raise Disagree("height", f"model {ms['board_height']}, oracle {ost['height']}")
        if sorted(ms["epochs"]) != sorted(x["e"] for x in ost["epochs"]):
            raise Disagree("epochs", f"model {ms['epochs']}, oracle {ost['epochs']}")
        n = 0
        for x in sorted(mreq):
            mp, op = model_proj(mreq[x], ms["posts"]), oracle_proj(oreq[x])
            if x in pending:
                if kind == "expire" and e == x:
                    pending.pop(x)
                    if mp["end_height"] != op["end_height"]:
                        if not self.relax:
                            raise Disagree("RQ-046 timing", f"request {x}: the model expires it at height "
                                           f"{mp['end_height']}, the oracle at the tick to {op['end_height']}")
                        self.cover["relaxed: expiry height differs"] += 1
                        self.relaxed[x] = (mp["end_height"], op["end_height"])
                elif mp != pending[x]:
                    raise Disagree("RQ-046 timing", f"request {x}: the model changes it after its expiry height "
                                   f"({diff(pending[x], mp)}); the oracle expired it at the tick")
                else:
                    continue
            if op["phase"] == "EXPIRED" and mp["phase"] not in TERMINAL and ms["board_height"] > mp["exp"]:
                pending[x] = mp                  # the model's `expire` event is still to come
                continue
            if self.relaxed.get(x) == (mp["end_height"], op["end_height"]):
                mp = {**mp, "end_height": op["end_height"]}
            d = diff(mp, op)
            if d:
                raise Disagree("state", f"request {x}: " + "; ".join(f"{k}: model {a}, oracle {b}" for k, (a, b) in d.items()))
            n += 1
        return n


# ---------------------------------------------------------------- lanes of the other packages
#
# Each lane threads its own oracle state from its own oracle process. A disagreement ends
# that lane for the trace; the other lanes go on.

def initial_state(path, inputs, timeout):
    """The oracle's state at `init`, from its default mode with no operations."""
    env = {**os.environ, "LEAN_ABORT_ON_PANIC": "1"}
    req = {"protocol": "kink-implementation/1", "program": "replay", "inputs": inputs}
    out = subprocess.run([path], input=json.dumps(req), capture_output=True, text=True, env=env, timeout=timeout)
    if out.returncode != 0 or out.stderr:
        raise ProtocolError(f"{path}: default mode exit {out.returncode}, stderr {out.stderr[:200]!r}")
    ans = json.loads(out.stdout)
    if ans.get("end") != "final":
        raise ProtocolError(f"{path}: default mode answers {ans}")
    return ans["cells"]["state"]


def live(r):
    return r["phase"] not in TERMINAL


class Lane:
    name = "?"
    other = set()        # refusal codes of other packages: counted, not replayed

    def __init__(self, oracle, mode, profile, cover, s0):
        self.o, self.mode, self.profile, self.cover, self.s0 = oracle, mode, profile, cover, s0
        self.hits = []

    def apply(self, ost, op):
        new, obs = self.o.step(ost, op)
        if new is None:
            raise Disagree("oracle refuses", f"{self.name} oracle refuses {op} with {obs}")
        return new

    def probe(self, ost, op, code, kind):
        new, obs = self.o.step(ost, op)
        if new is not None:
            raise Disagree("refusal code", f"model refuses {kind} with {code}; {self.name} oracle accepts {op}")
        if code not in obs:
            raise Disagree("refusal code", f"model refuses {kind} with {code}; {self.name} oracle refuses with {obs}")


class AuthLane(Lane):
    """split-authorization: the asset record and the authorizations (AU-001 to AU-029).
    Model nullifiers are integers; the lane maps each one to the oracle's `Nf`
    (`fresh n` for a new coin, `(auth, outcome)` for a settlement successor)."""
    name = "authorization"
    mine = {("authorize", "nf_used"), ("revoke", "not_revocable"), ("reissue", "bad_carry")}

    def start(self, ms):
        self.nf = {1: {"fresh": 1}}
        p2 = self.profile == "P2"
        st = self.apply(self.s0, {"op": "charter", "cid": 1, "profile": self.profile, "board_first": False,
                                  "stateful": False})
        st = self.apply(st, self.rec_op(1, 1))
        if ms["lastOp"]["kind"] == "init_armed":
            st = self.apply(st, {"op": "authorize", "call": self.call(ms, 1, 1, {"fresh": 1}, 1)})
            st = self.apply(st, {"op": "finalize", "auth": 1, "height": ms["auths"][1]["final_height"]})
        return st

    def rec_op(self, rid, nf):
        return {"op": "record", "rid": rid, "cid": 1, "cm_addr": rid, "nf": {"fresh": nf}, "hold_tag": 1,
                "slr_own": 1, "slr_G": 1 if self.profile == "P2" else None}

    def call(self, ms, rid, e, nf, pin, carry=None):
        src = ms["requests"][e]["source"]
        if src == "NONE":       # a probe for a request that no wallet authorizes (AU-022 refusal)
            src = "OWNER"
        return {"rid": rid, "nf": nf, "auth": e, "rh": 0, "source": src, "slot": None, "inputs_ok": True,
                "pred_ok": True, "in_gamma": True, "blacklisted": False, "ticket_ok": True, "pin": pin,
                "to_exit": False, "carry": carry}

    def onf(self, n):
        if n not in self.nf:
            raise ProtocolError(f"model nullifier {n} has no oracle nullifier")
        return self.nf[n]

    def step(self, kind, e, arg, code, ms0, ms1, ost):
        rc0, rc1 = ms0["record"], ms1["record"]
        if code:
            if (kind, code) not in self.mine:
                return ost
            if kind == "authorize":
                pin = rc0["pin"] if rc0["rstate"] == "LOCKED" else rc0["next_pin"]
                self.probe(ost, {"op": "authorize", "call": self.call(ms0, rc0["coin"], e, self.onf(rc0["nf"]), pin)},
                           code, kind)
            elif kind == "revoke":
                self.probe(ost, {"op": "revoke", "auth": e, "tag": 1}, code, kind)
            else:
                # AU-022: a reissue that carries a leaf other than (auth_0, VOID)
                c = self.call(ms0, rc0["coin"], e, self.onf(rc0["nf"]), rc0["next_pin"],
                              {"auth_0": e, "outcome": "FINAL", "sigs": Q})
                c["auth"] = 1000 + e
                self.probe(ost, {"op": "authorize", "call": c}, code, kind)
            return ost
        if kind == "authorize":
            return self.apply(ost, {"op": "authorize", "call": self.call(ms0, rc0["coin"], e, self.onf(rc0["nf"]), arg)})
        if kind == "finalize_auth":
            return self.apply(ost, {"op": "finalize", "auth": e, "height": arg})
        if kind == "revoke":
            return self.apply(ost, {"op": "revoke", "auth": e, "tag": 1})
        if kind == "checkpoint":
            leaves = [[x[0], x[1]] for x in ms1["cp"]["settle_root"]]
            st = self.apply(ost, {"op": "settle_root", "leaves": leaves})
            pa, out = rc0["pending_auth"], dict(ms1["cp"]["settle_root"]).get(rc0["pending_auth"])
            if rc1["coin"] != rc0["coin"]:
                self.nf[rc1["nf"]] = {"fresh": rc1["nf"]}
                st = self.apply(st, self.rec_op(rc1["coin"], rc1["nf"]))
            elif rc1["nf"] != rc0["nf"]:
                self.nf[rc1["nf"]] = {"auth": pa, "outcome": out}
                if out == "VOID" and rc0["pin"] != -1:
                    self.hits.append("AU-029 VOID of a pinned record")
            return st
        if kind == "reissue":
            e1 = arg
            pa = rc0["pending_auth"]
            self.nf[rc1["nf"]] = {"auth": e, "outcome": "VOID"}
            if rc0["pin"] != -1:
                self.hits.append("AU-029 VOID of a pinned record")
            c = self.call(ms1, rc1["coin"], e1, self.nf[rc1["nf"]], ms1["auths"][e1]["pin"],
                          {"auth_0": e, "outcome": "VOID", "sigs": Q})
            return self.apply(ost, {"op": "authorize", "call": c})
        return ost

    def compare(self, ms, ost):
        rc = ms["record"]
        recs = ost["records"]
        if len(recs) != rc["coin"]:
            raise Disagree("record", f"model coin {rc['coin']}, oracle records {len(recs)}")
        cur = [r for r in recs if r["rid"] == rc["coin"]][0]
        used = [u[0] for u in ost["used"]]
        mine = {"rstate": rc["rstate"], "pin": opt(rc["pin"]), "nf": self.onf(rc["nf"]),
                "nf_used": rc["nf_used"], "hold_set": rc["hold_set"]}
        theirs = {"rstate": cur["rstate"], "pin": cur["pin"], "nf": cur["nf"], "nf_used": cur["nf"] in used,
                  "hold_set": bool(ost["holds"])}
        d = diff(mine, theirs)
        if d:
            raise Disagree("record", "; ".join(f"{k}: model {a}, oracle {b}" for k, (a, b) in d.items()))
        oauth = {b["auth"]: (r["rid"], b) for r in recs for b in r["auths"]}
        if set(oauth) != set(ms["auths"]):
            raise Disagree("auths", f"model auths {sorted(ms['auths'])}, oracle {sorted(oauth)}")
        for a, ma in ms["auths"].items():
            rid, ob = oauth[a]
            mine = {"coin": ma["coin"], "status": ma["status"], "final_height": opt(ma["final_height"]),
                    "settled": ma["settled"], "pin": opt(ma["pin"]), "nf": self.onf(ma["nf"])}
            theirs = {"coin": rid, "status": ob["status"], "final_height": ob["final_height"],
                      "settled": ob["settled"], "pin": ob["pin"], "nf": ob["nf"]}
            d = diff(mine, theirs)
            if d:
                raise Disagree("auths", f"auth {a}: " + "; ".join(f"{k}: model {x}, oracle {y}" for k, (x, y) in d.items()))


class SlotsLane(Lane):
    """split-slots, committee slots (SL-004, SL-005, SL-008 to SL-010, CP-020): the
    model's one committee pool of four indices is pool (BIP340, epoch 1)."""
    name = "slots"

    def start(self, ms):
        st = self.apply(self.s0, {"op": "deal_c", "suite": "BIP340", "epoch": 1, "k": 4})
        if ms["lastOp"]["kind"] == "init_armed":
            st = self.force(st, ms, 1)
        return st

    def force(self, st, ms, e):
        root = "G" if ms["requests"][e]["source"] == "SEIZURE" else "OWN"
        new, obs = self.o.step(st, {"op": "in_force", "eid": e, "root": root})
        if new is None:
            r = ms["requests"][e]
            if r["lapsed"] or not live(r):
                # SL-005: a precedence that lapsed stays lapsed; an ended request gets no
                # precedence (the model finalizes an authorization after the end too)
                return st
            raise Disagree("oracle refuses", f"slots oracle refuses in_force {e} with {obs}")
        return new

    def names(self, r):
        return [{"suite": "BIP340", "epoch": 1, "idx": r["cslot"][g]} for g in range(1, r["G"] + 1)]

    def step(self, kind, e, arg, code, ms0, ms1, ost):
        if code:
            return ost
        st = ost
        r0, r1 = ms0["requests"].get(e), ms1["requests"].get(e)
        schnorr = r1 is not None and r1["suite"] == "SCHNORR"
        if kind == "finalize_auth":
            st = self.force(st, ms1, e)
        elif kind == "open" and arg == 1 and schnorr:
            st = self.apply(st, {"op": "open_c", "eid": e, "pos": r1["order_pos"], "names": self.names(r1)})
            if r1["lapsed"] and any(ms1["cslots"][r1["cslot"][g]]["bstat"] == "BURNED"
                                    and ms0["cslots"][r1["cslot"][g]]["bstat"] != "BURNED" for g in range(1, r1["G"] + 1)):
                self.hits.append("SL-005 late open burns")
        elif kind == "opened_vote" and schnorr:
            st = self.apply(st, {"op": "reserve", "eid": e})
        elif kind == "admit" and schnorr:
            if r0["phase"] == "OPENED":
                st = self.apply(st, {"op": "reserve", "eid": e})
            st = self.apply(st, {"op": "claim", "eid": e})
        elif kind == "restart":
            lo, hi = ms0["cp"]["pending_min"], ms0["cp"]["h"] + 2
            if lo <= hi:
                st = self.apply(st, {"op": "burn_range", "suite": "BIP340", "epoch": 1, "lo": lo, "hi": hi})
        for x in sorted(ms1["requests"]):
            a, b = ms0["requests"].get(x), ms1["requests"][x]
            if a is not None and live(a) and not live(b):
                st = self.apply(st, {"op": "end", "eid": x})
        for x in sorted(ms1["requests"]):
            a, b = ms0["requests"].get(x), ms1["requests"][x]
            if b["lapsed"] and (a is None or not a["lapsed"]):
                st = self.apply(st, {"op": "lapse", "eid": x})
        return st

    def compare(self, ms, ost):
        o = {x["idx"]: x for x in ost["cslots"]}
        for i, c in ms["cslots"].items():
            x = o[i]
            mine = {"bstat": c["bstat"], "prec": opt0(c["prec"]), "namers": sorted(c["namers"])}
            theirs = {"bstat": x["bstat"], "prec": x["prec"], "namers": sorted({n[0] for n in x["namers"]})}
            d = diff(mine, theirs)
            if d:
                raise Disagree("cslot", f"slot {i}: " + "; ".join(f"{k}: model {a}, oracle {b}" for k, (a, b) in d.items()))


class EnvelopeLane(Lane):
    """split-envelope EN-023: `order_check` probes at every `post` and `order` (accepted,
    b = height + 1) and at every `order/exp_c_not_below_exp` refusal."""
    name = "envelope"

    def start(self, ms):
        return self.s0

    def step(self, kind, e, arg, code, ms0, ms1, ost):
        if kind not in ("post", "order"):
            return ost
        if code and code != "exp_c_not_below_exp":
            return ost
        r = (ms1 if kind == "post" else ms0)["requests"][e]
        op = {"op": "order_check", "exp": r["exp"], "height": ms0["board_height"] + 1}
        if code:
            self.probe(ost, op, code, kind)
        else:
            new, obs = self.o.step(ost, op)
            if new is None:
                raise Disagree("EN-023", f"model {kind} with exp {r['exp']} at b = {op['height']}; oracle refuses {obs}")
        self.hits.append(f"EN-023 order_check at {kind}{'/' + code if code else ''}")
        return ost

    def compare(self, ms, ost):
        pass


class ShardLane(Lane):
    """split-shard-holders SH-030 to SH-037 (DECISIONS 67): the model's `addr`, the asset
    record of one address with a network-created shard, against the oracle's record of
    `cm_addr` CM and its `ack_ok` pairs. Member `m` of the model is node `m - 1`."""
    name = "shard-holders"
    CM, CHARTER = 1, 1
    # SH-001: the user is the primary of an OR gate whose escrow child is a 3-of-5 guardian group.
    GAMMA = {"gate": "OR", "mid": 0, "primary": {"gate": "LEAF", "mid": 0, "actor": 1},
             "escrow": {"gate": "GROUP", "mid": 0, "k": 3, "children": [
                 {"gate": "LEAF", "mid": i, "actor": 9 + i} for i in range(1, 6)]}}
    # SH-007 to SH-009: one actor with a network-created shard; every proof passes.
    BIRTH = {"x_f": 1, "charter_id": CHARTER, "chain_id": 1, "dealer_ok": True, "x_recomputed": True,
             "encoding_ok": True, "opening_ok": True,
             "actors": [{"slot": 0, "x_a": 2, "ctx": [1, 2, 0, CHARTER, 1], "valid": True, "network_created": True,
                         "pop_U": True, "delta": True}]}

    def start(self, ms):
        self.env = "NONE"        # the ACK envelope that opened: wallet facts, no oracle state
        self.paid = False
        if ms["addr"]["registered"]:
            raise ProtocolError("shard-holders lane: an initial state with a registered address")
        return self.apply(self.s0, {"op": "fix_charter", "id": self.CHARTER, "gamma": self.GAMMA})

    def exact(self, ost, op, code, kind):
        """An expected refusal: the oracle refuses with exactly the mapped code. A probe
        never threads, so the oracle state stays unchanged."""
        new, obs = self.o.step(ost, op)
        if new is not None or obs != [code]:
            raise Disagree("refusal code", f"model refuses {kind} with {code}; {self.name} oracle answers "
                           f"{'accepts ' + json.dumps(op) if new is not None else obs}")

    def expect(self, ost, op, want, sh):
        new, obs = self.o.step(ost, op)
        if new is None:
            raise Disagree("oracle refuses", f"{self.name} oracle refuses {op} with {obs}")
        if obs != {want: True}:
            raise Disagree(sh, f"{self.name} oracle answers {op} with {obs}, the model takes {want}")
        return new

    def ack_flags(self, m):
        """SH-031 inputs of member m on the open envelope. The holder's envelope carries a
        valid pop_u; the creator's does not. A corrupt member signs any envelope: its check
        is an adversarial input (all flags true), not evidence."""
        honest = m != 1
        return {"x_recomputed": True, "opening_ok": True, "pop_u": self.env == "HOLDER" or not honest}

    def step(self, kind, e, arg, code, ms0, ms1, ost):
        a0 = ms0["addr"]
        if code:
            if kind == "ack_ok" and code == "ack_refused":
                m = e
                if m == 1 or self.env != "CREATOR":
                    raise ProtocolError(f"ack_refused of member {m} on envelope {self.env}")
                self.exact(ost, {"op": "ack_check", "node": m - 1, "cm_addr": self.CM,
                                 "ack": self.ack_flags(m)}, code, kind)
                self.hits.append("SH-032 ack_refused (probe)")
            elif kind == "acknowledge" and code == "no_ack_certificate":
                signers = sorted(m - 1 for m in a0["ack_ok"])
                self.exact(ost, {"op": "acknowledge", "cm_addr": self.CM, "signers": signers}, code, kind)
                self.hits.append("SH-033 no_ack_certificate (probe)")
            return ost
        if kind not in ADDR_OPS:
            return ost
        if kind == "register_addr":
            st = ost
            for node in range(Q):
                st = self.expect(st, {"op": "birth_check", "node": node, "cm_addr": self.CM, "birth": self.BIRTH},
                                 "birth_ok", "SH-009")
            rec = {"cm_addr": self.CM, "profile": self.profile, "charter": self.CHARTER, "signers": list(range(Q)),
                   "owner_reg": False, "escrow_acks": 3, "escrow_quorum": 3, "guardian_acks": 3, "q_g": 3,
                   "network_created": True}
            st = self.expect(st, {"op": "submit_record", "record": rec}, "ok", "SH-034")
            self.hits.append("SH-034 register (driven)")
            return st
        if kind == "holder_ack":
            # SH-030: the model takes holder_ack only when x_u·G = X_u (ec_ok)
            self.expect(ost, {"op": "holder_open", "cm_addr": self.CM, "x_match": a0["ec_ok"]}, "ack_envelope",
                        "SH-030")
            self.env = "HOLDER"
            self.hits.append("SH-030 holder_open (driven)")
            return ost
        if kind == "creator_ack":
            self.env = "CREATOR"       # no oracle operation: it sets the pop_u input of later checks
            return ost
        if kind == "ack_ok":
            m = arg
            st = self.expect(ost, {"op": "ack_check", "node": m - 1, "cm_addr": self.CM, "ack": self.ack_flags(m)},
                             "ack_ok", "SH-031")
            self.hits.append("SH-031 ack_check (driven)" if m != 1 else "SH-031 ack_check, corrupt member (input)")
            return st
        if kind == "acknowledge":
            signers = sorted(m - 1 for m in a0["ack_ok"])
            if len(signers) != arg:
                raise ProtocolError(f"acknowledge arg {arg}, model ack_ok {a0['ack_ok']}")
            st = self.expect(ost, {"op": "acknowledge", "cm_addr": self.CM, "signers": signers}, "ok", "SH-037")
            self.hits.append("SH-037 acknowledge (driven)")
            return st
        if kind == "pay_addr":
            self.expect(ost, {"op": "pay", "cm_addr": self.CM}, "paid", "SH-035")
            self.paid = True
            self.hits.append("SH-035 pay (driven)")
            return ost
        raise ProtocolError(f"unmapped event {kind}")

    def compare(self, ms, ost):
        a = ms["addr"]
        recs = [r for r in ost["records"] if r["cm_addr"] == self.CM]
        if len(ost["records"]) != len(recs):
            raise Disagree("record", f"oracle records {ost['records']}")
        rec = recs[0] if recs else None
        mine = {"registered": a["registered"], "acked": a["acked"], "ack_ok": sorted(a["ack_ok"]),
                "network_created": a["registered"] or None,
                "ack_env": a["ack_env"], "paid": a["paid"]}
        theirs = {"registered": rec is not None, "acked": bool(rec and rec["acked"]),
                  "ack_ok": sorted(n + 1 for n, cm in ost["ack_ok"] if cm == self.CM),
                  "network_created": rec["network_created"] if rec else None,
                  "ack_env": self.env, "paid": self.paid}
        d = diff(mine, theirs)
        if d:
            raise Disagree("addr", "; ".join(f"{k}: model {x}, oracle {y}" for k, (x, y) in d.items()))
        if rec is not None:
            # SH-035 at every registered state: the payer wallet pays exactly when the record is acked
            new, obs = self.o.step(ost, {"op": "pay", "cm_addr": self.CM})
            pays = new is not None and obs == {"paid": True}
            if not pays and obs != ["SH-035"]:
                raise Disagree("SH-035", f"pay probe answers {obs}")
            if pays != a["acked"]:
                raise Disagree("SH-035", f"model acked {a['acked']}; the payer wallet {'pays' if pays else 'refuses SH-035'}")
            self.hits.append("SH-035 pay probe " + ("paid" if pays else "refused"))


def run_lane(lane, states, census):
    st = lane.start(states[0])
    lane.compare(states[0], st)
    steps = 0
    for i in range(1, len(states)):
        ms0, ms1 = states[i - 1], states[i]
        lo = ms1["lastOp"]
        kind, e, arg, code = lo["kind"], lo["eid"], lo["arg"], lo["code"]
        key = f"{kind}/{code}" if code else kind
        lane.hits = []
        census[key]["seen"] += 1
        try:
            st = lane.step(kind, e, arg, code, ms0, ms1, st)
            lane.compare(ms1, st)
            for h in lane.hits:
                lane.cover[h] += 1
            census[key]["agree"] += 1
            steps += 1
        except Disagree as d:
            census[key]["disagree"] += 1
            return {"steps": steps, "agree": False, "step": i, "event": key, "eid": e, "arg": arg,
                    "class": d.cls, "text": d.text}
    return {"steps": steps, "agree": True}



def flat(s):
    """A trace exported from a named instance (`inst::splitspec::st`) holds the state
    record in `st`; hoist its fields as tools/flatten_itf.py does."""
    out = {}
    for k, v in s.items():
        if k.endswith("::st"):
            out.update(v)
        elif k.endswith("::lastOp"):
            out["lastOp"] = v
        elif k.endswith("::g"):
            pass
        else:
            out[k] = v
    return out


def load(path):
    t = json.loads(path.read_text(), parse_constant=lambda c: (_ for _ in ()).throw(ProtocolError(c)))
    return [flat(itf(s)) for s in t["states"]]


def replay_trace(path, states, oracle, mode, profile, census, cover, relax=False):
    run = Run(oracle, mode, profile, census, cover, relax)
    ost = init_state(mode)
    first = states[0]["lastOp"]["kind"]
    if first == "init_armed":
        r = states[0]["requests"][1]
        ost = run.apply(ost, {"op": "post", "eid": 1, "epoch": r["epoch"], "exp": r["exp"], "type": r["req_type"],
                              "profile": r["profile"]})
    elif first != "init":
        raise ProtocolError(f"{path.name}: first state is {first}")
    pending = {}
    run.compare(states[0], ost, pending, first, 0)
    steps = 0
    for i in range(1, len(states)):
        ms0, ms1 = states[i - 1], states[i]
        lo = ms1["lastOp"]
        kind, e, arg, code = lo["kind"], lo["eid"], lo["arg"], lo["code"]
        key = f"{kind}/{code}" if code else kind
        run.hits = []
        census[key]["seen"] += 1
        try:
            if code:
                strip = lambda s: {k: v for k, v in s.items() if k != "lastOp"}
                if strip(ms0) != strip(ms1):
                    raise Disagree("model", f"refusal step {key} changes the model state")
                how = run.refusal(kind, e, code, ms0, ost)
                if how.startswith("other:"):
                    census[key]["other package"] += 1
                    continue
                if kind == "order" and code == "exp_c_not_below_exp":
                    run.hits.append("EN-023 order refusal")
            else:
                if kind in ("send_release", "record_release"):
                    run.node_release(kind, e, arg, ms0, ost, pending)
                for op in run.ops_for(kind, e, arg, ms0, ms1):
                    ost = run.apply(ost, op, e, pending)
                if kind == "post_void":
                    r1 = ms1["requests"][e]
                    if r1["phase"] == "VOID" and ms0["requests"][e]["phase"] != "VOID":
                        if r1["reason"] == "MIXED":
                            run.hits.append("RQ-072 MIXED tombstone")
                        if ms0["requests"][e]["any_release"] and any(
                                p["eid"] == e and p["kind"] == "VOID" and p["reason"] == "STALLED" for p in ms1["posts"]):
                            run.hits.append("RQ-073/RQ-074 STALLED post after release")
                if kind == "reissue":
                    run.hits.append("RQ-071 carry of a STALLED leaf")
            run.compare(ms1, ost, pending, kind, e)
            for h in run.hits:          # counted only for a step that agrees
                cover[h] += 1
            census[key]["agree"] += 1
            steps += 1
        except Disagree as d:
            census[key]["disagree"] += 1
            return {"trace": path.name, "steps": steps, "agree": False, "step": i, "event": key, "eid": e,
                    "arg": arg, "class": d.cls, "text": d.text}
    if pending:
        # A model run that ends before its `expire` event: the oracle's expiry is still
        # the model's next enabled step for those requests (stuttering), not a disagreement.
        pass
    return {"trace": path.name, "steps": steps, "agree": True}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", required=True, help="the request oracle")
    ap.add_argument("--auth-oracle", help="the authorization oracle (lane: record and auths)")
    ap.add_argument("--slots-oracle", help="the slots oracle (lane: committee slots)")
    ap.add_argument("--envelope-oracle", help="the envelope oracle (lane: EN-023 order_check)")
    ap.add_argument("--shard-oracle", help="the shard-holders oracle (lane: SH-030 to SH-037, the address record)")
    ap.add_argument("--traces", nargs="*", default=[])
    ap.add_argument("--expect-disagree", nargs="*", default=[])
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--json")
    ap.add_argument("--relax-expiry-height", action="store_true",
                    help="diagnostic only: accept a model `expire` at a later height than the oracle's tick")
    a = ap.parse_args()
    sets = [(pathlib.Path(d), None) for d in a.traces]
    for c in a.expect_disagree:
        parts = c.split("@")
        if len(parts) != 3:
            ap.error("--expect-disagree takes DIR@EVENT@TEXT")
        sets.append((pathlib.Path(parts[0]), (parts[1], parts[2])))
    if not sets:
        ap.error("no trace directory")
    census = collections.defaultdict(collections.Counter)
    cover = collections.Counter()
    lanes = [(n, c, path) for n, c, path in [("authorization", AuthLane, a.auth_oracle),
                                             ("slots", SlotsLane, a.slots_oracle),
                                             ("envelope", EnvelopeLane, a.envelope_oracle),
                                             ("shard-holders", ShardLane, a.shard_oracle)] if path]
    lane_census = {n: collections.defaultdict(collections.Counter) for n, _, _ in lanes}
    lane_rows = {n: [] for n, _, _ in lanes}
    rows, ok = [], True
    try:
        for d, ctl in sets:
            mode, profile = instance(d)
            files = sorted(d.glob("*.itf.json"), key=lambda p: int(re.sub(r"\D", "", p.stem) or 0))
            if not files:
                raise ProtocolError(f"{d}: no traces")
            oracle = Oracle(a.oracle, a.timeout)
            mine = [] if ctl is not None else lanes      # the controls run the request lane only
            procs = {}
            for n, cls, path in mine:
                inputs = {"authorization": {"params": {"mode": mode, "q": Q}, "ops": []},
                          "slots": {"params": {"mode": mode, "w": W}, "ops": []},
                          "envelope": {"params": {"mode": mode, "delta_c": DELTA_C}, "height": 0, "epochs": [],
                                       "ops": []},
                          "shard-holders": {"params": {"n": N, "f": F, "mode": mode, "N_h": 30}, "ops": []}}[n]
                procs[n] = (cls, Oracle(path, a.timeout), initial_state(path, inputs, a.timeout))
            res, lres = [], {n: [] for n in procs}
            for f in files:
                states = load(f)
                res.append(replay_trace(f, states, oracle, mode, profile, census, cover, a.relax_expiry_height))
                for n, (cls, o, s0) in procs.items():
                    r = run_lane(cls(o, mode, profile, cover, s0), states, lane_census[n])
                    r["trace"] = f.name
                    lres[n].append(r)
            oracle.close()
            for n, (cls, o, s0) in procs.items():
                o.close()
                lr = lres[n]
                lagree = sum(r["agree"] for r in lr)
                ok = ok and lagree == len(lr)
                lane_rows[n].append({"set": str(d), "traces": len(lr), "agree": lagree,
                                     "steps": sum(r["steps"] for r in lr),
                                     "disagreements": [r for r in lr if not r["agree"]]})
                print(f"replay [{n}]: {d.name}: {lagree}/{len(lr)} traces agree, {lane_rows[n][-1]['steps']} "
                      f"transitions agree{'' if lagree == len(lr) else '  FAIL'}")
                for c, k in sorted(collections.Counter(r["class"] for r in lr if not r["agree"]).items()):
                    ex = next(r for r in lr if not r["agree"] and r["class"] == c)
                    print(f"  {k} x {c}: e.g. {ex['trace']} step {ex['step']} {ex['event']}: {ex['text'][:300]}")
            agree = sum(r["agree"] for r in res)
            want = ctl is None
            good = agree == len(res) if want else all(
                not r["agree"] and r["event"] == ctl[0] and ctl[1] in r["text"] for r in res)
            ok = ok and good
            rows.append({"set": str(d), "mode": mode, "profile": profile,
                         "expect": "agree" if want else f"disagree at {ctl[0]} ({ctl[1]})",
                         "traces": len(res), "agree": agree, "steps": sum(r["steps"] for r in res),
                         "ok": good, "disagreements": [r for r in res if not r["agree"]]})
            print(f"replay [request]: {d.name}: {agree}/{len(res)} traces agree, {rows[-1]['steps']} transitions agree"
                  f" (expect {rows[-1]['expect']}){'' if good else '  FAIL'}")
            classes = collections.Counter(r["class"] for r in res if not r["agree"])
            for c, k in sorted(classes.items()):
                ex = next(r for r in res if not r["agree"] and r["class"] == c)
                print(f"  {k} x {c}: e.g. {ex['trace']} step {ex['step']} {ex['event']}: {ex['text'][:300]}")
    except ProtocolError as err:
        print(f"replay: protocol error: {err}", file=sys.stderr)
        return 2
    print("replay [request]: census (event: seen / agree / disagree / other package)")
    for k in sorted(census):
        c = census[k]
        print(f"  {k}: {c['seen']} / {c['agree']} / {c['disagree']} / {c['other package']}")
    print("replay: coverage of revisions 4 and 6 (compared transitions)")
    for k in ["RQ-069 record before send (node)", "RQ-069 send after record (node)", "RQ-072 MIXED tombstone",
              "RQ-073/RQ-074 STALLED post after release", "RQ-071 carry of a STALLED leaf", "EN-023 order refusal"]:
        print(f"  {k}: {cover[k]}")
    for k in sorted(x for x in cover if x.startswith(("AU-029", "SL-005", "EN-023 order_check", "SH-"))):
        print(f"  {k}: {cover[k]}")
    for n in lane_census:
        print(f"replay [{n}]: census (event: seen / agree / disagree)")
        for k in sorted(lane_census[n]):
            c = lane_census[n][k]
            print(f"  {k}: {c['seen']} / {c['agree']} / {c['disagree']}")
    if a.relax_expiry_height:
        print(f"  relaxed: expiry height differs: {cover['relaxed: expiry height differs']} (diagnostic run)")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps({"rows": rows, "census": census, "cover": cover, "lanes": lane_rows, "lane_census": lane_census}, indent=1) + "\n")
    print(f"replay: {'every set as expected' if ok else 'disagreement'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
