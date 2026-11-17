#!/usr/bin/env -S python3 -I
"""kink-implementation/1 adapter between krs kink and a split-line Lean oracle.

kink sends each case's inputs in the KRS typed encoding (constructor forms such
as {"Submit": {"e": {"Env": {...}}}}) and reads the end's cells by Rust path.
The Lean oracles of formal/lean-split read and write their own JSON shapes
({"op": "submit", "envelope": {...}}, an answer {"state": {...}, "obs": [...]}).

This adapter translates between the two, driven only by a type schema
(schemas/<capability>.json). It holds no spec logic and no defaults: every
object must have exactly the keys its type names, every constructor must be a
declared one, and anything else is an error (exit 2). The answer's `state` is
flattened into one cell per oracle state field; `obs` stays one cell. A state
entry [okey, null, T] with T a record spreads the record's fields into cells.

Usage (from a FLOW.toml [[implementation]]):
  python3 -I oracle_adapter.py SCHEMA ORACLE        # one request on stdin
  python3 -I oracle_adapter.py SCHEMA --to-oracle   # print the oracle request only
  python3 -I oracle_adapter.py SCHEMA --from-oracle-inputs  # oracle inputs -> KRS inputs

Type language (JSON):
  "int" | "bool"
  {"list": T}
  {"tuple": CTOR, "items": [T, ...], "names": [F, ...]}
                                                KRS {CTOR: [..]} or {CTOR: {F: ..}} <-> oracle [..]
  {"record": CTOR, "fields": [[okey, kfield, T], ...]}
                                                KRS {CTOR: {kfield: ..}} <-> oracle {okey: ..}
  {"enum": {"ORACLE_NAME": "KrsCtor", ...}}     KRS "KrsCtor" <-> oracle "ORACLE_NAME"
  {"variant": {"tag": KEY, "cases": {"oracle_tag": [CTOR, [[okey, kfield, T], ...]], ...}}}
        tagged oracle objects {KEY: oracle_tag, okey: ..} <-> KRS {CTOR: {kfield: ..}}
  {"keyed": {"oracle_key": [CTOR, [[okey, kfield, T], ...]] | [CTOR, null], ...}}
        one-key oracle objects {oracle_key: X}:
        with fields [[null, kfield, T]] X is the one field's value;
        with named fields [[okey, kfield, T], ...] X is an object {okey: ..};
        with null the constructor is nullary and X is `true` ({"ok": true})
  {"union": {"strings": {"oracle_name": "KrsCtor", ...}, "keyed": {...as keyed...}}}
        oracle values that are either a bare name (a nullary constructor) or a
        one-key object ({"bound": 5}); a variant's nullary case may also come
        from KRS as the bare constructor name
  {"bykeys": [[CTOR, [[okey, kfield, T], ...]], ...]}
        oracle objects whose key set picks the case ({"fresh": 1} or
        {"auth": 2, "outcome": "VOID"}) <-> KRS {CTOR: {kfield: ..}}
  {"option": T}                                 KRS [] / [x]  <-> oracle null / x
  {"ref": NAME}                                 a named type of the schema's "types"
"""
import json
import os
import subprocess
import sys


class Bad(Exception):
    pass


def resolve(schema, t):
    while isinstance(t, dict) and "ref" in t:
        name = t["ref"]
        if name not in schema["types"]:
            raise Bad(f"schema: unknown type {name}")
        t = schema["types"][name]
    return t


def one_key(doc, where):
    if not isinstance(doc, dict) or len(doc) != 1:
        raise Bad(f"{where}: expected a one-key constructor object, got {json.dumps(doc)[:200]}")
    return next(iter(doc.items()))


def is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def to_oracle(schema, t, doc, where="inputs"):
    """KRS typed-encoding document -> oracle JSON."""
    t = resolve(schema, t)
    if t == "int":
        if not is_int(doc):
            raise Bad(f"{where}: expected an integer, got {doc!r}")
        return doc
    if t == "bool":
        if not isinstance(doc, bool):
            raise Bad(f"{where}: expected a boolean, got {doc!r}")
        return doc
    if "list" in t:
        if not isinstance(doc, list):
            raise Bad(f"{where}: expected a list, got {doc!r}")
        return [to_oracle(schema, t["list"], x, f"{where}[{i}]") for i, x in enumerate(doc)]
    if "option" in t:
        if not isinstance(doc, list) or len(doc) > 1:
            raise Bad(f"{where}: expected an option list [] or [x], got {doc!r}")
        return None if not doc else to_oracle(schema, t["option"], doc[0], f"{where}[0]")
    if "tuple" in t:
        c, v = one_key(doc, where)
        if isinstance(v, dict) and set(v) == set(t.get("names", [])):
            v = [v[n] for n in t["names"]]
        if c != t["tuple"] or not isinstance(v, list) or len(v) != len(t["items"]):
            raise Bad(f"{where}: expected {t['tuple']} with {len(t['items'])} items, got {doc!r}")
        return [to_oracle(schema, it, x, f"{where}.{i}") for i, (it, x) in enumerate(zip(t["items"], v))]
    if "record" in t:
        c, v = one_key(doc, where)
        if c != t["record"]:
            raise Bad(f"{where}: expected constructor {t['record']}, got {c}")
        return fields_to_oracle(schema, t["fields"], v, f"{where}.{c}")
    if "enum" in t:
        inv = {k: o for o, k in t["enum"].items()}
        if not isinstance(doc, str) or doc not in inv:
            raise Bad(f"{where}: expected one of {sorted(inv)}, got {doc!r}")
        return inv[doc]
    if "variant" in t:
        # a nullary case may come as the bare constructor name
        c, v = (doc, {}) if isinstance(doc, str) else one_key(doc, where)
        for otag, (ctor, fields) in t["variant"]["cases"].items():
            if ctor == c:
                out = {t["variant"]["tag"]: otag}
                out.update(fields_to_oracle(schema, fields, v, f"{where}.{c}"))
                return out
        raise Bad(f"{where}: unknown constructor {c}")
    if "keyed" in t:
        if isinstance(doc, str):
            c, v = doc, {}
        else:
            c, v = one_key(doc, where)
        for okey, (ctor, fields) in t["keyed"].items():
            if ctor == c:
                if fields is None:
                    if v not in ({}, []):
                        raise Bad(f"{where}: nullary {c} has fields {v!r}")
                    return {okey: True}
                if fields and all(f[0] is not None for f in fields):
                    return {okey: fields_to_oracle(schema, fields, v, f"{where}.{c}")}
                if len(fields) != 1 or fields[0][0] is not None:
                    raise Bad(f"schema: keyed {okey} needs one unnamed field")
                _, kf, ft = fields[0]
                if not isinstance(v, dict) or set(v) != {kf}:
                    raise Bad(f"{where}: {c} needs exactly field {kf}, got {v!r}")
                return {okey: to_oracle(schema, ft, v[kf], f"{where}.{c}.{kf}")}
        raise Bad(f"{where}: unknown constructor {c}")
    if "union" in t:
        inv = {k: o for o, k in t["union"].get("strings", {}).items()}
        if isinstance(doc, str) and doc in inv:
            return inv[doc]
        return to_oracle(schema, {"keyed": t["union"].get("keyed", {})}, doc, where)
    if "bykeys" in t:
        c, v = one_key(doc, where)
        for ctor, fields in t["bykeys"]:
            if ctor == c:
                return fields_to_oracle(schema, fields, v, f"{where}.{c}")
        raise Bad(f"{where}: unknown constructor {c}")
    raise Bad(f"schema: bad type {t!r}")


def fields_to_oracle(schema, fields, v, where):
    if isinstance(v, list):
        if len(v) != len(fields):
            raise Bad(f"{where}: expected {len(fields)} positional fields, got {len(v)}")
        v = {kf: x for (_, kf, _), x in zip(fields, v)}
    if not isinstance(v, dict) or set(v) != {kf for _, kf, _ in fields}:
        raise Bad(f"{where}: expected fields {sorted(kf for _, kf, _ in fields)}, got {v!r}")
    return {ok: to_oracle(schema, ft, v[kf], f"{where}.{kf}") for ok, kf, ft in fields}


def from_oracle(schema, t, doc, where="answer"):
    """Oracle JSON -> KRS typed-encoding document."""
    t = resolve(schema, t)
    if t == "int":
        if not is_int(doc):
            raise Bad(f"{where}: expected an integer, got {doc!r}")
        return doc
    if t == "bool":
        if not isinstance(doc, bool):
            raise Bad(f"{where}: expected a boolean, got {doc!r}")
        return doc
    if "list" in t:
        if not isinstance(doc, list):
            raise Bad(f"{where}: expected a list, got {doc!r}")
        return [from_oracle(schema, t["list"], x, f"{where}[{i}]") for i, x in enumerate(doc)]
    if "option" in t:
        return [] if doc is None else [from_oracle(schema, t["option"], doc, where)]
    if "tuple" in t:
        if not isinstance(doc, list) or len(doc) != len(t["items"]):
            raise Bad(f"{where}: expected a {len(t['items'])}-tuple, got {doc!r}")
        return {t["tuple"]: [from_oracle(schema, it, x, f"{where}.{i}")
                             for i, (it, x) in enumerate(zip(t["items"], doc))]}
    if "record" in t:
        return {t["record"]: fields_from_oracle(schema, t["fields"], doc, where)}
    if "enum" in t:
        if not isinstance(doc, str) or doc not in t["enum"]:
            raise Bad(f"{where}: expected one of {sorted(t['enum'])}, got {doc!r}")
        return t["enum"][doc]
    if "variant" in t:
        tag = t["variant"]["tag"]
        if not isinstance(doc, dict) or tag not in doc:
            raise Bad(f"{where}: expected an object with {tag!r}, got {doc!r}")
        otag = doc[tag]
        if otag not in t["variant"]["cases"]:
            raise Bad(f"{where}: unknown {tag} {otag!r}")
        ctor, fields = t["variant"]["cases"][otag]
        rest = {k: v for k, v in doc.items() if k != tag}
        return {ctor: fields_from_oracle(schema, fields, rest, f"{where}.{otag}")}
    if "keyed" in t:
        okey, v = one_key(doc, where)
        if okey not in t["keyed"]:
            raise Bad(f"{where}: unknown key {okey!r}")
        ctor, fields = t["keyed"][okey]
        if fields is None:
            if v is not True:
                raise Bad(f"{where}: {okey} must be true, got {v!r}")
            return ctor
        if fields and all(f[0] is not None for f in fields):
            return {ctor: fields_from_oracle(schema, fields, v, f"{where}.{okey}")}
        _, kf, ft = fields[0]
        return {ctor: {kf: from_oracle(schema, ft, v, f"{where}.{okey}")}}
    if "union" in t:
        if isinstance(doc, str):
            if doc not in t["union"].get("strings", {}):
                raise Bad(f"{where}: unknown name {doc!r}")
            return t["union"]["strings"][doc]
        return from_oracle(schema, {"keyed": t["union"].get("keyed", {})}, doc, where)
    if "bykeys" in t:
        if isinstance(doc, dict):
            for ctor, fields in t["bykeys"]:
                if set(doc) == {ok for ok, _, _ in fields}:
                    return {ctor: fields_from_oracle(schema, fields, doc, f"{where}.{ctor}")}
        raise Bad(f"{where}: no case has the keys of {json.dumps(doc)[:200]}")
    raise Bad(f"schema: bad type {t!r}")


def fields_from_oracle(schema, fields, doc, where):
    if not isinstance(doc, dict) or set(doc) != {ok for ok, _, _ in fields}:
        raise Bad(f"{where}: expected keys {sorted(ok for ok, _, _ in fields)}, got "
                  f"{sorted(doc) if isinstance(doc, dict) else doc!r}")
    return {kf: from_oracle(schema, ft, doc[ok], f"{where}.{ok}") for ok, kf, ft in fields}


def inputs_to_oracle(schema, inputs):
    want = {k for k, _ in schema["inputs"]}
    if not isinstance(inputs, dict) or set(inputs) != want:
        raise Bad(f"inputs: expected keys {sorted(want)}, got {sorted(inputs) if isinstance(inputs, dict) else inputs!r}")
    return {k: to_oracle(schema, t, inputs[k], f"inputs.{k}") for k, t in schema["inputs"]}


def inputs_from_oracle(schema, inputs):
    want = {k for k, _ in schema["inputs"]}
    if not isinstance(inputs, dict) or set(inputs) != want:
        raise Bad(f"inputs: expected keys {sorted(want)}")
    return {k: from_oracle(schema, t, inputs[k], f"inputs.{k}") for k, t in schema["inputs"]}


def answer_from_oracle(schema, ans):
    if not isinstance(ans, dict) or "end" not in ans:
        raise Bad(f"oracle answer has no end: {ans!r}")
    if ans["end"] == "could-not-apply":
        return ans
    if ans["end"] != "final" or set(ans) != {"end", "cells"}:
        raise Bad(f"oracle answer: unexpected shape {sorted(ans)}")
    cells = ans["cells"]
    if set(cells) != {"state", "obs"}:
        raise Bad(f"oracle cells: expected state and obs, got {sorted(cells)}")
    st = cells["state"]
    want = {ok for ok, _, _ in schema["state"]}
    if not isinstance(st, dict) or set(st) != want:
        raise Bad(f"oracle state: expected keys {sorted(want)}, got {sorted(st) if isinstance(st, dict) else st!r}")
    out = {}
    for ok, kf, t in schema["state"]:
        v = from_oracle(schema, t, st[ok], f"state.{ok}")
        if kf is None:
            # a record state field spread into one cell per record field
            # (a #[k::init] cannot hold a constructor term with fields)
            (v,) = v.values()
            out.update(v)
        else:
            out[kf] = v
    out["obs"] = from_oracle(schema, {"list": schema["obs"]}, cells["obs"], "obs")
    return {"end": "final", "cells": out}


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        schema = json.loads(open(argv[1]).read())
        req = json.loads(sys.stdin.read())
        if argv[2] == "--from-oracle-inputs":
            print(json.dumps(inputs_from_oracle(schema, req)))
            return 0
        if not isinstance(req, dict) or set(req) - {"protocol", "program", "inputs", "stop"} \
                or req.get("protocol") != "kink-implementation/1":
            raise Bad(f"request: unexpected shape {sorted(req) if isinstance(req, dict) else req!r}")
        if "stop" in req:
            raise Bad("request: a stop count is not supported")
        oreq = {"protocol": req["protocol"], "program": req["program"],
                "inputs": inputs_to_oracle(schema, req["inputs"])}
        if argv[2] == "--to-oracle":
            print(json.dumps(oreq))
            return 0
        p = subprocess.run(argv[2:], input=json.dumps(oreq), capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            raise Bad(f"oracle exit {p.returncode}: {p.stderr.strip()[:500]}")
        print(json.dumps(answer_from_oracle(schema, json.loads(p.stdout))))
        return 0
    except Bad as e:
        print(f"oracle_adapter: {e}", file=sys.stderr)
        log = os.environ.get("ORACLE_ADAPTER_LOG")
        if log:
            with open(log, "a") as f:
                f.write(f"oracle_adapter: {e}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
