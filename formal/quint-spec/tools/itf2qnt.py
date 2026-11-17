# Usage: python3 -I tools/itf2qnt.py TRACE.itf.json INSTANCE STATE_INDEX NAME
"""Print state K of an ITF trace as Quint `pure val NAME_st`, `NAME_g` and `NAME_lastOp` literals."""
import json
import sys

path, inst, k = sys.argv[1], sys.argv[2], int(sys.argv[3])
t = json.load(open(path))


def q(x):
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        return str(x)
    if isinstance(x, str):
        return json.dumps(x)
    if isinstance(x, list):
        return "[" + ", ".join(q(a) for a in x) + "]"
    if isinstance(x, dict):
        if '#bigint' in x:
            return x['#bigint']
        if '#map' in x:
            return "Map(" + ", ".join(f"{q(a)} -> {q(b)}" for a, b in x['#map']) + ")"
        if '#set' in x:
            return "Set(" + ", ".join(q(a) for a in x['#set']) + ")"
        if '#tup' in x:
            return "(" + ", ".join(q(a) for a in x['#tup']) + ")"
        if '#unserializable' in x:
            raise SystemExit("unserializable value")
        return "{ " + ", ".join(f"{a}: {q(b)}" for a, b in x.items()) + " }"
    raise SystemExit(f"unknown {x!r}")


s = t['states'][k]
pre = f"{inst}::splitspec::"
for var in ("st", "g", "lastOp"):
    print(f"  pure val {sys.argv[4]}_{var} = {q(s[pre + var])}")
