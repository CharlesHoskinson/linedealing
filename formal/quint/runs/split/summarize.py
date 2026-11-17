#!/usr/bin/env python3
"""Print an ITF trace of splitline.qnt one step per line: action, request states,
slot states, and new honest partials. Usage: summarize.py TRACE.itf.json"""
import json, sys

def v(x):
    if isinstance(x, dict):
        if '#bigint' in x: return int(x['#bigint'])
        if '#set' in x: return [v(e) for e in x['#set']]
        if '#map' in x: return {json.dumps(v(k)) if isinstance(v(k), (list, dict)) else v(k): v(val) for k, val in x['#map']}
        if '#tup' in x: return tuple(v(e) for e in x['#tup'])
        if 'tag' in x and 'value' in x:
            val = v(x['value'])
            return x['tag'] if val in ({}, (), None) else f"{x['tag']}({val})"
        return {k: v(val) for k, val in x.items()}
    if isinstance(x, list): return [v(e) for e in x]
    return x

def main(path):
    tr = json.load(open(path))
    prev = set()
    for n, st in enumerate(tr['states']):
        key = [k for k in st if k == 's' or k.endswith('::s')][0]
        s = v(st[key])
        reqs = s['reqs']
        rs = ' '.join(f"r{r}:{q['st']}{'/A' if q['admitted'] else ''}{'/R' if q['reserved'] else ''}"
                      f"{'/auth=' + q['auth'] if q['auth'] != 'ANone' else ''}{'/bf' if q['bfInForce'] else ''}"
                      f" anch={[q['anchors'][g] for g in sorted(q['anchors'])]}"
                      for r, q in sorted(reqs.items()))
        sl = ' '.join(f"{l}:{st_}" for l, st_ in sorted(s['slots'].items()) if st_ != 'Free')
        parts = {(p['node'], p['slot'], p['tk']) for p in s['sigPartials']}
        new = sorted(parts - prev); prev = parts
        print(f"{n:3d} {s['lastAction']:<16} {rs} | {sl}" + (f" | +partial {new}" if new else ''))

if __name__ == '__main__':
    main(sys.argv[1])
