#!/usr/bin/env python3
"""Summarize a Quint ITF trace of linedealing: one line per step (new posts, chain blocks, node changes)."""
import json, sys

def v(x):
    if isinstance(x, dict):
        if '#bigint' in x: return int(x['#bigint'])
        if '#set' in x: return sorted((v(e) for e in x['#set']), key=str)
        if '#map' in x: return {v(k): v(val) for k, val in x['#map']}
        if '#tup' in x: return tuple(v(e) for e in x['#tup'])
        if 'tag' in x and 'value' in x:
            return x['tag'] if x['value'] in ({}, {'#tup': []}, []) else (x['tag'], v(x['value']))
        return {k: v(val) for k, val in x.items()}
    if isinstance(x, list): return [v(e) for e in x]
    return x

def post_str(p):
    k = p['kind']
    s = f"{k} e{p['epoch']} n{p['node']}"
    if k == 'P_MSG':
        s += f" mid{p['mid']} {p['mode']} {p['tProfile']} {p['rotPolicy']} nb{p['nb']} exp{p['exp']} bad{p['badNodes']}"
    elif k in ('P_OBS', 'P_NACK'): s += f" g{p['g']} a{p['a']} h{p['h']}"
    elif k in ('P_PREVOTE', 'P_PARTIAL'): s += f" g{p['g']} a{p['a']} h{p['h']} dg{p['dg']}"
    elif k == 'P_SEALED_PARTIAL': s += f" g{p['g']} a{p['a']} h{p['h']} var{p['variant']}"
    elif k == 'P_RS_DEAL': s += f" gens{p['gens']} bad{p['badNodes']}"
    elif k == 'P_READY': s += f" Q{p['dealers']}"
    elif k == 'P_RS_COMPLAINT': s += f" dealer{p['targetDealer']}"
    elif k in ('P_FINAL', 'P_VOID'): s += f" dg{p['dg']}"
    return s + f" @bh{p['bheight']}"

def main(path):
    d = json.load(open(path))
    states = [{k.split('::')[-1]: v(val) for k, val in s.items() if k != '#meta'} for s in d['states']]
    s0 = states[0]
    print(f"byz1={s0['byz1']} byz2={s0['byz2']} genesis={s0['chainBlocks'][0]}")
    print("impls1=", {i: st['builderImpl'] for i, st in s0['nodes1'].items()})
    for i, s in enumerate(s0['board']): print(f"  init post[{i}] {post_str(s)}")
    for t in range(1, len(states)):
        a, b = states[t-1], states[t]
        ev = []
        for i in range(len(a['board']), len(b['board'])): ev.append(f"post[{i}] {post_str(b['board'][i])}")
        for blk in b['chainBlocks'][len(a['chainBlocks']):]:
            ev.append(f"block h{blk['height']} trig={blk['triggerOk']} fee={blk['marketFee']} {blk['txKind']} g{blk['txGen']} val{blk['txVal']}")
        if b['boardHeight'] != a['boardHeight']: ev.append(f"boardHeight -> {b['boardHeight']}")
        for e in ('nodes1', 'nodes2'):
            for n in b[e]:
                if b[e][n] != a[e][n]:
                    diff = {k: b[e][n][k] for k in b[e][n] if b[e][n][k] != a[e][n][k]}
                    ev.append(f"{e}[{n}] {diff}")
        print(f"[{t}] " + ("; ".join(ev) if ev else "(no change)"))

main(sys.argv[1])
