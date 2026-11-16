#!/usr/bin/env python3
"""Build markdown result tables from runs/v2/*.log (run from formal/quint)."""
import re, glob, os
jobs = [l.split() for l in open('runs/v2/jobs.txt') if l.strip()]
SHORT = {'ArmedReached':'armed','LockCertReached':'lock','OpenPartialReached':'openPart','SpendExecuted':'spend',
         'Gen2PartialReached':'gen2Part','Gen2SpendReached':'gen2Spend','ReshareDoneReached':'handover',
         'HandoverWithOldPartialReached':'handover+oldPart','Epoch2PartialReached':'e2Part',
         'RollbackAfterPrevoteReached':'rbAfterPrevote','RollbackAfterPartialReached':'rbAfterPartial',
         'FinalReached':'final','VoidReached':'void','ExpiredReached':'expired'}
def parse(name):
    t = open(f'runs/v2/{name}.log').read()
    res = re.search(r'^\[(ok|violation)\][^\n]*', t, re.M)
    res = res.group(0) if res else 'NO RESULT: ' + t.strip().splitlines()[-1]
    states = len(re.findall(r'^\[State \d+\]', t, re.M))
    wit = dict((w, (int(n), int(m))) for w, n, m in re.findall(r'^(\w+) was witnessed in (\d+) trace\(s\) out of (\d+)', t, re.M))
    wall = re.search(r'# exit: (\d+)\s+wall: (\d+)s', t)
    return res, states, wit, wall.groups() if wall else ('?', '?')
for kind, title in (('w_', 'Witnesses'), ('m_', 'Mutants'), ('c_', 'Control: --invariants list form on mutants'), ('s_', 'Safety')):
    print(f'\n### {title}\n')
    if kind == 's_':
        print('| run | main | init | step | steps | samples | seed | outcome | ' + ' | '.join(SHORT.values()) + ' |')
        print('|' + '---|' * (8 + len(SHORT)))
    else:
        print('| run | main | init | step | steps | samples | seed | invariant | outcome | trace length |')
        print('|---|---|---|---|---|---|---|---|---|---|')
    for name, main, init, step, steps, samples, seed, target in jobs:
        if not name.startswith(kind): continue
        if not os.path.exists(f'runs/v2/{name}.log'): print(f'| {name} | (not run) |'); continue
        res, states, wit, (rc, wall) = parse(name)
        out = 'VIOLATED' if res.startswith('[violation]') else ('no violation' if res.startswith('[ok]') else res)
        if kind == 's_':
            cells = [f"{wit[w][0]}" if w in wit else '-' for w in SHORT]
            print(f'| {name} | {main} | {init} | {step} | {steps} | {samples} | {seed} | {out} ({wall}s) | ' + ' | '.join(cells) + ' |')
        else:
            tl = f'{states} states' if (states and out == 'VIOLATED') else '-'
            tgt = 'all five (`--invariants`)' if target.startswith('SAFETY') else target
            print(f'| {name} | {main} | {init} | {step} | {steps} | {samples} | {seed} | {tgt} | {out} ({wall}s) | {tl} |')
