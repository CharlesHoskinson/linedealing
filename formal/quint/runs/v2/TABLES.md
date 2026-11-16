
### Witnesses

| run | main | init | step | steps | samples | seed | invariant | outcome | trace length |
|---|---|---|---|---|---|---|---|---|---|
| w_NoArmed | linedealing | init | stepHonestProgress | 40 | 2000 | 101 | NoArmed | VIOLATED (4s) | 16 states |
| w_NoLockCert | linedealing | initArmed | stepHonestProgress | 40 | 2000 | 102 | NoLockCert | VIOLATED (4s) | 25 states |
| w_NoHonestPartial | linedealing | initArmed | stepHonestProgress | 40 | 2000 | 103 | NoHonestPartial | VIOLATED (4s) | 20 states |
| w_NoSpendExecuted | linedealing | init | stepHonestProgress | 40 | 2000 | 104 | NoSpendExecuted | VIOLATED (4s) | 28 states |
| w_NoSpendExecuted_weighted | linedealing | init | stepWeighted | 40 | 2000 | 105 | NoSpendExecuted | VIOLATED (7s) | 23 states |
| w_NoGen2 | linedealing | initArmed | stepHonestProgress | 40 | 2000 | 106 | NoGen2 | VIOLATED (4s) | 34 states |
| w_NoGen2Spend | linedealing | initArmed | stepHonestProgress | 40 | 3000 | 107 | NoGen2Spend | VIOLATED (14s) | 30 states |
| w_NoReshareDone | linedealing | initArmed | stepHonestProgress | 40 | 2000 | 108 | NoReshareDone | VIOLATED (4s) | 15 states |
| w_NoEpoch2Partial | linedealing | initArmed | stepHonestProgress | 40 | 2000 | 109 | NoEpoch2Partial | VIOLATED (5s) | 21 states |
| w_NoRollbackAfterPrevote | linedealing | initArmedOpen | stepProgressFaults | 40 | 2000 | 110 | NoRollbackAfterPrevote | VIOLATED (5s) | 37 states |
| w_NoRollbackAfterPartial | linedealing | initArmedOpen | stepProgressFaults | 40 | 2000 | 111 | NoRollbackAfterPartial | VIOLATED (5s) | 37 states |
| w_NoFinal | linedealing | initArmed | stepHonestProgress | 40 | 2000 | 112 | NoFinal | VIOLATED (4s) | 25 states |
| w_NoVoid | linedealing | initArmed | stepAdversarial | 40 | 2000 | 113 | NoVoid | VIOLATED (3s) | 8 states |
| w_NoExpired | linedealing | initArmed | stepAdversarial | 40 | 2000 | 114 | NoExpired | VIOLATED (5s) | 28 states |
| w_n7_NoSpendExecuted | linedealing_n7_f2 | initArmed | stepHonestProgress | 80 | 1000 | 115 | NoSpendExecuted | VIOLATED (4s) | 20 states |
| w_n7_NoReshareDone | linedealing_n7_f2 | initArmed | stepHonestProgress | 80 | 1000 | 116 | NoReshareDone | VIOLATED (5s) | 20 states |

### Mutants

| run | main | init | step | steps | samples | seed | invariant | outcome | trace length |
|---|---|---|---|---|---|---|---|---|---|
| m_broken_prevote_adv | linedealing_broken_prevote | initArmedOpen | stepAdversarial | 40 | 3000 | 201 | NoNonceReuse | VIOLATED (78s) | 31 states |
| m_broken_rule4_adv | linedealing_broken_rule4 | initArmedOpen | stepAdversarial | 40 | 3000 | 202 | NoNonceReuse | VIOLATED (16s) | 41 states |
| m_broken_prevote_weighted | linedealing_broken_prevote | initArmedOpen | stepWeighted | 40 | 3000 | 203 | NoNonceReuse | VIOLATED (13s) | 22 states |
| m_broken_rule4_weighted | linedealing_broken_rule4 | initArmedOpen | stepWeighted | 40 | 3000 | 204 | NoNonceReuse | VIOLATED (281s) | 22 states |
| m_broken_prevote_step | linedealing_broken_prevote | init | step | 30 | 10000 | 205 | NoNonceReuse | no violation (450s) | - |
| m_broken_rule4_step | linedealing_broken_rule4 | init | step | 30 | 10000 | 206 | NoNonceReuse | no violation (495s) | - |
| m_broken_rule4_init_weighted | linedealing_broken_rule4 | init | stepWeighted | 40 | 3000 | 207 | NoNonceReuse | VIOLATED (138s) | 41 states |
| m_broken_prevote_init_weighted | linedealing_broken_prevote | init | stepWeighted | 40 | 3000 | 208 | NoNonceReuse | VIOLATED (687s) | 38 states |
| m_broken_rule4_armed_step | linedealing_broken_rule4 | initArmedOpen | step | 40 | 3000 | 209 | NoNonceReuse | VIOLATED (86s) | 37 states |
| m_broken_prevote_armed_step | linedealing_broken_prevote | initArmedOpen | step | 40 | 3000 | 210 | NoNonceReuse | no violation (427s) | - |

### Control: --invariants list form on mutants

| run | main | init | step | steps | samples | seed | invariant | outcome | trace length |
|---|---|---|---|---|---|---|---|---|---|
| c_list_broken_rule4 | linedealing_broken_rule4 | initArmedOpen | stepAdversarial | 40 | 3000 | 202 | all five (`--invariants`) | VIOLATED (22s) | 41 states |
| c_list_broken_prevote | linedealing_broken_prevote | initArmedOpen | stepAdversarial | 40 | 3000 | 201 | all five (`--invariants`) | VIOLATED (105s) | 31 states |

### Safety

| run | main | init | step | steps | samples | seed | outcome | armed | lock | openPart | spend | gen2Part | gen2Spend | handover | handover+oldPart | e2Part | rbAfterPrevote | rbAfterPartial | final | void | expired |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| s_n4_adv_open | linedealing | initArmedOpen | stepAdversarial | 40 | 3000 | 301 | no violation (1840s) | 3000 | 421 | 360 | 94 | 8 | 2 | 497 | 8 | 61 | 656 | 272 | 55 | 1620 | 1088 |
| s_n4_adv_any | linedealing | initArmed | stepAdversarial | 40 | 3000 | 302 | no violation (1742s) | 3000 | 222 | 180 | 163 | 22 | 3 | 441 | 12 | 58 | 325 | 139 | 123 | 1737 | 943 |
| s_n4_adv_reshare | linedealing | initArmedOpenReshare | stepAdversarial | 40 | 2000 | 303 | no violation (2150s) | 2000 | 204 | 181 | 51 | 2 | 0 | 920 | 15 | 112 | 268 | 79 | 18 | 632 | 1165 |
| s_n4_progress | linedealing | initArmed | stepHonestProgress | 40 | 2000 | 304 | no violation (1021s) | 2000 | 498 | 496 | 1201 | 120 | 27 | 611 | 15 | 597 | 0 | 0 | 1070 | 692 | 0 |
| s_n4_progfaults | linedealing | initArmedOpen | stepProgressFaults | 40 | 2000 | 305 | no violation (583s) | 2000 | 159 | 151 | 24 | 7 | 3 | 211 | 6 | 14 | 395 | 143 | 20 | 1068 | 860 |
| s_n4_weighted | linedealing | init | stepWeighted | 40 | 3000 | 306 | no violation (1907s) | 1758 | 196 | 162 | 132 | 23 | 0 | 548 | 2 | 105 | 125 | 51 | 69 | 1728 | 757 |
| s_n4_step_init | linedealing | init | step | 40 | 3000 | 307 | no violation (357s) | 519 | 2 | 1 | 0 | 0 | 0 | 23 | 0 | 0 | 2 | 0 | 0 | 1390 | 1209 |
| s_n4_step_armed | linedealing | initArmed | step | 40 | 3000 | 308 | no violation (519s) | 3000 | 46 | 27 | 13 | 0 | 0 | 220 | 2 | 4 | 95 | 26 | 11 | 1329 | 1632 |
| s_n7_progress | linedealing_n7_f2 | initArmed | stepHonestProgress | 80 | 600 | 401 | no violation (953s) | 600 | 156 | 156 | 353 | 17 | 4 | 190 | 3 | 187 | 0 | 0 | 350 | 206 | 0 |
| s_n7_adv_open | linedealing_n7_f2 | initArmedOpen | stepAdversarial | 80 | 600 | 402 | no violation (478s) | 600 | 25 | 22 | 8 | 0 | 0 | 49 | 0 | 2 | 61 | 22 | 7 | 281 | 309 |
| s_n7_weighted | linedealing_n7_f2 | init | stepWeighted | 80 | 600 | 403 | no violation (698s) | 302 | 21 | 20 | 8 | 1 | 0 | 56 | 0 | 5 | 24 | 20 | 8 | 323 | 241 |
| s_n7_step_init | linedealing_n7_f2 | init | step | 60 | 1000 | 404 | no violation (207s) | 87 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 380 | 489 |
| s_n7_step_armed | linedealing_n7_f2 | initArmed | step | 60 | 1000 | 405 | no violation (532s) | 1000 | 1 | 1 | 0 | 0 | 0 | 29 | 0 | 0 | 10 | 1 | 0 | 367 | 633 |
| s_n7_adv_reshare | linedealing_n7_f2 | initArmedOpenReshare | stepAdversarial | 80 | 400 | 406 | no violation (602s) | - | 6 | 6 | - | - | - | 79 | 1 | 1 | - | - | - | - | - |
