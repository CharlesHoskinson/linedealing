# Quint model of the line-dealing committee protocol: report

This report covers `formal/quint/linedealing.qnt` and the runs under `formal/quint/runs/v2/`. Every result here comes from a command that was run on the model file with SHA-256 `5a2a5d55de99767219b35b38b85ca2a00adb706865c9df5df372762ad16fb4b9` (stored in `runs/v2/MODEL.sha256`).

- Each log starts with the exact `quint` command and ends with the exit code and wall time.
- `runs/v2/run_all.sh` reruns every simulation row. It reads `runs/v2/jobs.txt` and writes `runs/v2/SUMMARY.txt`.
- `runs/v2/tables.py` rebuilds the tables below from the logs.
- `python3 runs/v2/summarize.py runs/v2/<run>.itf.json` prints a trace one step per line.
- The same command with the same `--seed` reproduces the same run. A violation run does not print a "reproduce" seed, so the `--seed` in the table is the reproduction handle.

The previous version of this report was written by a model that could not run `quint`. It stated results for which no runs existed. All of those claims are removed here. The logs in `runs/*.log`, one level above `v2/`, come from the original uniform `step` (see section 3). They are kept only as the record of the vacuous baseline.

## 1. What the model covers

The protocol module is `linedealing_protocol`. It has the constants `N`, `F`, `ENFORCE_ONE_PREVOTE` and `ENFORCE_RULE4`. There are four instances:

| instance | N | F | rule 1 (one PREVOTE per (rid, g)) | rule 4 (restart replay) |
|---|---|---|---|---|
| `linedealing` | 4 | 1 | on | on |
| `linedealing_n7_f2` | 7 | 2 | on | on |
| `linedealing_broken_prevote` | 4 | 1 | **off** | on |
| `linedealing_broken_rule4` | 4 | 1 | on | **off** |

The model covers SCHEME.md sections 3.4 to 3.10, 4 and 5:

- **Committees.** Two committees (epochs 1 and 2). Each has a static Byzantine set of at most `F` nodes.
- **Board.** A totally ordered log with a board height and the `[nb, exp]` window.
- **Step A.** MSG binding, the ACK quorum and verified complaints.
- **Step B.** Height-only OBS posts. The anchor is entry `f+1` of the first `q` heights (`q = QUORUM = (N + F + 2) / 2`, which is `2f+1` at `n = 3f+1`; LOOP item 4b). `f+1` NACKs fail an attempt. Anchor replacement and the board cut are included.
- **Sealed release.** `Select` on a two-variant fee grid.
- **Open signing.** PREVOTE, the lock certificate of `q` PREVOTE posts, and PARTIAL only after the lock and only for the node's own digest. The durable slot ledger, rules 1 to 5, a disk-rollback action (rule 4 replay) and a clean builder restart.
- **Generations.** `g = 1, 2`, with the `Δ` rule and the fee bump.
- **Committee change.** ROTATE with the finish, void and reshare policies. The freeze rule, reshare deals, complaints, READY and HANDOVER.
- **Tombstones.** FINAL, VOID and EXPIRED.
- **Target chain.** Every request or foreign transaction spends the pin.

Digests are injective integers `encodeDigest(e, g, a, h*, fee, builderImpl)`. Builder divergence (`builderImpl ∈ {1, 2}`) lets two honest nodes build different digests at the same anchor.

## 2. Bounds and abstractions

- **Bounds.** `MAX_GEN = 2`, `MAX_ATTEMPTS = 2`, `MAX_VARIANTS = 2`, `MAX_CHAIN_HEIGHT = 4`, `MAX_BOARD_HEIGHT = 5`, two epochs, and at most 8 Byzantine posts.
- **Not modeled.** Curve arithmetic, the Shamir and Feldman algebra, encryption, `π`, multi-input transactions, chain reorgs, adaptive corruption, and the board's consensus internals.
- **Reconstruction.** `canReconstruct*` credits the adversary with all `|byz|` shares and needs at least one honest partial.

## 3. Why the original runs were vacuous

The original `step` picks uniformly among its enabled branches. Many branches are enabled almost all the time:

- squat MSG posts;
- board-height ticks toward `exp`;
- empty and foreign chain blocks;
- Byzantine posts;
- ROTATE and rollbacks.

These branches fill the 4-block target chain, after which `advanceChainReqSpend` is disabled. They also expire or void the request before the roughly 15 honest steps that a spend needs.

Section 5 measures this:

- **Mutants under the original `step`.** `m_broken_prevote_step` and `m_broken_rule4_step` find no violation in 10000 samples at 30 steps each.
- **Clean model, `step` from `init`.** `s_n4_step_init` reaches a lock in 2 of 3000 traces and a spend in 0. `s_n7_step_init` reaches no lock in 1000 traces.

`rollbackWithoutRule4Test` scripts a mutant counterexample, so the mutant runs pass only because the deep states are never sampled.

## 4. Exploration aids (protocol semantics unchanged)

The additions are one inserted block, "Exploration aids", plus one `run` test. A `diff` against the original file shows insert-only hunks. No guard or update of a protocol action was changed. The added actions are:

- **Armed initial states: `initArmedWith(modes, pols)`, `initArmed`, `initArmedOpen` and `initArmedOpenReshare`.**
  - They keep all of `init`'s nondeterministic choices: the Byzantine sets, the genesis trigger and fee, and the divergent builder.
  - They also place a valid MSG on the board (`mid 1`, `nb 1`, `exp 4`, no bad shares; `reshare` forces `T1`), followed by `q` ACKs from honest nodes. The request therefore starts ARMED.
  - `run initArmedReachableTest` checks that `init` + `postOwnerMsg` + three `honestStepA` reaches the same MSG and the same ACK posts. The ACK order is `Set.fold` order, and any order of honest ACKs is reachable.
- **`stepHonestProgress`** (honest progress only). It contains:
  - the first MSG, if none is on the board;
  - Step A;
  - Step B and Step C, each weighted three times, for the epoch that `activeEpochForGen` names for `g` and for honest nodes of that epoch;
  - eligible chain blocks, leaving one chain slot free;
  - a tip sync to the chain head;
  - a spend of any digest or variant that has a partial on the board;
  - FINAL, ROTATE, reshare deals and READY.
- **`stepFaults`.** The rollback and restart branch of `step` (with the instance's rule 4 setting), board-height ticks, any chain block including foreign spends, and honest VOID.
- **`stepByz`.** `byzEchoPrevote` aimed at PREVOTE posts already on the board, plus the arbitrary Byzantine posts of `step` with the same value sets (the ACK/COMPLAINT branch is left out).
- **Weighted mixes.**
  - `stepProgressFaults`: 70% progress, 30% faults.
  - `stepAdversarial`: 60% progress, 20% faults, 20% Byzantine.
  - `stepWeighted`: 60% progress, 40% the **original full `step`**.

  A toy model checked that the Rust simulator resamples a step whose chosen branch is disabled. This makes the weights act as weights.

Every branch of a focused step is a branch of `step` with narrower nondeterministic choices. The one extra guard ("no MSG yet" on the owner post) only removes behaviour. So a focused step reaches a subset of the states that `step` reaches from the same initial state. A "no violation" result under a focused step covers real protocol states, but not all of them.

The reachability values come in two forms. The positive form is passed to `--witnesses`. The `No*` negation is passed to `--invariant`, where a violation shows that the state is reachable.

| val | state reached |
|---|---|
| `ArmedReached` / `NoArmed` | the request is armed (`q` ACKs) |
| `LockCertReached` / `NoLockCert` | an open-mode lock certificate exists for some `g` |
| `HonestPartialReached` / `NoHonestPartial` | an honest PARTIAL or sealed PARTIAL |
| `OpenPartialReached` | an honest open PARTIAL (antecedent of LockBeforeShare) |
| `SpendExecuted` / `NoSpendExecuted` | a request transaction is on the target chain |
| `Gen2PartialReached` / `NoGen2` | an honest partial of fee-bump generation 2 |
| `Gen2SpendReached` / `NoGen2Spend` | the generation-2 transaction executed |
| `ReshareDoneReached` / `NoReshareDone` | HANDOVER completed after ROTATE |
| `Epoch2PartialReached` / `NoEpoch2Partial` | the new committee released a partial |
| `HandoverWithOldPartialReached` | HANDOVER is complete and an honest old-committee partial is on the board (antecedent of FreezeSafety) |
| `RollbackAfterPrevoteReached` / `NoRollbackAfterPrevote` | an honest node's PREVOTE is on the board and its ledger entry is empty |
| `RollbackAfterPartialReached` / `NoRollbackAfterPartial` | the same for an honest PARTIAL. Only a disk rollback produces this, because PARTIAL writes the ledger. |
| `FinalReached`, `VoidReached`, `ExpiredReached` and their `No*` forms | each tombstone (antecedents of NoTransientTombstone) |

## 5. Results

### Typecheck and unit tests

| check | command | outcome |
|---|---|---|
| typecheck | `quint typecheck linedealing.qnt` (`runs/v2/typecheck.log`) | exit 0, no errors |
| unit tests | `quint test --main=linedealing linedealing.qnt` (`runs/v2/unit_tests.log`) | 6 passing: anchorSplitTest, initArmedReachableTest, voteRulesTest, rollbackWithRule4Test, rollbackWithoutRule4Test, freezeAndReshareTest |

Every simulation row below is `quint run --main=<main> --init=<init> --step=<step> --max-steps=<steps> --max-samples=<samples> --seed=<seed> ... linedealing.qnt`, run through `heavy-run --mem 8G`. The log is `runs/v2/<run>.log`. The trace is `runs/v2/<run>.itf.json`: the counterexample for a violated row, and one sampled trace for a row with no violation. The wall time is shown in brackets.

The witness and mutant rows use `--invariant=<invariant>`. A witness `No*` invariant that is VIOLATED means the state was reached, and the log holds the trace. A mutant VIOLATED means the bug was caught. A violation stops the run, so "samples" is an upper bound.

#### Witnesses

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

#### Mutants

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

#### Control: --invariants list form on mutants

| run | main | init | step | steps | samples | seed | invariant | outcome | trace length |
|---|---|---|---|---|---|---|---|---|---|
| c_list_broken_rule4 | linedealing_broken_rule4 | initArmedOpen | stepAdversarial | 40 | 3000 | 202 | all five (`--invariants`) | VIOLATED (22s) | 41 states |
| c_list_broken_prevote | linedealing_broken_prevote | initArmedOpen | stepAdversarial | 40 | 3000 | 201 | all five (`--invariants`) | VIOLATED (105s) | 31 states |

### Mutant counterexamples (both genuine; the flags are wired correctly)

**`m_broken_prevote_adv`** (seed 201, 31 states). Setup: `byz1 = {2}`, node 1 on builder 2, open mode, `T2`.

1. Honest node 3 prevotes `dg 111130` (builder 1).
2. Honest node 1 prevotes `dg 111131`.
3. Node 3 restarts with its ledger kept and moves to builder 2 (`restartKeepLedger`). Because rule 1 is off, it prevotes `dg 111131` as well.
4. Byzantine node 2 prevotes both digests. This completes lock `111130 = {3, 4, 2}` and lock `111131 = {1, 3, 2}`.
5. Honest node 4 releases PARTIAL `111130` and honest node 1 releases PARTIAL `111131` in slot `(rid, g = 1)`. NoNonceReuse fails.

**`m_broken_rule4_adv`** (seed 202, 41 states). Setup: `byz1 = {3}`, node 4 on builder 2.

1. Honest node 2 prevotes `dg 111320`.
2. Honest node 4 prevotes `dg 111321`.
3. Byzantine node 3 prevotes both digests.
4. Honest node 1 prevotes `111320`. It then rolls back to an empty ledger and, with rule 4 off, releases PARTIAL `111320` without abstaining. This is already mutant behaviour: rule 4 would have made node 1 abstain.
5. Honest node 2 rolls back to an empty ledger and builder 2. With rule 4 off, it does not abstain. It prevotes `111321`, which completes lock `{4, 3, 2}`.
6. Honest node 4 releases PARTIAL `111321`. NoNonceReuse fails.

In both traces an honest node double-votes by exactly the mechanism the disabled rule forbids.

How much each step configuration can detect, measured on the mutants:

- `initArmedOpen` + `stepAdversarial` catches both mutants (16 s and 78 s).
- `stepWeighted` catches both, from `initArmedOpen` and from plain `init`.
- The original `step` catches neither from `init`, in 10000 samples at 30 steps.
- From `initArmedOpen`, the original `step` catches the rule-4 mutant (`m_broken_rule4_armed_step`) but not the rule-1 mutant (`m_broken_prevote_armed_step`, 3000 samples).

The rows that use the original `step` therefore have only partial detection power.

The control rows `c_list_*` show that the `--invariants` list form used by the safety rows does enforce the invariants. With the same flags and seeds as the mutant rows, both mutants are reported as violations.

### Safety runs

Each row checks all five safety invariants in one run, with `--invariants NoNonceReuse AtMostOneExecution LockBeforeShare NoTransientTombstone FreezeSafety`. A conjunction that holds means each invariant holds. Each run also passes `--witnesses` for the 14 reachability values. The witness columns give the number of sampled traces that reached each state. They show how deep each run actually went.

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

### LOOP item 4b: quorum `q` and the instance `n = 9`, `f = 2` (2026-11-13)

Model change. `QUORUM` was `2 * F + 1`. It is now `quorumOf(N, F) = (N + F + 2) / 2`, which is `⌈(N + F + 1)/2⌉` (SCHEME section 2). Every quorum of the model reads `QUORUM`: the ACK quorum, the OBS set, the lock certificate and the READY quorum of a handover. The counts `F + 1` (NACK, FINAL and VOID, the resharing set) and the anchor index `F` did not change. For `n = 4, f = 1` and `n = 7, f = 2` the value is the same as before (3 and 5), so the semantics of the existing instances did not change. New instance module `linedealing_n9_f2` (`N = 9`, `F = 2`, `QUORUM = 6`). `anchorSplitTest` gained asserts for `quorumOf` (4/1 → 3, 7/2 → 5, 16/5 → 11, 9/2 → 6, 8/2 → 6, 10/3 → 7), for `QUORUM == 3` in the default instance, and for the anchor of six reports with two Byzantine reports at the top or at the bottom.

The two safety runs below were made on the model file with SHA-256 `e38de8818da84aca4aaa330e738a412d80b44beb8db74edf500194692115304b`. After the runs one comment line changed (line 6 of the file header, `N = 3F + 1` to `N >= 3F + 1`); the final file has SHA-256 `80649a2a21d02bd6f6e2e92361529dc3800ce660889b1732dfc6b338f42c5c4d`, and typecheck and the unit tests were run again on it. Both hashes are in `runs/4b/MODEL.sha256`. All rows of the tables above were produced on the model before the change (`runs/v2/MODEL.sha256`). The logs of this section are under `runs/4b/`. Every command was run in `formal/quint` through `heavy-run --mem 8G --name <name> --`. The file argument comes first because the list options `--invariants` and `--witnesses` take every later argument.

| check | command | outcome |
|---|---|---|
| typecheck | `quint typecheck linedealing.qnt` (`runs/4b/typecheck.log`) | exit 0, no errors |
| unit tests | `quint test --main=linedealing linedealing.qnt` (`runs/4b/unit_tests.log`) | 6 passing: anchorSplitTest, initArmedReachableTest, voteRulesTest, rollbackWithRule4Test, rollbackWithoutRule4Test, freezeAndReshareTest |
| safety, `n = 9` (`runs/4b/s_n9_progress.log`) | `quint run linedealing.qnt --main=linedealing_n9_f2 --init=initArmed --step=stepHonestProgress --max-steps=80 --max-samples=300 --seed=501 --invariants NoNonceReuse AtMostOneExecution LockBeforeShare NoTransientTombstone FreezeSafety --witnesses SpendExecuted LockCertReached` | `[ok] No violation found` (805 s wall). Trace length max 81, min 18, average 49.14. `SpendExecuted` witnessed in 203 of 300 traces, `LockCertReached` in 111 of 300 |
| safety, `n = 4`, regression (`runs/4b/s_n4_progfaults.log`) | `quint run linedealing.qnt --main=linedealing --init=initArmedOpen --step=stepProgressFaults --max-steps=40 --max-samples=2000 --seed=305 --invariants NoNonceReuse AtMostOneExecution LockBeforeShare NoTransientTombstone FreezeSafety --witnesses ArmedReached LockCertReached OpenPartialReached HonestPartialReached SpendExecuted Gen2PartialReached Gen2SpendReached ReshareDoneReached HandoverWithOldPartialReached Epoch2PartialReached RollbackAfterPrevoteReached RollbackAfterPartialReached FinalReached VoidReached ExpiredReached` | `[ok] No violation found` (547 s wall). Trace length statistics and all 15 witness counts are identical to row `s_n4_progfaults` above (lock 159, openPart 151, spend 24, gen2Part 7, gen2Spend 3, handover 211, handover+oldPart 6, e2Part 14, rbAfterPrevote 395, rbAfterPartial 143, final 20, void 1068, expired 860) |

Reading. The `n = 9` run reaches a lock certificate of 6 PREVOTE posts in 111 traces and an executed spend in 203 traces (sealed requests spend with no lock certificate), so the five invariants were checked on states past the quorum. The step is `stepHonestProgress`, the same step as row `s_n7_progress`: it has no rollback and no adversarial scheduling (the `rbAfter*` columns of that row are 0). No adversarial or weighted step was run at `n = 9`, and no mutant was run at `n = 9`. The `n = 4` rerun differs from the recorded row only in the wall time, which shows that the change left the default instance as it was.

## 6. Interpretation

**No safety invariant was violated in any run.** Neither instance violated any of the five invariants under the focused steps or under the original `step`, so no protocol flaw was found. Under the focused steps the antecedents of every invariant were reached:

- open honest partials (LockBeforeShare): 151 to 496 traces per n=4 run;
- spends: up to 1201 traces;
- disk rollbacks of a node whose PREVOTE was on the board: 268 to 656 traces; of a node whose PARTIAL was on the board: 79 to 272 traces (both under `stepAdversarial` and `stepProgressFaults`);
- FINAL, VOID and EXPIRED (NoTransientTombstone);
- HANDOVER with an old-committee partial on the board (FreezeSafety): 6 to 15 traces per n=4 run.

`s_n4_adv_open` uses the exact configuration that caught both mutants, `initArmedOpen` + `stepAdversarial` at 40 steps. It ran 3000 traces with no violation. The mutants were caught within 3000 samples, in 16 s and 78 s.

**Limits of these results.**

- They come from random simulation, not proofs. Rare states had few samples:
  - HANDOVER with an old partial, under the focused steps: 6 to 15 traces at n=4, and 0 to 3 at n=7 (1 in 400 for the extra `s_n7_adv_reshare` row). Under the original `step` and `stepWeighted` it was reached 0 to 2 times.
  - The generation-2 spend: at most 27 traces.
  - n=7 under `stepAdversarial`: a lock in only 25 of 600 traces.
- The rows that use the original `step` are shallow at both sizes:
  - `s_n4_step_init`: 2 locks and 0 spends in 3000 traces.
  - `s_n4_step_armed`: 46 locks, 13 spends and no generation 2.
  - n=7: 0 to 1 locks in 2000 traces.

  Those rows are reported for completeness, and their "no violation" carries little weight. The full-action-set rows that do carry weight are `s_n4_weighted` and `s_n7_weighted`: `stepWeighted` keeps all of `step` and caught both mutants from `init`.
- `AtMostOneExecution` holds by construction. `advanceChainReqSpend` requires `not(pinSpentAt(...))`, and every transaction spends the pin. The invariant checks the model's chain abstraction, not the protocol.

## 7. Apalache (`quint verify`)

Apalache 0.56.1 was already installed under `~/.quint/apalache-dist-0.56.1` (directory mtime 2026-11-08, before these runs). It is quint 0.32.0's default `--apalache-version`, so quint used it and downloaded nothing. Two attempts were made, each with `quint verify linedealing.qnt --main=linedealing --init=initArmedOpen --step=stepHonestProgress --max-steps=3 --invariants NoNonceReuse AtMostOneExecution LockBeforeShare NoTransientTombstone FreezeSafety`:

| log | settings | outcome |
|---|---|---|
| `runs/v2/verify/verify_n4_focused_k3.log` | default 4 GB heap | `Error: Ran out of heap memory: Java heap space` after 275 s |
| `runs/v2/verify/verify_n4_focused_k3_xmx20g.log` | `JVM_ARGS=-Xmx20g`, `heavy-run --mem 24G`, timeout 1800 s | Preprocessing completed. At state 0 the log shows that invariants 0, 1 and 2 hold. The process was then killed with exit 137 after 1188 s, while it checked invariant 3. The user journal records `heavy-quint_verify-...scope: Failed with result 'oom-kill'` with a 24G memory peak. The 24G cap was this run's own setting, only 4G above the Java heap. |

Bounded model checking therefore gives **no result** for this model at the tested memory budget. The list folds over the board are the likely cost. A larger heap was not tried.

## 8. Not covered

- The cryptographic algebra (see `experiments/line-dealing/checks.py`).
- Multi-input transactions and UTXO fee arithmetic.
- Adaptive corruption, board split views and target-chain reorgs.
- More than 2 generations, 2 attempts or 2 variants.
- Liveness. No temporal properties are checked. The witnesses show only that the progress states can be reached.
- A crash between the ledger write and the board post. `honestPrevote` writes the ledger and appends the PREVOTE in one atomic action, so the model never explores a rollback after the PREVOTE was sent but before the board included it.

### Lead rerun after item 4b (QUORUM = (N + F + 2) / 2)

| Command | Result |
|---|---|
| `quint run linedealing.qnt --main=linedealing_n9_f2 --init=initArmedOpen --step=stepAdversarial --max-steps=80 --max-samples=300 --seed=502 --invariants NoNonceReuse AtMostOneExecution LockBeforeShare NoTransientTombstone FreezeSafety --witnesses SpendExecuted LockCertReached RollbackAfterPartialReached` | no violation; SpendExecuted 3/300, LockCertReached 25/300, RollbackAfterPartialReached 23/300 (`runs/4b-lead/s_n9_adv.log`) |
| `quint run linedealing.qnt --main=linedealing_broken_rule4 --init=initArmedOpen --step=stepAdversarial --max-steps=40 --max-samples=3000 --seed=202 --invariant=NoNonceReuse` | violated in 18 s: the mutant is still caught under the new quorum (`runs/4b-lead/b202.log`) |

## 9. Model v3: conformance fix M1 (2026-11-14)

The conformance replay of `impl/` (CONFORMANCE.md) found that the model let an honest old-committee node post RS_DEAL after HANDOVER, although SCHEME section 5 has it erase the transferred shares at HANDOVER. `honestReshareDeal` now requires that the node still holds every share it would deal (`holdsShares`), and the unit test `dealAfterHandoverTest` checks it. The model file has SHA-256 `c8b2376ca89e304bf9c06b6f4121278ec9a5e063c72ad4a284faa9b45693d826` (`runs/v3/MODEL.sha256`).

| Check | Command | Result |
|---|---|---|
| typecheck | `quint typecheck linedealing.qnt` and `conformance/linedealing_mbt.qnt` (`runs/v3/typecheck.log`) | exit 0 |
| unit tests | `quint test --main=linedealing linedealing.qnt` (`runs/v3/unit_tests.log`) | 7 passing, including `dealAfterHandoverTest` |
| M1 before the fix | `dealAfterHandoverTest` on the model of commit 3de9c9a (`runs/v3/m1_prefix_test.log`, `runs/v3/prefix_with_test.qnt`) | fails: the late deal is enabled |
| simulation rows | `runs/v3/run_all.sh` (the jobs of `runs/v2/jobs.txt`; logs `runs/v3/<run>.log`, summary `runs/v3/SUMMARY.txt`) | every row has the same verdict as in v2: all witnesses reached, no safety violation, every mutant row as before |
| reshare reachability | `s_n4_adv_reshare`, `s_n7_adv_reshare` | ReshareDoneReached 941/2000 (v2: 920) and 87/400 (v2: 79) |
