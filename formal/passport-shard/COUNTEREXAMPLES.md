# Passport shard: counterexamples

Lane `passport-quint`, LOOP item 39. Each entry is a disagreement between the Quint model and the Lean oracle, or an invariant violation or modelling observation that is a real finding. Each entry has one verdict:

- **CONFIRMED**: the counterexample runs on the oracle and shows a defect.
- **NOT REPRODUCED**: the counterexample does not run on the oracle.
- **GUARD HOLDS**: a guard of the oracle stops the counterexample.
- **OPEN DESIGN**: the spec does not decide the behavior. The owner of the spec must decide.

The model is `quint/passportShard.qnt`. It was written from `research/passport-fit/SHARD-SPEC.md` §3-7 only. Each kept trace is under `quint/regressions/` and replays as a named test in `scripts/run_quint.sh replay`.

## Replay result

The Quint model and the oracle disagree on no transition. There are 64000 transitions in 1600 traces: four instances, and 400 traces of 40 steps for each instance. This result is from the gate run after the PS-067 fix (`quint/runs/gate-all.log`). The traces include `pending-successor` refusals (6 traces each on `webSynced`, `mixed` and `allNative`, 2 on `d0Two`). These transitions include accepted and refused operations. Each refusal is compared by its exact list of codes. Each acceptance is compared on every key of the §3 state. No invariant fails on the specified model.

## OD-1: the pending successor id can be enrolled before RECOVER_FINALISE

**Verdict: CONFIRMED, fixed in commit `bb863f6`** (PS-067, decision D-1 of SHARD-SPEC.md §9, option (a): lead pick, for owner confirmation). This entry was OPEN DESIGN before the fix.

Trace: `quint/regressions/od1_pendingSuccessorEnrolled.itf.json`. Test: `od1_pendingSuccessorEnrolled` in `quint/passportShard_test.qnt`.

The sequence before the fix:

1. `CORRUPT_GUARDIAN(0)`, `CORRUPT_GUARDIAN(1)` and `PUBLISH_RWRAP(0)` occur with quorum 2. The adversary gets the root through `via_quorum` (PS-046).
2. `ADV_RECOVER_SUBMIT(2)` passes, and `pending` becomes `{"succ": 2, "adv": true}` (PS-040, PS-041).
3. `ENROLL(0, 2)` passes. PS-007 checked only that `d` is fresh.
4. `RECOVER_FINALISE` passes. PS-039 checks only that `pending` is not `null`. Then `creds` becomes `{2}` and `adv_cred` gets 2 (PS-036, PS-038).

At the end, the adversary held the credential of device 2, and the user had enrolled device 2 in step 3.

The fix. PS-067: while `pending` is not `null`, `ENROLL(by, d)` with `d = pending.succ` is refused with the code `pending-successor`, for both values of `pending.adv`. Options (b) (`RECOVER_FINALISE` refuses a successor that is no longer fresh) and (c) (no change) are recorded with the reasons in SHARD-SPEC.md §9.

Before and after:

- The od1 test now expects step 3 to be refused with `["pending-successor"]`, and `creds` to stay `{0}`. On the model without the guard this test fails at step 3. On the fixed model it passes.
- `inv_PS067_enrolledNeverAdvSuccessor` (no id that a passing `ENROLL` added is ever added to `adv_cred` by `RECOVER_FINALISE`) is violated on the model without the guard (`webSynced`, `stepMostlyHonest`, 10000 samples, 40 steps, seed 20261116). The mutant `mut13_enrollPendingSucc` drops the guard and is KILLED by that invariant in the gate. Its trace replays as DISAGREE against the fixed oracle.
- The trace kept before the fix (ENROLL accepted) replays against the fixed oracle as DISAGREE at the ENROLL step: the model accepted and the oracle answers `{"refused": ["pending-successor"]}`. The kept trace was exported again from the fixed model. It replays with 6 agreeing transitions.
- Lean: `pending_successor_fresh` proves that in every reachable state the pending successor is in neither `creds` nor `readers`. `enrolled_never_adv_successor` proves that after a passing `ENROLL(b, d)` and any further operations, `RECOVER_FINALISE` does not add `d` to `adv_cred`. The Lean mutant `lmut1_noPendingSuccessorGuard` (`scripts/lean_mutants.sh`) drops the guard and fails `lake build --wfail` in `Tests.lean` and `Theorems.lean`.
- The logs of the runs before the fix are `quint/runs/od1-prefix-test.log`, `quint/runs/od1-prefix-inv_PS067.log`, `quint/runs/od1-prefix-trace-vs-fixed-oracle.log` and `lean/od1-prefix-build.log`.

## Modelling observations (no verdict needed)

- **`no-wrap` never fails alone.** In every reachable state, `creds` is a subset of `readers`. `ENROLL` adds the device to both sets, `RECOVER_FINALISE` adds the successor to `readers`, and `REMOVE_DEVICE` removes from `creds` only. So the only refusals that contain `no-wrap` are combined refusals with `not-enrolled`. The replay covers those combined refusals.
- **PS-023 has no safety invariant.** A mutant that drops the `committee-corrupt` guard of `RELEASE` (`mut11_corruptRelease`) survives every invariant. This is expected. `CORRUPT_COMMITTEE` also sets `adv_xf` (PS-043), so a release by a corrupt committee gives no capability that `ADV_SIGN` (PS-056) does not already give. The refusal test `t_release_refusals` and the oracle replay check PS-023 as a refusal code.
