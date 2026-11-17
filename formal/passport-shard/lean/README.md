# Lean oracle: Passport shard placement

The Lean oracle for `research/passport-fit/SHARD-SPEC.md`. The spec defines the
placement of the first shard of split-line dealing in Midnight Passport: a
wrapped shard root, one wrap for each reader, an ES256 assertion bound to the
intent, and a guardian recovery wrap.

Lean 4.35.0, no Mathlib. Only the axioms `propext`, `Classical.choice` and
`Quot.sound` occur. No module holds `sorry`. The oracle comes from the spec
only. No Quint model was read.

| File | Content |
|---|---|
| `PassportShard/Spec.lean` | `Cfg`, `St`, `Op`, `Refusal`, `init`, `refusals`, `effect`, `apply`, `runOps`, `Reach`. No `Lean.*` import. |
| `PassportShard/Theorems.lean` | the invariants `Inv` and `Inv2` and the property theorems |
| `PassportShard/Tests.lean` | 101 step-level pins, each checked by `decide +kernel` and by `#guard` |
| `PassportShard/Audit.lean` | `#audit_ns PassportShard` pinned at `[]`, and `#print axioms` of each theorem, pinned |
| `Main.lean` | the codec and the two modes. No transition logic. |

The JSON codec and the `#audit_ns` command come from `../../lean-split/codec`.

## Build and run

    LEAN_ABORT_ON_PANIC=1 lake build --wfail
    LEAN_ABORT_ON_PANIC=1 .lake/build/bin/oracle < request.json
    LEAN_ABORT_ON_PANIC=1 .lake/build/bin/oracle --step < steps.jsonl

- Default mode: one `kink-implementation/1` request,
  `{"protocol": "kink-implementation/1", "program": NAME, "inputs": {"cfg", "d0", "ops"}}`.
  The answer is `{"end": "final", "cells": {"state", "obs"}}`, or
  `{"end": "could-not-apply", "reason": CODES}` for a configuration that PS-002
  or PS-003 refuses. `obs` holds one entry for each operation:
  `{"accepted": true}` or `{"refused": [CODES]}`.
- `--step`: JSON Lines. One line `{"state": S, "op": O}` gives one line:
  `{"state": S', "obs": {"accepted": true}}`, `{"refused": [CODES]}` (the state
  is unchanged), `{"refused": ["outside-state-domain"]}`, or `{"error": TEXT}`
  for a line that does not decode.

The state keys, the operation names and their parameters are those of
SHARD-SPEC.md sections 3 and 4. Each set is a JSON array in ascending order.
The codec removes duplicates when it decodes a set. The decoder refuses an
unknown, a missing or a duplicate key, a fraction and an exponent.

## Hypotheses

The cryptography is abstract. Each hypothesis of SHARD-SPEC.md section 6 is one
rule of `Spec.lean`: H-WRAP, H-PRF and H-PAGE in `prfEval` and `leak`, H-SHAMIR
in `quorumRule`, H-CONTRIB and H-SIG in the guards of `release` and `advSign`,
H-ES256 in the guards of `approve` and `advAssert`, H-BLIND in `originAssert`, H-BIND and H-MIDNIGHT in
the guards of `authorize`. A secret is never a value in the state: the state
records who holds it. The theorems hold for every protocol whose primitives
satisfy these rules. They are not Lean axioms.

## Theorems

`Reach c d0 s` means: `s` is the state after any sequence of honest and
adversarial operations from `init c d0`.

| Property | Theorems |
|---|---|
| Nobody outside the access structure signs, also with a fully corrupt committee | `no_signature_outside_access_structure`, `fully_corrupt_committee_cannot_forge`, `root_needs_leaf`, `via_sound` |
| No user-side coalition signs without the committee | `no_signature_without_committee`, `stolen_root_needs_user_approval`, `committee_half_source` |
| Every signature needs a user-verified unlock | `signature_needs_user_verification` (three named exceptions), `signature_needs_user_verification_strict` (no exception with device-bound readers and no recovery wrap) |
| Recovery keeps the access structure and the key apart | `recovery_keeps_committee_half`, `recovery_gives_no_root`, `eReprovision_frame`, `valid_cfg_no_overlap` |
| An assertion authorizes only its intent | `assertion_binds_intent`, `authorize_needs_exact_assertion`, `nf_authorizes_one_intent`, `authorization_is_user_approved`, `hijack_needs_corrupt_origin` |
| An enrolled device is never the successor of the adversary (PS-067, decision D-1) | `enroll_refuses_pending_successor`, `pending_successor_fresh`, `enrolled_never_adv_successor` |

## Limits

- The statement "every signature needs a user-verified unlock" is false for
  this placement without its exceptions. The provider of a synced passkey
  evaluates the PRF with no user verification. A guardian quorum opens the
  recovery wrap with no passkey. An honest recovery on a corrupt origin shows
  the root to that origin. `signature_needs_user_verification` names the three
  cases.
- "Recovery never puts the whole key in one place" is proved only as far as the
  state reaches. The state records what the adversary holds. It has no record
  of which honest party holds what. The proved parts: no recovery operation
  changes `adv_xf`, none sets `adv_root` under an honest origin and fewer
  corrupt guardians than the quorum, and a reprovision by `E` changes
  `committee_corrupt` and `epoch` only. `cfg.overlap` drives no transition:
  PS-003 refuses a configuration with an overlap.
- `stolen_root_needs_user_approval` and `authorization_is_user_approved` need
  `hijacked = []`. A corrupt origin sets the challenge of an approval on a web
  credential (PS-065). `hijack_needs_corrupt_origin` gives `hijacked = []` from
  an honest origin.
- PS-014, PS-015 and PS-026 to PS-029 have no state in the oracle.
- The package has no `cases.json` and no ambiguity ledger. The gates
  `words`, `cases`, `mutants`, `ledger` and `trace` of
  `formal/lean-split/gates.sh` were not run for it.
- `../scripts/lean_mutants.sh` runs the oracle mutants. Each one edits
  `Spec.lean` in place and must fail `lake build --wfail`. `lmut1` drops the
  PS-067 guard. The build fails in `Tests.lean` (the od1 pins) and in
  `Theorems.lean` (`enroll_refuses_pending_successor`, `pendFresh_apply`).
  `mutants.log` holds the result.

## Requirements

| ID | Sentence | Definitions | Theorems and pins | Scope |
|---|---|---|---|---|
| PS-001 | The shard model shall keep `cfg` unchanged in every operation. | `St.cfg`, `effect` | `cfg_reach` | proved |
| PS-002 | If `cfg.quorum` is less than 1 or more than `cfg.n_guard`, then the shard model shall refuse the configuration with the code `bad-quorum`. | `cfgRefusals`, `validCfg` | pins | pinned |
| PS-003 | If `cfg.overlap` is not empty, then the shard model shall refuse the configuration with the code `guardian-overlap`. | `cfgRefusals`, `validCfg` | `valid_cfg_no_overlap` | proved |
| PS-004 | When an account is created on device `d0`, the shard model shall set `readers`, `creds` and `prf_log` to `{d0}`, set `epoch` to 0, set `pending` to `null`, set every boolean to false and set every other set to the empty set. | `init` | `inv_init`, `inv2_init`, pins | proved |
| PS-005 | If a `--step` state has a `cfg` that PS-002 or PS-003 refuses, then the shard oracle shall answer `{"refused": ["outside-state-domain"]}`. | `validState`; `Main.oracle.step` | mode check | checked by run |
| PS-006 | When an `ENROLL(by, d)` operation passes, the shard model shall record a PRF evaluation on `by`, add `d` to `creds` and add `d` to `readers`. | `effect .enroll`, `prfEval` | pins | pinned |
| PS-007 | If `by` is not in `creds`, `by` is not in `readers`, or `d` is not fresh, then the shard model shall refuse `ENROLL(by, d)` with the code of each failed guard from `not-enrolled`, `no-wrap` and `already-enrolled`. | `refusals .enroll`, `fresh` | pins | pinned |
| PS-067 | While `pending` is not `null`, if `d` equals `pending.succ`, then the shard model shall refuse `ENROLL(by, d)` with the code `pending-successor`. | `refusals .enroll`, `notPendingSucc` | `enroll_refuses_pending_successor`, `pending_successor_fresh`, `enrolled_never_adv_successor`, pins | proved |
| PS-008 | When a `REMOVE_DEVICE(by, d)` operation passes, the shard model shall remove `d` from `creds` and keep `readers` unchanged. | `effect .removeDevice` | pins | pinned |
| PS-009 | If `by` is not in `creds`, `d` is not in `creds`, or `by` equals `d`, then the shard model shall refuse `REMOVE_DEVICE(by, d)` with the code of each failed guard from `not-enrolled`, `unknown-device` and `self-removal`. | `refusals .removeDevice` | pins | pinned |
| PS-010 | When an `UNLOCK(d, ic)` operation passes, the shard model shall add `[d, ic]` to `unlock_log`. | `effect .unlock` | pins | pinned |
| PS-011 | When an `UNLOCK(d, ic)` operation passes, the shard model shall record a PRF evaluation on `d`. | `effect .unlock`, `prfEval` | `Inv.unlockPrf` | proved |
| PS-012 | While `origin_corrupt` is true, when an `UNLOCK`, `ENROLL` or `PUBLISH_RWRAP` operation passes on an acting device that is not in `cfg.native`, the shard model shall set `adv_root` to true and add the acting device to `via_origin_leak`. | `leak`, `prfEval` | pins; `viaOk .originLeak` | proved (invariant), pinned |
| PS-013 | If `d` is not in `creds` or `d` is not in `readers`, then the shard model shall refuse `UNLOCK(d, ic)` with the code of each failed guard from `not-enrolled` and `no-wrap`. | `refusals .unlock` | pins | pinned |
| PS-014 | When the Passport wallet has computed the contributions of one request, the Passport wallet shall erase the shard root and every value derived from it from memory. | none | none | outside the oracle |
| PS-015 | The Passport wallet shall keep the ECDSA slot halves of an address on the one device that ran the slot session and outside every wrap. | none | none | outside the oracle |
| PS-016 | When an `APPROVE(d, ic, nf)` operation passes, the shard model shall add `[d, ic, nf]` to `approved` and to `asserts`. | `effect .approve` | `Inv.assertSrc`, pins | proved |
| PS-017 | If `d` is not in `creds`, then the shard model shall refuse `APPROVE(d, ic, nf)` with the code `not-enrolled`. | `refusals .approve` | pins | pinned |
| PS-018 | When an `AUTHORIZE(d, ic, nf)` operation passes, the shard model shall add `[ic, nf]` to `authorized` and add `nf` to `used_nf`. | `effect .authorize` | `assertion_binds_intent` | proved |
| PS-019 | If `[d, ic, nf]` is not in `asserts`, then the shard model shall refuse `AUTHORIZE(d, ic, nf)` with the code `no-assertion`. | `refusals .authorize` | `authorize_needs_exact_assertion` | proved |
| PS-020 | If `d` is not in `creds`, then the shard model shall refuse `AUTHORIZE(d, ic, nf)` with the code `not-enrolled`. | `refusals .authorize` | pins | pinned |
| PS-021 | If `nf` is in `used_nf`, then the shard model shall refuse `AUTHORIZE(d, ic, nf)` with the code `nf-used`. | `refusals .authorize` | `nf_authorizes_one_intent` | proved |
| PS-022 | When a `RELEASE(ic, nf)` operation passes, the shard model shall add `ic` to `sigs`. | `effect .release` | pins | pinned |
| PS-023 | If `committee_corrupt` is true, then the shard model shall refuse `RELEASE(ic, nf)` with the code `committee-corrupt`. | `refusals .release` | pins | pinned |
| PS-024 | If `[ic, nf]` is not in `authorized`, then the shard model shall refuse `RELEASE(ic, nf)` with the code `not-authorized`. | `refusals .release` | `Inv.sigComm` | proved |
| PS-025 | If `unlock_log` holds no pair `[d, ic]` for any `d` and `adv_root` is false, then the shard model shall refuse `RELEASE(ic, nf)` with the code `no-contribution`. | `refusals .release`, `hasUnlock` | `Inv.sigUser` | proved |
| PS-026 | The Passport wallet shall derive `x_u`, the tweak seed, the receive key `u` and `K_exit` of each address from the shard root with a domain-separated hash. | none (H-DERIVE) | none | outside the oracle |
| PS-027 | The Passport wallet shall store one wrap of the shard root for each enrolled reader in the Passport account inbox. | `St.readers` | none | outside the oracle |
| PS-028 | The Passport native wallet shall require one user verification for each use of the enclave reader key. | `Cfg.native`, `leak` | none | outside the oracle |
| PS-029 | The `authorize` circuit shall accept an owner source only with an ES256 assertion that has the user-verification flag and the challenge `H(charter_id, ic, nf)`. | `refusals .authorize` (H-BIND, H-ES256) | none | outside the oracle |
| PS-030 | When a `PUBLISH_RWRAP(by)` operation passes, the shard model shall record a PRF evaluation on `by`, set `r_wrap` to true and set `r_wrap_ever` to true. | `effect .publishRWrap` | pins | pinned |
| PS-031 | If `by` is not in `creds` or `by` is not in `readers`, then the shard model shall refuse `PUBLISH_RWRAP(by)` with the code of each failed guard from `not-enrolled` and `no-wrap`. | `refusals .publishRWrap` | pins | pinned |
| PS-032 | When a `RECOVER_SUBMIT(succ)` operation passes, the shard model shall set `pending` to `{"succ": succ, "adv": false}`. | `effect .recoverSubmit` | pins | pinned |
| PS-033 | If `r_wrap` is false, `pending` is not `null`, or `succ` is not fresh, then the shard model shall refuse `RECOVER_SUBMIT(succ)` with the code of each failed guard from `no-recovery-wrap`, `recovery-pending` and `already-enrolled`. | `refusals .recoverSubmit` | `Inv2.pendEver`, pins | proved |
| PS-034 | When a `RECOVER_CANCEL(by)` operation passes, the shard model shall set `pending` to `null`. | `effect .recoverCancel` | pins | pinned |
| PS-035 | If `by` is not in `creds` or `pending` is `null`, then the shard model shall refuse `RECOVER_CANCEL(by)` with the code of each failed guard from `not-enrolled` and `no-pending`. | `refusals .recoverCancel` | pins | pinned |
| PS-036 | When a `RECOVER_FINALISE` operation passes, the shard model shall set `creds` to `{succ}`, add `succ` to `readers`, set `r_wrap` to false and set `pending` to `null`, where `succ` is the successor of `pending`. | `effect .recoverFinalise` | `recovery_gives_no_root`, pins | proved |
| PS-037 | While `origin_corrupt` is true, when a `RECOVER_FINALISE` operation passes with `pending.adv` false and a successor that is not in `cfg.native`, the shard model shall set `adv_root` to true and add the successor to `via_recovery_leak`. | `effect .recoverFinalise`, `leak` | `Inv2.leakEver`, pins | proved |
| PS-038 | When a `RECOVER_FINALISE` operation passes with `pending.adv` true, the shard model shall add the successor to `adv_cred`. | `effect .recoverFinalise` | pins | pinned |
| PS-039 | If `pending` is `null`, then the shard model shall refuse `RECOVER_FINALISE` with the code `no-pending`. | `refusals .recoverFinalise` | pins | pinned |
| PS-040 | When an `ADV_RECOVER_SUBMIT(succ)` operation passes, the shard model shall set `pending` to `{"succ": succ, "adv": true}`. | `effect .advRecoverSubmit` | pins | pinned |
| PS-041 | If `adv_guard` has fewer than `cfg.quorum` members, `r_wrap` is false, `pending` is not `null`, or `succ` is not fresh, then the shard model shall refuse `ADV_RECOVER_SUBMIT(succ)` with the code of each failed guard from `no-quorum`, `no-recovery-wrap`, `recovery-pending` and `already-enrolled`. | `refusals .advRecoverSubmit` | pins | pinned |
| PS-042 | When an `E_REPROVISION` operation occurs, the shard model shall set `committee_corrupt` to false, add 1 to `epoch` and keep `adv_xf` unchanged. | `effect .eReprovision` | `recovery_keeps_committee_half` | proved |
| PS-043 | When a `CORRUPT_COMMITTEE` operation occurs, the shard model shall set `committee_corrupt` to true and set `adv_xf` to true. | `effect .corruptCommittee` | `committee_half_source` | proved |
| PS-044 | When a `CORRUPT_E` operation occurs, the shard model shall set `e_corrupt` to true and set `adv_xf` to true. | `effect .corruptE` | `committee_half_source` | proved |
| PS-045 | When a `CORRUPT_ORIGIN` operation occurs, the shard model shall set `origin_corrupt` to true. | `effect .corruptOrigin` | pins | pinned |
| PS-046 | While `r_wrap_ever` is true and `adv_guard` has at least `cfg.quorum` members, when a `CORRUPT_GUARDIAN` or `PUBLISH_RWRAP` operation has passed and its other effects are applied, the shard model shall set `adv_root` to true and set `via_quorum` to true. | `quorumRule` | `viaOk .quorum`, pins | proved (invariant), pinned |
| PS-047 | If `g` is not less than `cfg.n_guard` or `g` is in `adv_guard`, then the shard model shall refuse `CORRUPT_GUARDIAN(g)` with the code of each failed guard from `unknown-guardian` and `already-corrupt`. | `refusals .corruptGuardian` | pins | pinned |
| PS-048 | When a `STEAL_DEVICE(d, true)` operation passes, the shard model shall add `d` to `adv_cred`. | `effect .stealDevice` | pins | pinned |
| PS-049 | When a `STEAL_DEVICE(d, false)` operation passes, the shard model shall keep the state unchanged. | `effect .stealDevice` | pins | pinned |
| PS-050 | If `d` is not known, then the shard model shall refuse `STEAL_DEVICE(d, unlocked)` with the code `unknown-device`. | `refusals .stealDevice`, `known` | pins | pinned |
| PS-051 | When a `PROVIDER_TAKEOVER(d)` operation passes, the shard model shall add `d` to `adv_cred`. | `effect .providerTakeover` | pins | pinned |
| PS-052 | If `d` is not in `cfg.synced` or `d` is not known, then the shard model shall refuse `PROVIDER_TAKEOVER(d)` with the code of each failed guard from `not-synced` and `unknown-device`. | `refusals .providerTakeover` | pins | pinned |
| PS-053 | When an `ADV_ASSERT(d, ic, nf)` operation passes, the shard model shall add `[d, ic, nf]` to `asserts`. | `effect .advAssert` | pins | pinned |
| PS-054 | If `d` is not in `adv_cred`, then the shard model shall refuse `ADV_ASSERT(d, ic, nf)` with the code `no-credential`. | `refusals .advAssert` | `authorization_is_user_approved` | proved |
| PS-055 | When an `ADV_SIGN(ic)` operation passes, the shard model shall add `ic` to `sigs`. | `effect .advSign` | pins | pinned |
| PS-056 | If `adv_xf` is false, or `unlock_log` holds no pair `[d, ic]` for any `d` while `adv_root` is false, then the shard model shall refuse `ADV_SIGN(ic)` with the code of each failed guard from `no-committee-half` and `no-contribution`. | `refusals .advSign` | `Inv.sigUser`, `Inv.sigComm` | proved |
| PS-057 | If an operation fails a guard, then the shard model shall keep the state unchanged. | `apply` | `apply_refused` | proved |
| PS-058 | While the via sets are empty, the shard model shall hold in `sigs` only intents `ic` for which `unlock_log` holds a pair `[d, ic]` with `d` in `prf_log`. | `Inv`, `viaOk` | `no_signature_outside_access_structure`, `fully_corrupt_committee_cannot_forge`, `root_needs_leaf`, `via_sound` | proved |
| PS-059 | While `adv_xf` is false, the shard model shall hold in `sigs` only intents `ic` for which `authorized` holds a pair `[ic, nf]` and `asserts` holds a triple `[d, ic, nf]`. | `Inv` | `no_signature_without_committee`, `stolen_root_needs_user_approval` | proved |
| PS-060 | While `via_provider` and `via_recovery_leak` are empty and `via_quorum` is false, the shard model shall hold in `sigs` only intents `ic` for which a reader `d` in `prf_log` has `[d, ic]` in `unlock_log`, `d` in `via_origin_leak` or `d` in `via_theft`. | `Inv`, `Inv2` | `signature_needs_user_verification`, `signature_needs_user_verification_strict` | proved |
| PS-061 | When a `CORRUPT_GUARDIAN(g)` operation passes, the shard model shall add `g` to `adv_guard`. | `effect .corruptGuardian` | pins | pinned |
| PS-062 | When a `STEAL_DEVICE(d, true)` operation passes with `d` in `readers`, the shard model shall record a PRF evaluation on `d`, set `adv_root` to true and add `d` to `via_theft`. | `effect .stealDevice` | `viaOk .theft`, pins | proved (invariant), pinned |
| PS-063 | When a `PROVIDER_TAKEOVER(d)` operation passes with `d` in `readers` and `d` not in `cfg.native`, the shard model shall set `adv_root` to true and add `d` to `via_provider`. | `effect .providerTakeover` | `viaOk .provider`, pins | proved (invariant), pinned |
| PS-064 | The shard model shall hold in `authorized` at most one intent for each `nf`. | `Inv.authUnique` | `nf_authorizes_one_intent` | proved |
| PS-065 | When an `ORIGIN_ASSERT(d, ic, nf)` operation passes, the shard model shall add `[d, ic, nf]` to `hijacked` and to `asserts`. | `effect .originAssert` | `Inv2.assertSrc`, `Inv2.hijackSrc`, pins | proved |
| PS-066 | If `origin_corrupt` is false, `d` is not in `creds`, or `d` is in `cfg.native`, then the shard model shall refuse `ORIGIN_ASSERT(d, ic, nf)` with the code of each failed guard from `origin-honest`, `not-enrolled` and `native-credential`. | `refusals .originAssert` | `hijack_needs_corrupt_origin`, pins | proved |
