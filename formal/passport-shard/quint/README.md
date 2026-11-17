# Passport shard: Quint model

`passportShard.qnt` is an independent model of `research/passport-fit/SHARD-SPEC.md`, sections 3 to 7. It was written from the spec and the EARS requirements at commit `d0d2ce3`, without reading the Lean oracle. The PS-067 guard (decision D-1, OD-1) was added at commit `bb863f6` from the spec sentence. `passportShard_test.qnt` holds the refusal and effect tests. `scripts/run_quint.sh` runs every check, and `scripts/passport_replay.py` replays the traces through `lean/.lake/build/bin/oracle --step`.

## Shape

- `s` is the §3 state. It has the same keys, and `pending` is `PNone` or `PSome({succ, adv})`.
- Each step runs one §4 operation. A refused step keeps `s` unchanged (PS-057) and records the codes in `lastRefused`. `lastOp` is the operation. `ghost` is history that only the model keeps, and the replay does not send it.
- `step` picks any operation with any parameters, so it makes accepted and refused steps. `stepPass` and `stepMostlyHonest` make only accepted steps. In `stepMostlyHonest`, about four steps of five are honest. The invariant runs use all three.
- The instances are `webSynced` (quorum 2 of 3, every reader on the web, every credential synced), `mixed` (quorum 1 of 2, native readers 1 and 3, synced credentials 0 and 1), `allNative` (quorum 3 of 3, nothing synced) and `d0Two` (account device 2, other ids, quorum 1 of 1).
- `MUTANT` selects a broken guard or effect. The modules `mut1` to `mut13` are the mutant runs. `mut11` drops the PS-023 guard and survives (see `COUNTEREXAMPLES.md`).
- Each conditional invariant has a witness of its antecedent with a signature present (`w_ant058`, `w_ant059`, `w_ant060`, `w_ant060exception`, `w_antCoalition`, `w_ant058corrupt`). The witnesses show that the invariant runs check these states and that the invariants are not vacuous. The `runs/inv-*-all.log` files hold the counts. Every antecedent is reached on every instance in `stepMostlyHonest`, at 63 or more traces of 10000. The antecedents of PS-059 and the coalition invariant need a state where no committee or E corruption occurred and a signature exists, and `stepPass` rarely reaches that state. The directed tests `t_inv_*` reach that state and end in `.expect(inv)`.

## Invariants

| Invariant | PS-ids | Property |
|---|---|---|
| `inv_PS058_accessStructure` | PS-058, PS-022, PS-025, PS-055, PS-056 | no signature outside `Fenrir AND (d_1 OR ... OR R)`, also with a fully corrupt committee or E |
| `inv_noUserCoalitionWithoutCommittee` | PS-043, PS-044, PS-055, PS-056 | without a committee or E corruption, `adv_xf` is false and every signature is an honest release |
| `inv_PS059_committeeNeedsAuthorization` | PS-059, PS-019, PS-024 | while `adv_xf` is false, every signature has an authorization and an assertion over the same `(ic, nf)` |
| `inv_PS060_userVerifiedUnlock` | PS-060, PS-011, PS-012, PS-062 | a signature needs a user-verified unlock, except through the provider, a recovery leak or a guardian quorum |
| `inv_recoveryNoWholeKey` | PS-036, PS-042, PS-044, PS-046 | recovery operations and `E_REPROVISION` keep `adv_xf`; `adv_root` only through a via set; the whole key needs a committee or E corruption and a root leak |
| `inv_PS019_assertionBindsIntent` | PS-018, PS-019 | an authorization has an assertion over its `(ic, nf)`, and its `nf` is used |
| `inv_PS064_oneIntentPerNf` | PS-064, PS-021 | one `nf` authorizes one intent |
| `inv_authorizationSource` | PS-016, PS-053, PS-054, PS-065 | an authorization comes from an approval, a redirected approval or a credential that the adversary holds |
| `inv_PS066_hijackWebOnly` | PS-066 | a corrupt origin redirects only approvals on web credentials |
| `inv_PS067_enrolledNeverAdvSuccessor` | PS-067, PS-038 | no device id that a passing `ENROLL` added is ever added to `adv_cred` by `RECOVER_FINALISE` (ghost `enrolled` and `adv_finalised`; `w_ant067` witnesses both sets non-empty) |
| `inv_PS001_cfgFixed`, `inv_cfgDomain` | PS-001, PS-002, PS-003 | `cfg` does not change and stays in the domain |

## The other requirements

- **PS-006 to PS-013, PS-067, PS-016 to PS-025, PS-030 to PS-056, PS-061 to PS-063 and PS-065 to PS-066.** Each is an operation of the model. Each has at least one test in `passportShard_test.qnt`. The replay checks each one through the oracle, both accepted and refused.
- **PS-057.** A refused step keeps `s`. The replay sends the refusal and compares its exact code list.
- **PS-002, PS-003 and PS-005.** `passport_replay.py --probe-domain` checks these. The model's `cfg` is always in the domain, so the traces never reach them.
- **PS-004.** This is `initState` in the model. The `--step` replay does not check the initial state of the oracle, because every trace sends the model's own initial state. This is the one gap of the replay. `t_steal_locked` compares the model with PS-004.
- **PS-014, PS-015 and PS-026 to PS-029.** These requirements are on the wallet and the circuit. They are outside the model (SHARD-SPEC §8).

## Gate

`heavy-run scripts/run_quint.sh all`. The gate passes when every condition below holds:

- the 53 tests pass;
- every invariant gives `[ok]` at 10000 samples and 40 steps on every instance and step;
- every mutant except `mut11` violates its invariant (`runs/mutant-summary.txt`);
- every replayed transition agrees;
- every negative control (a wrong `cfg` value, or a mutant trace) gives `DISAGREE`.

The traces are generated again with a fixed seed. They are not committed.
