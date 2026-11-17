# Passport shard placement: specification

This specification defines the placement of the first shard of split-line dealing in Midnight Passport. It defines the state, the operations, the parties and the requirements PS-001 to PS-067. `REPORT.md` in this folder gives the reasons. `design/enhancement/DESIGN.md` defines split-line dealing.

The Lean oracle in `formal/passport-shard/lean` implements sections 3 to 5. A Quint model of this specification uses sections 3 to 7 only.

## 1. The placement

- The **shard root** is one 32-byte random secret for each Passport account.
- The wallet derives `x_u`, the tweak seed, the receive key `u` and `K_exit` of each address from the shard root.
- A **reader** is a device that can open a wrap of the shard root. A web reader derives its reader key from the WebAuthn PRF output of its passkey. A native reader holds its reader key in a device enclave.
- A **wrap** is the shard root encrypted to one reader key. The Passport account inbox stores the wraps. The inbox is append-only.
- A **credential** is the ES256 passkey of a device. The charter record holds a commitment to each enrolled credential.
- A spend has two user-verified steps. The unlock opens the wrap and computes the contribution. The approval is an ES256 assertion over the challenge `H(charter_id, ic, nf)`.
- The **recovery wrap** is the shard root encrypted to a key that only a guardian quorum can rebuild.
- The recovery group `E` holds a backup of the committee half `x_f`. It holds no part of the shard root.

The access structure of an address is `Fenrir AND (d_1 OR ... OR d_m OR R)`. Each `d_i` is an enrolled reader. `R` is the guardian quorum.

## 2. Parties

| Party | Holds | Honest behavior |
|---|---|---|
| Device `d` | a wrap, a reader key, a credential | unlocks and approves only on user verification |
| Committee | the committee half `x_f` | releases a signature only for an authorization in force |
| Recovery group `E` | a 3-of-5 backup of `x_f` | reprovisions a successor committee |
| Guardian `g` | a share of the recovery secret | answers only the owner |
| Wallet origin | nothing at rest | serves the wallet page of a web reader |
| Passkey provider | the synced credentials | syncs them to the devices of the user |
| Midnight | the charter record, `authorize` | accepts one `authorize` for each `nf` |

The adversary corrupts the committee, three members of `E`, the wallet origin, single guardians and the provider. The adversary steals devices. One adversary holds everything that the corrupt parties hold.

## 3. State

The state is one JSON object with exactly these keys. A device id, a guardian id, an intent id `ic` and a nullifier `nf` are non-negative integers.

| Key | Type | Meaning |
|---|---|---|
| `cfg` | object | the configuration (below) |
| `readers` | set of `d` | devices that have a wrap in the inbox |
| `creds` | set of `d` | credentials enrolled in the charter |
| `r_wrap` | boolean | a recovery wrap of the current guardian session exists |
| `r_wrap_ever` | boolean | a recovery wrap was published at some time |
| `pending` | `null` or `{"succ": d, "adv": boolean}` | the pending recovery and its origin |
| `unlock_log` | set of `[d, ic]` | a user-verified unlock on `d` dealt a contribution for `ic` |
| `prf_log` | set of `d` | readers with a user-verified PRF evaluation or enclave use |
| `approved` | set of `[d, ic, nf]` | assertions that the user approved |
| `asserts` | set of `[d, ic, nf]` | all assertions that exist |
| `hijacked` | set of `[d, ic, nf]` | approvals for which the corrupt origin set the challenge |
| `authorized` | set of `[ic, nf]` | authorizations in force |
| `used_nf` | set of `nf` | nullifiers that `authorize` consumed |
| `sigs` | set of `ic` | intents that have a complete signature |
| `adv_root` | boolean | the adversary holds the shard root |
| `adv_xf` | boolean | the adversary holds `x_f` |
| `via_origin_leak` | set of `d` | the root leaked from an unlock on web reader `d` |
| `via_recovery_leak` | set of `d` | the root leaked from the recovery of successor `d` |
| `via_theft` | set of `d` | the root leaked from stolen reader `d` |
| `via_provider` | set of `d` | the root leaked through the provider of reader `d` |
| `via_quorum` | boolean | the root leaked to a corrupt guardian quorum |
| `adv_cred` | set of `d` | credentials that the adversary can assert with |
| `adv_guard` | set of `g` | corrupt guardians |
| `origin_corrupt` | boolean | the wallet origin is corrupt |
| `committee_corrupt` | boolean | the current committee is fully corrupt |
| `e_corrupt` | boolean | three members of `E` are corrupt |
| `epoch` | integer | the number of reprovisions |

`cfg` has exactly these keys. The configuration never changes.

| Key | Type | Meaning |
|---|---|---|
| `quorum` | integer | the number of guardians that rebuild the recovery secret |
| `n_guard` | integer | the guardian ids are `0` to `n_guard - 1` |
| `native` | set of `d` | the native readers |
| `synced` | set of `d` | the credentials that a passkey provider syncs |
| `overlap` | set of `g` | the guardians that a committee operator or a member of `E` runs |

**Encoding.** A set is a JSON array in ascending order with no duplicate. Pairs and triples are JSON arrays, and their order is lexicographic. An integer is a JSON integer. An integer of 2^63 or more is a canonical decimal string.

The term **via sets** means the four sets `via_origin_leak`, `via_recovery_leak`, `via_theft` and `via_provider`, and the flag `via_quorum`. The via sets are **empty** when the four sets are empty and `via_quorum` is false.

## 4. Operations

An operation is a JSON object. The key `op` holds the name. The other keys are the parameters.

| `op` | Parameters | Actor |
|---|---|---|
| `ENROLL` | `by`, `d` | device `by` |
| `REMOVE_DEVICE` | `by`, `d` | device `by` |
| `UNLOCK` | `d`, `ic` | device `d` |
| `APPROVE` | `d`, `ic`, `nf` | device `d` |
| `AUTHORIZE` | `d`, `ic`, `nf` | any party |
| `RELEASE` | `ic`, `nf` | the honest committee |
| `PUBLISH_RWRAP` | `by` | device `by` |
| `RECOVER_SUBMIT` | `succ` | the owner with an honest guardian quorum |
| `RECOVER_CANCEL` | `by` | device `by` |
| `RECOVER_FINALISE` | none | any party |
| `E_REPROVISION` | none | the recovery group `E` |
| `ADV_RECOVER_SUBMIT` | `succ` | the adversary |
| `CORRUPT_COMMITTEE` | none | the adversary |
| `CORRUPT_E` | none | the adversary |
| `CORRUPT_ORIGIN` | none | the adversary |
| `CORRUPT_GUARDIAN` | `g` | the adversary |
| `STEAL_DEVICE` | `d`, `unlocked` (boolean) | the adversary |
| `PROVIDER_TAKEOVER` | `d` | the adversary |
| `ADV_ASSERT` | `d`, `ic`, `nf` | the adversary |
| `ORIGIN_ASSERT` | `d`, `ic`, `nf` | the corrupt wallet origin, on one approval gesture of the user |
| `ADV_SIGN` | `ic` | the adversary |

Each operation has **guards**. Each guard has a refusal code. An operation **passes** when no guard fails. The model checks all guards of the operation against the state before the operation.

The oracle answers one line `{"state": S, "op": O}` on standard input with one line on standard output:

- `{"state": S', "obs": {"accepted": true}}` when the operation passes.
- `{"refused": [CODES]}` when a guard fails, with the codes in ascending order.
- `{"refused": ["outside-state-domain"]}` when `S.cfg` fails PS-002 or PS-003.
- `{"error": TEXT}` when the line does not decode.

Three phrases in section 5 have a fixed meaning:

- **Record a PRF evaluation on `d`** means: add `d` to `prf_log`.
- **Device `d` is fresh** means: `d` is not in `creds` and `d` is not in `readers`.
- **Device `d` is known** means: `d` is in `creds` or `d` is in `readers`.

## 5. Requirements

### 5.1 Configuration and creation

- **PS-001** The shard model shall keep `cfg` unchanged in every operation.
- **PS-002** If `cfg.quorum` is less than 1 or more than `cfg.n_guard`, then the shard model shall refuse the configuration with the code `bad-quorum`.
- **PS-003** If `cfg.overlap` is not empty, then the shard model shall refuse the configuration with the code `guardian-overlap`.
- **PS-004** When an account is created on device `d0`, the shard model shall set `readers`, `creds` and `prf_log` to `{d0}`, set `epoch` to 0, set `pending` to `null`, set every boolean to false and set every other set to the empty set.
- **PS-005** If a `--step` state has a `cfg` that PS-002 or PS-003 refuses, then the shard oracle shall answer `{"refused": ["outside-state-domain"]}`.

### 5.2 Devices

- **PS-006** When an `ENROLL(by, d)` operation passes, the shard model shall record a PRF evaluation on `by`, add `d` to `creds` and add `d` to `readers`.
- **PS-007** If `by` is not in `creds`, `by` is not in `readers`, or `d` is not fresh, then the shard model shall refuse `ENROLL(by, d)` with the code of each failed guard from `not-enrolled`, `no-wrap` and `already-enrolled`.
- **PS-067** While `pending` is not `null`, if `d` equals `pending.succ`, then the shard model shall refuse `ENROLL(by, d)` with the code `pending-successor`. This guard applies for both values of `pending.adv`. It is a guard of `ENROLL` in addition to the guards of PS-007, and the refusal holds the code of each failed guard of PS-007 and PS-067 in ascending order. Decision D-1 in section 9 gives the reason.
- **PS-008** When a `REMOVE_DEVICE(by, d)` operation passes, the shard model shall remove `d` from `creds` and keep `readers` unchanged.
- **PS-009** If `by` is not in `creds`, `d` is not in `creds`, or `by` equals `d`, then the shard model shall refuse `REMOVE_DEVICE(by, d)` with the code of each failed guard from `not-enrolled`, `unknown-device` and `self-removal`.

### 5.3 Unlock and contribution

- **PS-010** When an `UNLOCK(d, ic)` operation passes, the shard model shall add `[d, ic]` to `unlock_log`.
- **PS-011** When an `UNLOCK(d, ic)` operation passes, the shard model shall record a PRF evaluation on `d`.
- **PS-012** While `origin_corrupt` is true, when an `UNLOCK`, `ENROLL` or `PUBLISH_RWRAP` operation passes on an acting device that is not in `cfg.native`, the shard model shall set `adv_root` to true and add the acting device to `via_origin_leak`.
- **PS-013** If `d` is not in `creds` or `d` is not in `readers`, then the shard model shall refuse `UNLOCK(d, ic)` with the code of each failed guard from `not-enrolled` and `no-wrap`.
- **PS-014** When the Passport wallet has computed the contributions of one request, the Passport wallet shall erase the shard root and every value derived from it from memory.
- **PS-015** The Passport wallet shall keep the ECDSA slot halves of an address on the one device that ran the slot session and outside every wrap.

### 5.4 Approval and authorization

- **PS-016** When an `APPROVE(d, ic, nf)` operation passes, the shard model shall add `[d, ic, nf]` to `approved` and to `asserts`.
- **PS-017** If `d` is not in `creds`, then the shard model shall refuse `APPROVE(d, ic, nf)` with the code `not-enrolled`.
- **PS-018** When an `AUTHORIZE(d, ic, nf)` operation passes, the shard model shall add `[ic, nf]` to `authorized` and add `nf` to `used_nf`.
- **PS-019** If `[d, ic, nf]` is not in `asserts`, then the shard model shall refuse `AUTHORIZE(d, ic, nf)` with the code `no-assertion`.
- **PS-020** If `d` is not in `creds`, then the shard model shall refuse `AUTHORIZE(d, ic, nf)` with the code `not-enrolled`.
- **PS-021** If `nf` is in `used_nf`, then the shard model shall refuse `AUTHORIZE(d, ic, nf)` with the code `nf-used`.

### 5.5 Release

- **PS-022** When a `RELEASE(ic, nf)` operation passes, the shard model shall add `ic` to `sigs`.
- **PS-023** If `committee_corrupt` is true, then the shard model shall refuse `RELEASE(ic, nf)` with the code `committee-corrupt`.
- **PS-024** If `[ic, nf]` is not in `authorized`, then the shard model shall refuse `RELEASE(ic, nf)` with the code `not-authorized`.
- **PS-025** If `unlock_log` holds no pair `[d, ic]` for any `d` and `adv_root` is false, then the shard model shall refuse `RELEASE(ic, nf)` with the code `no-contribution`.

### 5.6 Derivation, wraps and the challenge

- **PS-026** The Passport wallet shall derive `x_u`, the tweak seed, the receive key `u` and `K_exit` of each address from the shard root with a domain-separated hash.
- **PS-027** The Passport wallet shall store one wrap of the shard root for each enrolled reader in the Passport account inbox.
- **PS-028** The Passport native wallet shall require one user verification for each use of the enclave reader key.
- **PS-029** The `authorize` circuit shall accept an owner source only with an ES256 assertion that has the user-verification flag and the challenge `H(charter_id, ic, nf)`.

### 5.7 Recovery

- **PS-030** When a `PUBLISH_RWRAP(by)` operation passes, the shard model shall record a PRF evaluation on `by`, set `r_wrap` to true and set `r_wrap_ever` to true.
- **PS-031** If `by` is not in `creds` or `by` is not in `readers`, then the shard model shall refuse `PUBLISH_RWRAP(by)` with the code of each failed guard from `not-enrolled` and `no-wrap`.
- **PS-032** When a `RECOVER_SUBMIT(succ)` operation passes, the shard model shall set `pending` to `{"succ": succ, "adv": false}`.
- **PS-033** If `r_wrap` is false, `pending` is not `null`, or `succ` is not fresh, then the shard model shall refuse `RECOVER_SUBMIT(succ)` with the code of each failed guard from `no-recovery-wrap`, `recovery-pending` and `already-enrolled`.
- **PS-034** When a `RECOVER_CANCEL(by)` operation passes, the shard model shall set `pending` to `null`.
- **PS-035** If `by` is not in `creds` or `pending` is `null`, then the shard model shall refuse `RECOVER_CANCEL(by)` with the code of each failed guard from `not-enrolled` and `no-pending`.
- **PS-036** When a `RECOVER_FINALISE` operation passes, the shard model shall set `creds` to `{succ}`, add `succ` to `readers`, set `r_wrap` to false and set `pending` to `null`, where `succ` is the successor of `pending`.
- **PS-037** While `origin_corrupt` is true, when a `RECOVER_FINALISE` operation passes with `pending.adv` false and a successor that is not in `cfg.native`, the shard model shall set `adv_root` to true and add the successor to `via_recovery_leak`.
- **PS-038** When a `RECOVER_FINALISE` operation passes with `pending.adv` true, the shard model shall add the successor to `adv_cred`.
- **PS-039** If `pending` is `null`, then the shard model shall refuse `RECOVER_FINALISE` with the code `no-pending`.
- **PS-040** When an `ADV_RECOVER_SUBMIT(succ)` operation passes, the shard model shall set `pending` to `{"succ": succ, "adv": true}`.
- **PS-041** If `adv_guard` has fewer than `cfg.quorum` members, `r_wrap` is false, `pending` is not `null`, or `succ` is not fresh, then the shard model shall refuse `ADV_RECOVER_SUBMIT(succ)` with the code of each failed guard from `no-quorum`, `no-recovery-wrap`, `recovery-pending` and `already-enrolled`.
- **PS-042** When an `E_REPROVISION` operation occurs, the shard model shall set `committee_corrupt` to false, add 1 to `epoch` and keep `adv_xf` unchanged.

### 5.8 The adversary

- **PS-043** When a `CORRUPT_COMMITTEE` operation occurs, the shard model shall set `committee_corrupt` to true and set `adv_xf` to true.
- **PS-044** When a `CORRUPT_E` operation occurs, the shard model shall set `e_corrupt` to true and set `adv_xf` to true.
- **PS-045** When a `CORRUPT_ORIGIN` operation occurs, the shard model shall set `origin_corrupt` to true.
- **PS-046** While `r_wrap_ever` is true and `adv_guard` has at least `cfg.quorum` members, when a `CORRUPT_GUARDIAN` or `PUBLISH_RWRAP` operation has passed and its other effects are applied, the shard model shall set `adv_root` to true and set `via_quorum` to true.
- **PS-047** If `g` is not less than `cfg.n_guard` or `g` is in `adv_guard`, then the shard model shall refuse `CORRUPT_GUARDIAN(g)` with the code of each failed guard from `unknown-guardian` and `already-corrupt`.
- **PS-048** When a `STEAL_DEVICE(d, true)` operation passes, the shard model shall add `d` to `adv_cred`.
- **PS-049** When a `STEAL_DEVICE(d, false)` operation passes, the shard model shall keep the state unchanged.
- **PS-050** If `d` is not known, then the shard model shall refuse `STEAL_DEVICE(d, unlocked)` with the code `unknown-device`.
- **PS-051** When a `PROVIDER_TAKEOVER(d)` operation passes, the shard model shall add `d` to `adv_cred`.
- **PS-052** If `d` is not in `cfg.synced` or `d` is not known, then the shard model shall refuse `PROVIDER_TAKEOVER(d)` with the code of each failed guard from `not-synced` and `unknown-device`.
- **PS-053** When an `ADV_ASSERT(d, ic, nf)` operation passes, the shard model shall add `[d, ic, nf]` to `asserts`.
- **PS-054** If `d` is not in `adv_cred`, then the shard model shall refuse `ADV_ASSERT(d, ic, nf)` with the code `no-credential`.
- **PS-065** When an `ORIGIN_ASSERT(d, ic, nf)` operation passes, the shard model shall add `[d, ic, nf]` to `hijacked` and to `asserts`.
- **PS-066** If `origin_corrupt` is false, `d` is not in `creds`, or `d` is in `cfg.native`, then the shard model shall refuse `ORIGIN_ASSERT(d, ic, nf)` with the code of each failed guard from `origin-honest`, `not-enrolled` and `native-credential`.
- **PS-055** When an `ADV_SIGN(ic)` operation passes, the shard model shall add `ic` to `sigs`.
- **PS-056** If `adv_xf` is false, or `unlock_log` holds no pair `[d, ic]` for any `d` while `adv_root` is false, then the shard model shall refuse `ADV_SIGN(ic)` with the code of each failed guard from `no-committee-half` and `no-contribution`.
- **PS-057** If an operation fails a guard, then the shard model shall keep the state unchanged.
- **PS-061** When a `CORRUPT_GUARDIAN(g)` operation passes, the shard model shall add `g` to `adv_guard`.
- **PS-062** When a `STEAL_DEVICE(d, true)` operation passes with `d` in `readers`, the shard model shall record a PRF evaluation on `d`, set `adv_root` to true and add `d` to `via_theft`.
- **PS-063** When a `PROVIDER_TAKEOVER(d)` operation passes with `d` in `readers` and `d` not in `cfg.native`, the shard model shall set `adv_root` to true and add `d` to `via_provider`.

### 5.9 Invariants

These requirements hold in every state that a sequence of operations reaches from PS-004.

- **PS-058** While the via sets are empty, the shard model shall hold in `sigs` only intents `ic` for which `unlock_log` holds a pair `[d, ic]` with `d` in `prf_log`.
- **PS-059** While `adv_xf` is false, the shard model shall hold in `sigs` only intents `ic` for which `authorized` holds a pair `[ic, nf]` and `asserts` holds a triple `[d, ic, nf]`.
- **PS-060** While `via_provider` and `via_recovery_leak` are empty and `via_quorum` is false, the shard model shall hold in `sigs` only intents `ic` for which a reader `d` in `prf_log` has `[d, ic]` in `unlock_log`, `d` in `via_origin_leak` or `d` in `via_theft`.
- **PS-064** The shard model shall hold in `authorized` at most one intent for each `nf`.

PS-058 holds for every value of `adv_xf`, `committee_corrupt` and `e_corrupt`. A fully corrupt committee can have a coalition that did not enter the user leaf. That coalition signs only the intents that the user dealt.

## 6. Hypotheses

The model treats each primitive as an abstract, sound primitive. Each hypothesis is one rule of the model.

| Name | Hypothesis | Where the model uses it |
|---|---|---|
| H-WRAP | A wrap opens only with its reader key or its recovery key. | PS-012, PS-046, PS-062, PS-063 |
| H-PRF | A reader key comes only from a PRF evaluation of its credential, and the authenticator verifies the user for it. The holder of a synced credential evaluates the PRF without user verification. | PS-011, PS-062, PS-063 |
| H-PAGE | The PRF output of a web reader reaches the wallet origin. | PS-012, PS-037 |
| H-SHAMIR | Fewer than `cfg.quorum` guardians learn nothing about the recovery secret. | PS-046 |
| H-CONTRIB | A contribution for an intent needs the shard root. | PS-025, PS-056 |
| H-SIG | A signature needs a contribution for its intent and the committee half. The committee half is an honest release or the knowledge of `x_f`. | PS-022 to PS-025, PS-055, PS-056 |
| H-ES256 | An assertion over a challenge needs the credential and its user verification. | PS-016, PS-017, PS-053, PS-054 |
| H-BLIND | The authenticator does not show the intent to the user. A corrupt origin sets the challenge of an approval on a web credential. | PS-065, PS-066 |
| H-BIND | The challenge `H(charter_id, ic, nf)` is injective. | PS-019 |
| H-MIDNIGHT | Midnight accepts one `authorize` for each `nf`. | PS-021 |
| H-DERIVE | Values derived from the shard root for different addresses are independent. | PS-026 |

## 7. What each adversary learns and does

| Adversary | Operations | Result |
|---|---|---|
| Fully corrupt committee | `CORRUPT_COMMITTEE` | It holds `x_f`. It completes a signature only for an intent in `unlock_log` (PS-056, PS-058). It needs no authorization. |
| Three members of `E` | `CORRUPT_E` | The same as the fully corrupt committee (PS-044). |
| Malicious wallet origin | `CORRUPT_ORIGIN` | It learns the shard root at the next unlock of a web reader (PS-012) or at the next honest recovery to a web reader (PS-037). It learns nothing from a native reader. It sets the challenge of each approval that the user gives on a web credential (PS-065). With an honest committee it therefore signs one intent of its choice for each approval gesture, and nothing without a gesture (PS-059). |
| Thief of a locked device | `STEAL_DEVICE(d, false)` | Nothing (PS-049). |
| Thief of an unlocked device | `STEAL_DEVICE(d, true)` | It holds the credential (PS-048). It holds the shard root when the device has a wrap, also after `REMOVE_DEVICE` (PS-008, PS-062). With both it signs through an honest committee. An honest committee refuses a removed credential (PS-020). |
| Provider of a synced passkey | `PROVIDER_TAKEOVER(d)` | It holds the credential (PS-051). It holds the shard root when `d` is a web reader (PS-063). With both it signs through an honest committee. No user verification occurs. |
| Fewer guardians than the quorum | `CORRUPT_GUARDIAN` | Nothing (PS-046). |
| A guardian quorum | `CORRUPT_GUARDIAN` | It holds the shard root when a recovery wrap exists or existed (PS-046). It can start a recovery (PS-040). A live device can cancel that recovery (PS-034). |
| The whole key | an entry in the via sets and `adv_xf` | It signs every intent (PS-055). |

## 8. Outside the model

- The model has no time. The veto window of Passport recovery is the interval between `RECOVER_SUBMIT` and `RECOVER_FINALISE`.
- The model has no ECDSA slot state. PS-015 has no state in the oracle.
- PS-014 and PS-026 to PS-029 are requirements on the wallet and the circuit. The oracle has no state for them. The hypotheses of section 6 state their effect.
- The model has one account, one committee and one guardian roster.

## 9. Decisions

### D-1: the id of a pending successor cannot be enrolled (PS-067)

**Status: lead pick, for owner confirmation.**

The problem. Before this decision, `ENROLL(by, d)` checked only that `d` is fresh (PS-007). `RECOVER_FINALISE` checked only that `pending` is not `null` (PS-039). During an adversary recovery, the user could therefore enroll the id of `pending.succ`. Then `RECOVER_FINALISE` set `creds` to that id and added it to `adv_cred` (PS-036, PS-038). The new device of the user and the successor of the adversary had one id, and the adversary held that credential. The Quint lane found this sequence (OD-1 in `formal/passport-shard/COUNTEREXAMPLES.md`).

The options:

- (a) `ENROLL` refuses `d = pending.succ` with a new code `pending-successor`.
- (b) `RECOVER_FINALISE` refuses a successor that is no longer fresh.
- (c) No change. Device ids are credential ids, so a collision cannot occur in the deployed system.

The pick is (a). The reasons:

- (a) stops the collision at the step that makes it. The user gets the refusal at enrollment and can pick another id. The pending recovery stays visible, and the user can still stop it with `RECOVER_CANCEL` (PS-034).
- (b) lets the user enroll the device first and then refuses the recovery. An honest recovery to a successor that an `ENROLL` reused would also fail late, at the end of the veto window. Under (b) the user also loses the signal that a recovery to that id is pending.
- (c) moves the property into an assumption about credential ids that the model cannot check. A Quint model or an implementation that reuses ids would merge an honest device with the successor of the adversary again.

With (a), the successor of a pending recovery stays fresh until `RECOVER_FINALISE` or `RECOVER_CANCEL`. A device id that `ENROLL` accepts is in `readers` from then on, and `readers` never loses a member. So no id that `ENROLL` accepted is ever added to `adv_cred` by `RECOVER_FINALISE`.
