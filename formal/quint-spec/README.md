# Quint check of split-line dealing from the spec (LOOP item 14)

`splitspec.qnt` is a Quint model of the OpenSpec change `add-split-line-dealing`, written from
the six capability specs (238 EARS requirements: RQ, SL, AU, CP, EN, SH; revision 7 of the model with DECISIONS 59 to 71; SH-038 of DECISIONS 72 is excluded as the input of a hash and is checked by `formal/quint/splitline_binding.qnt`) and from
`specs/refinement/` (claims C1 to C21 as INV-*, D items, questions Q-001 to Q-008). It does not
read the Lean oracle (item 13) or the older models in `formal/quint/`. The model header holds the
SHA-256 of every source file.

| File | Content |
|---|---|
| `splitspec.qnt` | model, invariants, witnesses, the instance modules |
| `splitspec_test.qnt` | scripted schedules: design runs, finding runs, one kill run per mutant |
| `REQMAP.md` | every EARS ID with its Quint artifact or a written exclusion (`tools/reqmap.py`) |
| `replay_f6.qnt` | replay of the revision 3 random F6 traces on the current model (`tools/itf2qnt.py` loads state 40 from ITF); under urgent expiry the recorded suffix is moot and a shorter suffix reaches F6 (`FINDINGS.md`, revision 5) |
| `run_gate.sh` | resumable gate; ledger in `logs/ledger.tsv` |
| `tools/flatten_itf.py` | hoists the fields of `st` to top-level ITF variables for `quint_replay.py` |
| `tools/whichinv.sh` | names the invariants that a reported seed violates |
| `traces/` | exported ITF traces, flattened, per instance and init (not committed, about 18 MB per directory; `run_gate.sh traces testtraces` rebuilds a missing directory) |
| `traces-sample/` | three random traces per kind and all scripted traces of the current model, committed for the replay; `f6_nontee_p1_rev3/` holds the two revision 3 F6 traces, which are not traces of the current model |

## What the model covers

State (`st`, spec field names): requests (RQ-002), authorizations and the one asset record
(AU-001, AU-002), one committee pool (SL-002) and one account pool with an owner root and a
guardian root (SL-003), the latest landed checkpoint (CP-001, CP-002), the leaves Midnight holds,
the leaves the nodes signed, the FINAL and VOID posts per member and epoch, the host chain's
confirmed spends, and the committee's Midnight write count. History (`g`) holds the partials
that left the nodes, the tickets each slot signed and the honest VOID posts; it is not part of
the replay contract. Fault inputs (bad share, malformed header, dealer fault, refused
authorization, release check, failed contribution) are chosen at post time and stored in
`fault`.

The committee is one honest board view with `n = 4`, `f = 1` and member 1 corrupt in every
epoch, so the counting rules of RQ-042 to RQ-045 run over real members. Quorum votes (OPENED,
ADMIT) commit as one event. Instances:

| Instance | mode | profile | mutant |
|---|---|---|---|
| `tee_p2`, `tee_p1`, `nontee_p2`, `nontee_p1` | TEE / NON_TEE | P2 / P1 | none |
| `m_*` | TEE (and `m_d058_b_nontee`) | P2 | one planted rule change each |

Init `init` is the empty system; `initArmed` starts from the state after the owner posted
request 1 and its authorization became final (formal kit practice 20). Step `step` samples every
protocol event; `stepRestart` adds the whole-committee restart once a request released or ended;
`stepAll` adds the refusal branches.

Model choices that the specs leave open, each named in the code:

- The wallet authorizes only a live request (an authorization after the end would leave the
  record PENDING; AU-005 item 1 settles it by proof, which the model does not state).
- The restart reads one checkpoint (CP-023 with one read) and may lose the board entries after
  it (`restartWith(lose)`, the lost board tail of DECISIONS 53). By RQ-076 (DECISIONS 70) the loss
  changes no request field; `lose` stays in `lastOp.arg` as the event label.
- The acknowledgement of a network-created shard (SH-030 to SH-037, DECISIONS 67) runs on one
  address record `st.addr`, apart from the spend record. `ec_ok` stands for `x_u·G = X_u` with the
  `E_c` of the record, and the holder's envelope stands for a valid `pop_u`; the cryptography is
  not modelled. The events are sampled in `step` behind `coin(4)`.
- RQ-025 and SL-016 are admission checks (DECISIONS 68): an honest node posts AUTH_REFUSED, or
  SLOT_TAKEN for a slot under another precedence, only while the authorization is in force. SL-013
  (an index below the window) keeps its post without that clause.
- Expiry (RQ-046, lead ruling A) is part of every event that raises the board height (`tick`,
  `order`, `checkpoint`): no event lands on a live request whose `exp` the board height has passed.
- The selection rule of RQ-027 is a nondeterministic pick recorded in `anchor[1]`.
- `coin(k)` branches and the window-biased slot pick of `post` only bias the sampler.

## Invariants, requirement IDs and claims

| Invariant | Requirements | Claim |
|---|---|---|
| `inv_RQ064_RQ065_RQ066_domains` | RQ-002, RQ-064, RQ-065, RQ-066 | |
| `inv_RQ065_liveReasonNone` | RQ-065 | |
| `inv_RQ067_grid` | RQ-067 | |
| `inv_RQ029_selection` | RQ-029 | |
| `inv_RQ008_C8_sealedUntilOrder` | RQ-008, RQ-009 | C8 (INV-008) |
| `inv_RQ057_C6_C20_noReleaseBeforeAdmission` | RQ-057, RQ-024, AU-010 | C6, C20 (INV-006, INV-020) |
| `inv_C20_stalledReleasedNothing` | RQ-057, RQ-045, RQ-047, RQ-072 (D-061) | C20 (INV-020: "a stalled request releases nothing", read on the tombstone reason) |
| `inv_RQ069_C11_sentNeverVoid` | RQ-069, RQ-051 (D-059) | C11 |
| `inv_RQ045_RQ072_C13_C20_reasonHasHonestPost` | RQ-045, RQ-071, RQ-072 (D-061) | C13, C20 |
| `inv_EN023_expCBelowExp` | EN-023, RQ-006 (D-062) | |
| `inv_SL005_SL010_lapsedPrecBurned` | SL-005, SL-010 (D-063) | C13 |
| `inv_RQ073_C20_noStalledAfterRelease` | RQ-073, RQ-074, RQ-045, RQ-072 (D-064) | C20 |
| `inv_RQ058_C9_oneVariantPerGeneration` | RQ-058, RQ-030 | C9 (INV-009) |
| `inv_RQ059_C7_noReleaseAfterRevoke` | RQ-059, RQ-032 | C7 (INV-007) |
| `inv_SL027_C12_oneTicketPerSlot` | SL-021, SL-027, SL-029, CP-038 | C12, C16 (INV-012, INV-016) |
| `inv_AU024_C11_oneSpendPerRecordState` | AU-024, AU-008, RQ-054, RQ-068 | C11 (INV-011) |
| `inv_AU008_C11_oneAuthPerNf` | AU-008 | C11 |
| `inv_RQ054_C11_heldLeafNeverReplaced` | RQ-054 (D-058) | C11 |
| `inv_AU025_C11_releasedNeverUnspent` | AU-025, AU-029, RQ-052 (D-053, D-060) | C11 |
| `inv_RQ052_RQ068_C11_restartEndNeverVoid` | RQ-052, RQ-068 (D-053, D-058) | C11 |
| `inv_RQ068_C11_reEnded` | RQ-068 (D-058) | C11 |
| `inv_RQ049_RQ050_RQ051_outcome` | RQ-049, RQ-050, RQ-051 | |
| `inv_RQ053_leafSigned` | RQ-053 | |
| `inv_SL010_committeeBurnAtPrecEnd` | SL-010 (D-054 item 1) | |
| `inv_SL011_SL028_ecdsaBurnOnlyByReserver` | SL-011, SL-028 (D-054 item 4) | C13 |
| `inv_SL007_C13_ecdsaPrecOnlyInForce` | SL-006, SL-007 (D-054 item 4) | C13 (INV-013) |
| `inv_RQ063_C13_ecdsaTakenOnlyByInForce` | RQ-063 safety half, SL-016 | C13 |
| `inv_RQ042_C13_voidNeedsHonestPost` | RQ-042, RQ-045 (D-056) | C13 |
| `inv_RQ044_finalNeedsConfirmation` | RQ-040, RQ-044 (D-055) | |
| `inv_CP005_batchedWrites` | CP-005, CP-006 (D-052, owner rule) | |
| `inv_CP013_AU020_settledByRoot` | CP-013, AU-020 (D-052) | C11 |
| `inv_CP007_CP008_CP009_landedChain` | CP-007, CP-008, CP-009 (D-052 D4) | C16 |
| `inv_CP014_pendingFields` | CP-002, CP-014 | |
| `inv_CP020_C16_burnCovers` | CP-020, CP-038 | C16 (INV-016) |
| `inv_CP039_C16_boundedLoss` | CP-039 | C16 |
| `inv_SL017_precForward` | SL-017 | |
| `inv_AU006_sources` | AU-006 | |
| `inv_RQ046_urgentExpiry` | RQ-046 (lead ruling A) | |
| `inv_RQ076_C11_releaseMonotone` | RQ-076, RQ-037 (D-070) | C11 |
| `inv_RQ025_SL016_admissionChecksInForce` | RQ-025, SL-016, RQ-023 (D-068) | C13 |
| `inv_CP040_pendingMinForward` | CP-040 (D-069) | C16 |
| `inv_CP014_CP040_honestFloorKept` | CP-014, CP-040 (D-071, finding F7) | C13 |
| `inv_SH033_SH037_ackedNeedsCertificate` | SH-033, SH-034, SH-037 (D-067) | C1 |
| `inv_SH031_SH036_C1_ackedOnlyRightEc` | SH-030, SH-031, SH-032, SH-036 (D-067) | C1 |
| `inv_SH035_payOnlyAcked` | SH-035 (D-067) | |

`inv` is the conjunction, and since revision 3 `inv_gate` is `inv`. Revision 2 left out
`inv_AU024_C11_oneSpendPerRecordState`, `inv_AU025_C11_releasedNeverUnspent` (findings F1, F5) and
`inv_C20_stalledReleasedNothing` (finding F2); DECISIONS 59 to 61 fix those findings, so they are in
the gate. The gate also runs them on their own (`tier_c11`, `tier_c20`). The F3 and F4 witnesses
(`w_exp_c_not_below_exp`, `w_open_after_lapse`) are now the invariants `inv_EN023_expCBelowExp`
and `inv_SL005_SL010_lapsedPrecBurned`. F6 (`FINDINGS.md`), found in the revision 3 run, is fixed
by DECISIONS 64 (revision 4, owner ruling): `inv_RQ073_C20_noStalledAfterRelease` replaces the
witness `w_stalled_after_release` in the gate, and `f6StalledAfterAdmitTest` is a regression test.
F7, found in the revision 6 run, is fixed by DECISIONS 71 (revision 7, owner ruling): CP-014 lists
only the slots at or above the landed `pending_min`, `inv_CP014_CP040_honestFloorKept` is in the
gate, and `f7SpamPrecedenceLandsTest` is a regression test. The second half of C20 (a reissue reuses no slot or
pair) has no invariant: the model's reissue takes fresh slots by construction.

Claims with no model artifact: C1, C2, C3, C4, C5, C10, C17, C18, C19 and C21 are cryptographic
or information-flow claims (rogue key, sealed halves, blindness, confinement). The model has no
key or ciphertext state, so an invariant for them would be vacuous. C13 liveness (RQ-063) is
temporal and `quint run` does not check it; its safety half is above. C14 and C15 are out of
scope (baseline exclusions).

## Mutants

"The one burn rule" is read as SL-010 (a committee slot burns when its precedence holder ends
or lapses, used or not) together with SL-011 and SL-028 (an ECDSA slot burns only when the
request in `reserver` ends). Both directions are planted.

| Mutant (`MUT`) | Rule changed | Killed by | Schedule |
|---|---|---|---|
| `ecdsa_prec_at_open` | SL-006/SL-007: ECDSA precedence at header open, committee-style taken rule and burn | `inv_SL007_C13_ecdsaPrecOnlyInForce`, `inv_RQ063_C13_ecdsaTakenOnlyByInForce` | `killEcdsaPrecAtOpenTest` |
| `committee_burn_reserved_only` | SL-010: a committee slot burns only if reserved | `inv_SL010_committeeBurnAtPrecEnd` (end half; design twin `sl010EndBurnsTest`; the lapse half is the design test `sl010LapseBurnsTest`, which the invariant does not state) | `killCommitteeBurnReservedOnlyTest` |
| `ecdsa_burn_by_namer` | SL-011/SL-028: an ECDSA slot burns at the end of any namer | `inv_SL011_SL028_ecdsaBurnOnlyByReserver` | `killEcdsaBurnByNamerTest` |
| `d058_b` | RQ-068 does not fire when a leaf exists (DECISIONS 58 option (b)) | `inv_RQ068_C11_reEnded` (TEE); with `inv_AU024_C11_oneSpendPerRecordState` on NON_TEE | `killD058bTeeTest`, `killD058bTest` |
| `replace_held` | RQ-054 carve-out and the D-058 skip dropped: the restart re-ends a request whose leaf Midnight holds and replaces the leaf | `inv_RQ054_C11_heldLeafNeverReplaced` | `killReplaceHeldTest` |
| `restart_void_unspent` | RQ-052: a restart end with an unspent pin and no visible release settles VOID (rule before DECISIONS 53) | `inv_RQ052_RQ068_C11_restartEndNeverVoid` (an admitted request that released nothing; with RQ-076 a released request keeps `any_release`, `killRestartVoidUnspentReleasedSurvivesTest`) | `killRestartVoidUnspentTest` |
| `settle_per_request` | CP-005: one committee Midnight write per ended request | `inv_CP005_batchedWrites` | `killSettlePerRequestTest` |
| `root_omit` | CP-013: the root leaves out the requests that ended at its own board height | `inv_CP013_AU020_settledByRoot` | `killRootOmitTest` |
| `no_jump` | CP-009: no restart jump of `h` and no contract check | `inv_CP007_CP008_CP009_landedChain` | `killNoJumpTest` |
| `cross_epoch` | RQ-042: VOID posts of two epochs added | `inv_RQ042_C13_voidNeedsHonestPost` | `killCrossEpochTest` |
| `ignore_revoke` | RQ-030/RQ-059: release after revocation | `inv_RQ059_C7_noReleaseAfterRevoke` | `killIgnoreRevokeTest` |
| `any_variant` | RQ-058: release a variant other than the anchor | `inv_RQ058_C9_oneVariantPerGeneration`, `inv_SL027_C12_oneTicketPerSlot` | `killAnyVariantTest` |
| `send_before_record` (NON_TEE P2) | RQ-069: send before the RELEASE commits (revision 2, F1) | `inv_RQ069_C11_sentNeverVoid`, then `inv_AU024_C11_oneSpendPerRecordState` | `killSendBeforeRecordTest` |
| `locked_void_unlocks` (TEE P1) | AU-029: a VOID settlement on a LOCKED record returns it to UNSPENT (revision 2, F5) | `inv_AU025_C11_releasedNeverUnspent`, then `inv_AU024_C11_oneSpendPerRecordState` | `killLockedVoidUnlocksTest` |
| `completing_reason` (TEE P1) | RQ-045: the reason of the completing post (revision 2, F2) | `inv_RQ045_RQ072_C13_C20_reasonHasHonestPost` | `killCompletingReasonTest` |
| `exp_c_unchecked` | EN-023 dropped (revision 2, F3) | `inv_EN023_expCBelowExp` | `killExpCUncheckedTest` |
| `lapse_once` | SL-005 as one event on tick (revision 2, F4) | `inv_SL005_SL010_lapsedPrecBurned` | `killLapseOnceTest` |
| `stalled_after_release` (TEE P1; `_nontee`: NON_TEE P1) | RQ-074: STALLED posts stay reason posts after a RELEASE (revision 3, F6) | `inv_RQ073_C20_noStalledAfterRelease`, `inv_C20_stalledReleasedNothing` | `killStalledAfterReleaseTest`, `killStalledAfterReleaseNonteeTest` (the replayed F6 schedule of `replayF6Seed14MutantTest`) |
| `late_expiry` | RQ-046: expiry as a separate `expire` event that may come late (item 14, lead ruling A) | `inv_RQ046_urgentExpiry` | `killLateExpiryTest` |
| `restart_clears_release` | RQ-076: a restart that loses the board tail clears `any_release` and `released` (item 14, lead ruling D) | `inv_RQ076_C11_releaseMonotone` | `killRestartClearsReleaseTest` |
| `auth_refused_before_force` | RQ-025: AUTH_REFUSED before the authorization is in force (rule before DECISIONS 68) | `inv_RQ025_SL016_admissionChecksInForce` | `killAuthRefusedBeforeForceTest` |
| `taken_before_force` | SL-016: SLOT_TAKEN before the authorization is in force (rule before DECISIONS 68) | `inv_RQ025_SL016_admissionChecksInForce` | `killTakenBeforeForceTest` |
| `pending_min_unchecked` | CP-040 dropped | none since DECISIONS 71: no honest checkpoint lowers the floor; the schedule checks `cpCode` on the CP-040 scenario (design twin `cp040OldIndexRefusedTest`) | `killPendingMinUncheckedTest` |
| `pending_unwindowed` | CP-014: the list holds every slot a live request holds, also below the landed `pending_min` (revision 6, F7) | `inv_CP014_CP040_honestFloorKept` | `killPendingUnwindowedTest`, `killPendingUnwindowedBlocked1Test` |
| `ack_without_pop` | SH-031/SH-032: honest members sign ACK_OK for an envelope without a valid `pop_u` | `inv_SH031_SH036_C1_ackedOnlyRightEc` | `killAckWithoutPopTest` |
| `ack_cert_short` | SH-033: `acknowledge` lands with `f` ACK_OK signatures | `inv_SH031_SH036_C1_ackedOnlyRightEc`, `inv_SH033_SH037_ackedNeedsCertificate` | `killAckCertShortTest` |
| `pay_before_ack` | SH-035: the payer pays before `acked` | `inv_SH035_payOnlyAcked` | `killPayBeforeAckTest` |

Each schedule passes on its mutant: the named invariant is false at the last step (for
`pending_min_unchecked`, the mutated contract check accepts the lowered floor). The design
tests of `test_tee_p2` and `test_nontee_p2` run the same fragments (`releasedOne`, restart,
checkpoint) with `inv` true. Random runs of the mutants are in `tier_mutants`; the results are
in the ledger.

## Action-to-event map (replay contract)

`lastOp = { kind, eid, arg, code }` names the event of each step. The replay through the oracle
sends `lastOp` as `op`. `arg` carries the recorded pick.

| `lastOp.kind` | Spec event | Requirements | `arg` |
|---|---|---|---|
| `init`, `init_armed` | initial state | RQ-002, AU-001, CP-001 | |
| `post` | envelope passes the public checks | RQ-003, RQ-066, RQ-067, EN-011 | |
| `authorize` | Midnight accepts `authorize` | AU-004 to AU-009 | pin |
| `finalize_auth` | the `authorize` transaction is final | AU-010 | Midnight height |
| `revoke` | hold authority posts `revoke(auth)` | AU-018 | |
| `order` | the board orders the envelope under a QC | RQ-006, RQ-009, RQ-010 | order position |
| `complain` | a verified share complaint is ordered | RQ-011, RQ-012 | 1 early, 2 late |
| `open` | `t` header partials open the header | RQ-013, RQ-014, SL-004, SL-007 | 1 open, 0 malformed |
| `ecdsa_prec` | the authorization of a request with an open header is in force | SL-006 | |
| `opened_vote` | `q` OPENED votes commit | RQ-016, RQ-017, RQ-021, SL-008 | |
| `frame` | a contribution frame is ordered: attached (COLLECTING) or held (POSTED, or ORDERED at a height at most `exp_c`) | RQ-018, RQ-020, RQ-021 | board height |
| `frame_complaint` | a complaint against a frame is ordered | RQ-022 | |
| `admit` | the first `q` ADMIT votes commit | RQ-023, RQ-026, RQ-027, SL-008, SL-009 | anchor[1] |
| `anchor2` | an OBS set for generation 2 commits | RQ-028 | anchor[2] |
| `send_release` | release partials leave the nodes | RQ-030 to RQ-035, RQ-037 (TEE), RQ-069 (NON_TEE: after `record_release`) | 10·g + j |
| `record_release` | a RELEASE commits in a board vote, before the send | RQ-037, RQ-069 (NON_TEE) | g |
| `host_confirm` | the host chain confirms a variant | RQ-040 (input) | pin |
| `post_final` | a member posts FINAL | RQ-040, RQ-042, RQ-044, RQ-049, RQ-053 | 10·epoch + member |
| `post_void` | a member posts VOID | RQ-042, RQ-045, RQ-050 to RQ-053, and every VOID cause | 10·epoch + member |
| `tick` | a board block; expiry of every live request whose `exp` the new height passes, then the lapse (both also in `order` and `checkpoint`) | RQ-046, RQ-050, RQ-051, SL-005, SL-010 | board height |
| `tick_midnight` | a Midnight block | RQ-033 (input) | Midnight height |
| `checkpoint` | a checkpoint lands | CP-003, CP-005, CP-011, CP-013, CP-014, AU-020, AU-023, CP-027 | seq |
| `restart` | nodes classify a whole-committee restart | CP-018, CP-020 to CP-022, RQ-048, RQ-068, RQ-054, RQ-076 | 1 if the board tail is lost |
| `rotate` | ROTATE registers epoch 2 | RQ-042, CP-006 | 2 |
| `reissue` | a reissue's `authorize` carries a VOID leaf | AU-021, RQ-060 | new eid |
| `register_addr` | a payer registers the record of an address with a network-created shard | SH-034 | 1 if `E_c` is right |
| `holder_ack` | the holder wallet sends the ACK envelope with `pop_u` | SH-030, SH-036 | |
| `creator_ack` | the creator sends an ACK envelope without a valid `pop_u` | SH-032 (input) | |
| `ack_ok` | a member signs ACK_OK | SH-031, SH-032 | member |
| `acknowledge` | the `acknowledge` call lands | SH-033, SH-037 | number of ACK_OK signatures |
| `pay_addr` | a payer pays to the address | SH-035 | |
| refusals (`code` set) | a refused event, state unchanged | RQ-004, RQ-005, RQ-007, EN-023, RQ-019, RQ-020, RQ-075, RQ-024, RQ-061, SL-014, AU-008, AU-019, AU-022, RQ-043, CP-007 to CP-009, CP-040 (`pending_min_lowered`), SH-032 (`ack_refused`, `eid` holds the member), SH-033 (`no_ack_certificate`) | |

Revision 5 removed the `expire` kind: expiry is part of `tick`, `order` and `checkpoint`. The kind
occurs only in traces of the mutant `late_expiry`.

## Replay through the oracle

The traces in `traces/<instance>_<init>/` are flattened: each field of `st` is a top-level
variable with the spec name, `g_*` are the history fields, `lastOp` is the operation. Refusal
traces are separate (`traces/<instance>_refusals/`), because `quint_replay.py` counts an oracle
refusal as a disagreement. These traces and the committed `traces-sample/` feed the replay through
the Lean oracle of item 13 (`formal/lean-split/replay/`, on another branch). A direct run:

```sh
python3 -I ~/Projects/software-factory/plugins/formal/scripts/quint_replay.py \
  --oracle <oracle> --traces traces/tee_p2_initArmed --op-var lastOp \
  --compare requests,auths,record,cslots,eslots,cp,held,signed_leaf,committee_txs,host_spent \
  --drop g_sent --drop g_slot_tickets ...   # every g_* field
```

The oracle's state and op encodings are not known to this model; a field rename (`--map`) or a
small adapter may be needed. The constants of each instance (`MODE`, `PROFILE`, `n = 4`,
`f = 1`, `B = 2`, `DELTA_C = 4`, `DELTA_HOLD = 1`) go in with `--const` or the adapter.

## Commands and results

Revision 7 (DECISIONS 71: the CP-014 floor that fixes F7) reran the tiers that the change
touches on 2026-11-16 in the systemd user units `item36-quint-gate` (typecheck, tests, replay,
design, c11, mutants, traces, testtraces) and `item36-quint-gate-10k` (mutants10k), with the unit
log in `~/.cache/loop-verify/item36/`. The c20 tier did not rerun: CP-014 does not touch the
tombstone reason. Every quint call went through `heavy-run --mem 8G`. `logs/ledger.tsv` is the
record. `logs/ledger-rev2.tsv` to `logs/ledger-rev6.tsv` keep the runs that found F1 to F7 and
the revision 4 to 6 gates (revision 6, 2026-11-15, unit `quint-spec-14c`, ran every tier). Quint
0.32.0 with the rust evaluator v0.6.0. `quint run` is bounded random simulation, not model
checking.

| Tier | Command (per check) | Result |
|---|---|---|
| typecheck | `quint typecheck splitspec.qnt`, `splitspec_test.qnt` | both ok |
| tests | `quint test splitspec_test.qnt --main M --match 'Test$'` for 32 modules | all pass (test_tee_p2 49/49, test_nontee_p2 4/4, test_tee_p1 5/5, test_m_restart_void_unspent 2/2, test_m_pending_unwindowed 2/2, 27 other kill modules 1/1) |
| replay | `quint test replay_f6.qnt --main {replay_f6_base,replay_f6_stalled_after_release} --match 'Test$'` | 5/5 and 1/1 |
| design | `quint run --main INST --init {init,initArmed} --step stepRestart --invariant inv_gate --max-samples 10000 --max-steps 80 --seed {0x14,0x2a3} --witnesses w_*` | 16 of 16 `[ok] No violation found` |
| c11 | `quint run --main INST --init initArmed --step stepRestart --invariants inv_AU024_C11_oneSpendPerRecordState inv_AU025_C11_releasedNeverUnspent --max-samples 10000 --seed 0x14` | `[ok]` on all four instances |
| c20 | `quint run --main {tee_p1,nontee_p2} --init initArmed --step stepRestart --invariant inv_C20_stalledReleasedNothing --max-samples 10000 --seed 0x2a3` | `[ok]` on both (revision 6; not rerun) |
| mutants | `quint run --main m_* --init initArmed --step stepRestart --invariant INV --max-samples 2000 --seed 0x14` | 23 of 29 killed; `m_replace_held`, `m_locked_void_unlocks`, `m_stalled_after_release`, `m_stalled_after_release_nontee`, `m_pending_min_unchecked` and `m_pending_unwindowed` survive 2000 samples |
| mutants10k | the same with `--max-samples 10000 --seed {0x14,0x2a3}` for the two F6 mutants and `m_pending_unwindowed` | all three survive on both seeds |
| traces | `quint run ... --max-samples 300 --n-traces 50 --max-steps 60 --seed 0x1f0 --out-itf`; refusals with `stepAll`, seed 0x1f1 | 50 traces per instance and init, 20 refusal traces per instance |
| testtraces | `quint test --main {test_tee_p2,test_nontee_p2,test_tee_p1} --match 'Test$' --out-itf` | 58 scripted traces (49, 4, 5), the finding schedules among them (`traces-sample/tests_*`) |

The first unit's last lines: `== gate done 2026-11-16T06:01:31-07:00` and `ledger lines with FAIL
or VIOLATION: 0`; the second ends at `2026-11-16T06:13:11-07:00` with 0 as well. The ledger has
56 `ok` (one from the item 36b kill module), 23 `KILLED`, 12 `survived-random`, 15 trace counts and no `FAIL`.

Every mutant that survives its random runs is killed by its scripted module, which the `tests` tier
runs: `m_replace_held` by `killReplaceHeldTest`, `m_locked_void_unlocks` by
`killLockedVoidUnlocksTest`, `m_stalled_after_release` by `killStalledAfterReleaseTest`,
`m_stalled_after_release_nontee` by `killStalledAfterReleaseNonteeTest` (the replayed F6
schedule of `replayF6Seed14MutantTest`, `replay:replay_f6_stalled_after_release`), `m_pending_min_unchecked` by
`killPendingMinUncheckedTest`, and `m_pending_unwindowed` by `killPendingUnwindowedTest` and
`killPendingUnwindowedBlocked1Test`. Since DECISIONS 71 no honest checkpoint lowers the floor, so
no random run can kill `m_pending_min_unchecked`; its schedule checks the contract rule on
hand-built checkpoints. The F7 precondition (`w_prec_below_floor`) is reached in 8 of 16 design
runs at 0.01% at most, so a random kill of `m_pending_unwindowed` is not expected at 2000 samples; it also survives
10000 samples from `initArmed` on both seeds (`tier_mutants10k`).
The other mutants keep their revision 6 results.

With 10 threads the two start seeds often report the same kill seed. Replay a reported seed with
`--max-samples 1 --n-threads 1 --seed S`; `tools/whichinv.sh` names the invariant. Quint prints
`Use --seed=...` and the states of one trace after an `[ok]` run too, so read the verdict line.

The first proposal for F6 closed admission at `exp_c`. It was run and then withdrawn by the owner's
ruling before it was committed; its ledger is in `logs/superseded-late-admit/` (not committed).

Witness rates over the 16 design runs (percent of 10000 traces; min, max, runs):

| Witness | min % | max % | runs |
|---|---|---|---|
| `w_anchor2` | 0.03 | 3.10 | 16 |
| `w_auth_refused` | 0.00 | 0.24 | 16 |
| `w_collecting_admitted` | 0.05 | 1.59 | 16 |
| `w_cp_pending_min_lowered` | 0.00 | 0.00 | 16 |
| `w_creator_ack` | 74.18 | 76.15 | 16 |
| `w_ecdsa_prec` | 0.64 | 15.59 | 16 |
| `w_ecdsa_reserved` | 0.17 | 8.35 | 16 |
| `w_final` | 0.00 | 0.34 | 16 |
| `w_host_spend` | 0.03 | 8.98 | 16 |
| `w_lapsed` | 82.39 | 90.75 | 16 |
| `w_locked` | 2.80 | 8.54 | 16 |
| `w_locked_after_void` | 0.04 | 0.16 | 16 |
| `w_mixed` | 39.43 | 55.76 | 16 |
| `w_nontee_released_unconfirmed` | 0.00 | 2.24 | 16 |
| `w_open_lapsed` | 61.36 | 74.97 | 16 |
| `w_paid_acked` | 23.85 | 25.82 | 16 |
| `w_prec_below_floor` | 0.00 | 0.01 | 16 |
| `w_reissue` | 12.06 | 28.58 | 16 |
| `w_released_outcome` | 25.50 | 47.92 | 16 |
| `w_restart_cp_landed` | 33.20 | 44.76 | 16 |
| `w_restart_live_hit` | 0.51 | 1.16 | 16 |
| `w_restart_reend` | 13.88 | 26.41 | 16 |
| `w_revoked_void` | 0.00 | 14.97 | 16 |
| `w_rotate_post` | 99.34 | 99.75 | 16 |
| `w_sent` | 0.04 | 8.98 | 16 |
| `w_settled_by_root` | 17.32 | 36.00 | 16 |
| `w_stalled` | 3.89 | 5.65 | 16 |
| `w_two_coins` | 0.00 | 0.67 | 16 |
| `w_void_slot_taken` | 0.53 | 1.02 | 16 |

Every witness except `w_cp_pending_min_lowered` is reached in some run. That one is now the
absence of the F7 block: no design run reaches a state whose honest checkpoint CP-040 would
refuse, while the F7 precondition `w_prec_below_floor` is reached in 8 of 16 runs. A minimum of
0.00 means that some runs did not reach it:
`w_final` and `w_two_coins` on the P2 runs from `init` (the empty system; `w_two_coins` also on
`nontee_p1` from `init` at seed 0x2a3), `w_revoked_void` on P1, where AU-019 rules out revocation,
`w_nontee_released_unconfirmed` on TEE, where it cannot occur, `w_auth_refused` on 7 of the 8
`initArmed` runs, where the armed authorization leaves few unauthorized requests, and
`w_prec_below_floor`, reached in 8 of 16 runs. The scripted schedules `jny001FinalTest` (FINAL,
second coin), `rq025AuthRefusedTest` (AUTH_REFUSED in force) and `f7SpamPrecedenceLandsTest`
(precedence below the floor, and the checkpoint lands) reach those paths.

Coverage of the random replay traces, counted on the revision 6 traces, is thin on the release path: in the 400 protocol traces,
`send_release` occurs 28 times, `record_release` 21 times (NON_TEE only) and `reissue` not at all.
The acknowledgement path is dense: `register_addr` 400, `holder_ack` 301, `ack_ok` 1301,
`acknowledge` 301, `pay_addr` 300 and `creator_ack` 99 steps. The 80 refusal traces hold
`ack_refused` 283 times and `no_ack_certificate` 521 times; no trace holds `pending_min_lowered`.
The scripted traces (`testtraces`) cover release, FINAL, restart, reissue, the acknowledgement
schedules and the finding schedules. A test that ends in a blocked step (`*Blocked*Test`) is
exported without the blocked event. No trace of the design instances holds the `expire` kind.

Rare witnesses: `w_final` is at most 0.34%, so the FINAL path rests mostly on `jny001FinalTest`.
`w_locked_after_void` (DECISIONS 60) is 0.04% to 0.16%, with `f5LockedVoidUnlocksTest` as its
scripted case. `w_nontee_released_unconfirmed` (DECISIONS 59) is reached on NON_TEE only;
`f1NonTeeExpiryDoubleSpendTest` is its scripted case. The revision 3 witness
`w_stalled_after_release` is now the gate invariant `inv_RQ073_C20_noStalledAfterRelease`.
