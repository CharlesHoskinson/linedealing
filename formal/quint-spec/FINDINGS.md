# Findings of the spec-only Quint model (item 14)

Each finding cites the spec sentences it rests on and the scripted schedule in `splitspec_test.qnt` that reached it in revision 2 of the specs. Random-run seeds use `--max-samples 1 --n-threads 1` to replay.

Status, revision 4 (DECISIONS 59 to 64): F1 to F6 are fixed in the specs. F1 to F5 come from the revision 2 run and F6 from the revision 3 run. Each schedule is now a regression test that does not reach the bad state, each fix has a mutant that restores the old rule and is caught, and the invariants of F1, F2, F5 and F6 and the former witnesses of F3 and F4 are in `inv_gate`.

Revision 5 (lead rulings A to E on the item 14 replay, DECISIONS 70): expiry is urgent. The schedules below that used a late `expire` step are rebuilt or marked moot in the section "Revision 5".

Revision 7 (DECISIONS 71, owner ruling): F7 from the revision 6 run is fixed in the specs. CP-014 lists only the committee slots at or above the `pending_min` of the previous landed checkpoint.

| Finding | Fix | Regression tests | Mutant | Gate invariant |
|---|---|---|---|---|
| F1 | DECISIONS 59, RQ-069 | `f1NonTeeExpiryDoubleSpendBlocked1Test`, `f1NonTeeExpiryDoubleSpendTest`, `f1NonTeeExpiryDoubleSpendBlocked2Test` | `m_send_before_record` | `inv_RQ069_C11_sentNeverVoid`, `inv_AU024_C11_oneSpendPerRecordState` |
| F5 | DECISIONS 60, AU-029, AU-023, AU-025 | `f5LockedVoidUnlocksTest`, `f5LockedVoidUnlocksBlocked2Test` | `m_locked_void_unlocks` | `inv_AU025_C11_releasedNeverUnspent`, `inv_AU024_C11_oneSpendPerRecordState` |
| F2 | DECISIONS 61, RQ-045, RQ-071, RQ-072 | `f2CorruptReasonTest` (reason MIXED) | `m_completing_reason` | `inv_RQ045_RQ072_C13_C20_reasonHasHonestPost`, `inv_C20_stalledReleasedNothing` |
| F3 | DECISIONS 62, EN-023 | `en023ExpCTest`, `en023ExpCRefusedTest` | `m_exp_c_unchecked` | `inv_EN023_expCBelowExp` |
| F4 | DECISIONS 63, SL-005 | `sl005LateOpenLapsedTest` | `m_lapse_once` | `inv_SL005_SL010_lapsedPrecBurned` |
| F6 | DECISIONS 64 (owner ruling), RQ-073, RQ-074, RQ-045, RQ-072 | `f6StalledAfterAdmitTest` (reason MIXED, outcome RELEASED), `f6StalledNoReleaseTest`, `replay_f6.qnt` | `m_stalled_after_release`, `m_stalled_after_release_nontee` | `inv_RQ073_C20_noStalledAfterRelease`, `inv_C20_stalledReleasedNothing` |
| F7 | DECISIONS 71 (owner ruling), CP-014 | `f7SpamPrecedenceLandsTest` (the checkpoint lands with `pending_min = 2`, request 2 ends VOID SLOT_TAKEN), `cp040LapseUnblocksTest` | `m_pending_unwindowed` (`killPendingUnwindowedTest`, `killPendingUnwindowedBlocked1Test`) | `inv_CP014_CP040_honestFloorKept`, `inv_CP040_pendingMinForward` |

## F1 (C11, NON_TEE): an expiry after a partial was sent settles VOID and allows a second spend

Spec sentences:
- RQ-030: "the committee node SHALL send once its PRF partial … and its signature partial for each slot … to the combiners of RQ-036."
- RQ-037: "When a RELEASE of generation g … commits in a board vote … SHALL set released[g] = j and any_release = true."
- RQ-046: "When the board height passes exp … SHALL set phase = EXPIRED."
- RQ-050: "When a request with any_release = false and restart_end = false reaches phase VOID or EXPIRED … SHALL set outcome = VOID."
- RQ-005 refuses the later RELEASE.
- AU-023 (VOID): "nf' = N(nsk, auth, VOID) with rstate = UNSPENT".
- AU-024: "SHALL keep at most one FINAL settlement for the successors of one record state."

Schedule `test_nontee_p2::f1NonTeeExpiryDoubleSpendTest`:
1. post(1), authorize(1) on pin 1, finalize_auth, tick_midnight, order, open, admit(anchor 1).
2. send_release(1, g1, j1): the partials leave the nodes; no RELEASE vote commits.
3. tick ×8, expire(1): outcome VOID.
4. checkpoint: auth 1 settles VOID; the record becomes UNSPENT with a fresh nf.
5. post(2), authorize(2) on pin 2, …, send_release(2).
6. host_confirm(2) and host_confirm(1) both succeed: `inv_AU024` is false.

A restart before the checkpoint re-ends request 1 as RELEASED under RQ-068 and prevents it (`rq068NonTeeRestartTest`). TEE mode sends and records the release in one step, so F1 does not occur there. 10000 random samples on nontee_p2 did not reach F1.

## F5 (C11): a VOID settlement on a LOCKED record returns it to UNSPENT

Spec sentences:
- AU-023 (RELEASED): "the same record with rstate = LOCKED to the pinned input or nonce".
- AU-023 (VOID): "the same record under the nullifier nf' … with rstate = UNSPENT".
- AU-025: "SHALL never return a record whose authorization settled RELEASED to rstate = UNSPENT with a fresh nullifier."

Schedule `test_tee_p1::f5LockedVoidUnlocksTest`:
1. Request 1 releases, expires and is checkpointed: settled RELEASED, record LOCKED to pin 1.
2. Re-post 3 is authorized on pin 1, expires without a release and is checkpointed: settled VOID; the record becomes UNSPENT with a fresh nf and the lock is gone.
3. authorize(2) takes pin 2: `inv_AU025` is false.
4. Request 2 releases; host_confirm(2) and host_confirm(1) both succeed: `inv_AU024` is false.

AU-025 as written does not forbid this, because the record that returns to UNSPENT is the re-post's successor. Random runs break AU-025 on tee_p2 (seed 0x4c7363), tee_p1 (0x1dbed) and nontee_p1 (0xf180ad); only the schedule shows the two confirmed spends.

## F2 (RQ-045, Q-002, C20): a corrupt post chooses the VOID reason

Spec sentences:
- RQ-045: "… SHALL set phase = VOID and reason to the reason of the post that completes the count."
- The note under RQ-045: DESIGN does not say which reason applies when the posts differ (Q-002, provisional).

Schedule `test_tee_p1::f2CorruptReasonTest` (P1, member 1 corrupt): a malformed header is ordered and opened; honest member 2 posts VOID with MALFORMED; corrupt member 1 completes the count with REVOKED. The tombstone says REVOKED in P1, where AU-019 rules out revocation.

Random runs (tier_c20) find a worse case: member 1 completes the count with STALLED on a request that released and was host-confirmed (outcome FINAL), breaking C20 ("a stalled request releases nothing"). Seeds: tee_p1 0x4887c5, nontee_p2 0x476170. Two rules read the reason: the C13 half of RQ-063 and the stalled gate of AU-021. `inv_RQ042_C13_voidNeedsHonestPost` holds.

## F3 (RQ-001, EN-021, RQ-047): nothing keeps exp_c below exp

- RQ-001 lists Δ_c as a committee parameter; EN-021: "The initiator wallet SHALL choose Δ_c so that exp_c lies below exp."; RQ-047: STALLED fires at exp_c.
- No public check of EN-004 to EN-008 refuses an envelope with exp_c ≥ exp. With exp_c ≥ exp, RQ-046 expires the request first, STALLED never fires and the AU-021 reissue is not available.
- Witness `w_exp_c_not_below_exp` reached in 49.45% to 57.32% of traces across the 16 design runs.

## F4 (SL-004, SL-005, Q-003): a header that opens after b + Δ_c takes a precedence that never lapses

- SL-004 sets prec when the header opens. SL-005: "If the authorization of a request ordered at board height b is not in force at board height b + Δ_c, then … SHALL mark the precedence … as lapsed." The note under SL-004 makes a node judge a header only after every earlier-ordered live envelope opened or ended (Q-003).
- SL-005 fires once, at b + Δ_c. A header that opens later takes precedence after that event and nothing marks it lapsed; its slots wait until exp.
- Witness `w_open_after_lapse` reached in 10.58% to 17.10% of traces.

## F6 (C20, found in the revision 3 run): an ADMIT quorum after an honest STALLED post

- RQ-047: at `exp_c` with no `q` ADMIT votes committed, the node posts VOID STALLED. RQ-023 and RQ-026 do not refuse an ADMIT vote that commits after `exp_c`, or after the voter's own STALLED post, and the VOID tombstone forms only at `f + 1` posts (RQ-045).
- Schedule (revision 3, now `test_m_stalled_after_release::killStalledAfterReleaseTest`): a filled collecting request; at `exp_c` honest member 2 posts STALLED; the `q` ADMIT votes commit next; generation 1 releases; corrupt member 1 posts STALLED. Two STALLED posts, one of them honest, so RQ-045 sets reason STALLED on a request that released: `inv_C20_stalledReleasedNothing` is false.
- Safety of C11 is not affected: the outcome is RELEASED (RQ-051), and AU-022 refuses to carry a leaf other than VOID. The reason read by the stalled gate of AU-021 is wrong.
- Fix, DECISIONS 64 (owner ruling 2026-11-15): late admission stays allowed. Once `any_release = true`, a STALLED post counts toward the `f + 1` posts of the tombstone but is no reason post (RQ-074), and a request with `any_release = true` never has reason STALLED (RQ-073). The reason is the reason of `f + 1` remaining posts, otherwise MIXED (RQ-045, RQ-072); with a STALLED post among the `f + 1` that is always MIXED. `test_tee_p1::f6StalledAfterAdmitTest` runs the revision 3 schedule and ends VOID with reason MIXED and outcome RELEASED; `f6StalledNoReleaseTest` keeps STALLED for a request that released nothing.
- Same schedule on the NON_TEE path: the revision 3 design runs of `nontee_p1` from `initArmed` reached `w_stalled_after_release` (reason STALLED, a RELEASE on the board) once per seed. Rerun on the revision 3 model with the invariant `not(w_stalled_after_release)` and the same instance, init and seeds, both seeds return one 51-state schedule (`traces-sample/f6_nontee_p1_rev3/`): honest member 4 posts STALLED for collecting request 1 at height 12 (`exp_c = 9`), `admit(1)` commits at height 16, the RELEASE of generation 1 is recorded at 18, and the corrupt STALLED post at 19 forms the tombstone; no partial was sent and the outcome is RELEASED. This is F6. Replay on revision 4 (`replay_f6.qnt`: state 40 loaded from the ITF file with `tools/itf2qnt.py`, steps 41 to 50 run as actions): on both seeds every recorded step is enabled and the request ends VOID with reason MIXED and outcome RELEASED (`replayF6Seed14Test`, `replayF6Seed2a3Test`); the revision 3 end state breaks `inv_RQ073_C20_noStalledAfterRelease` (`replayF6Rev3EndStateTest`); with the mutant the same steps end STALLED again (`replayF6Seed14MutantTest`). Revision 5 (urgent expiry) makes the recorded steps 46 to 50 moot; see the next section.

## Revision 5: the findings under urgent expiry

The replay of the item 14 traces through the Lean oracle found five classes of disagreement. The lead ruled each one as a reading of the specs:

- (A) RQ-046 expiry is urgent.
- (B) RQ-020 refuses a frame above `exp_c` also while the target is ORDERED.
- (C) A frame for an OPENED or ADMITTED target is refused with `late_contribution` (new RQ-075).
- (D) A restart that loses the board tail keeps `any_release` and `released` (new RQ-076).
- (E) A restart does not end again a request whose leaf Midnight holds (DECISIONS 58).

DECISIONS 70 records C and D. Under A the model expires a request inside the event that takes the board height past its `exp` (tick, order, checkpoint). The separate `expire` step of item 14 exists only under the mutant `late_expiry`.

Item 14 reached the F1 and F5 schedules, the SL-010 end test and the F6 random seeds through a late `expire`. The table gives the result for each under urgent expiry. DECISIONS 59 to 64 stay as they are.

| Schedule | Under urgent expiry | Fate |
|---|---|---|
| F1: `f1NonTeeExpiryDoubleSpend{,Blocked1,Blocked2}Test`, `killSendBeforeRecordTest` | Only ticks lay between the send and the late `expire`. The tick that takes the board to `exp + 1 = 8` now expires request 1. With `send_before_record` the request still ends VOID after a send and settles VOID, and both confirmations succeed. | Reachable, so the finding stands as found. The schedules now use 7 ticks (the expiry falls on the last tick) and have no `expire` step. |
| F5: `f5LockedVoidUnlocks{,Blocked2}Test`, `killLockedVoidUnlocksTest` | The same holds for both expiries (request 1 at height 8, re-post 3 at height 17). With `locked_void_unlocks` the record returns to UNSPENT and both confirmations succeed. | Reachable, so the finding stands as found. The `expire` steps are removed. |
| SL-010 end half: `sl010EndBurnsTest` | The holder was never authorized, so SL-005 burned its slot at the lapse (height 5), before the late `expire` at height 9. The test checked the lapse burn, not the end burn. | Rebuilt with an in-force holder: the slot is NAMED at height 7 and the expiry at height 8 burns it. `killCommitteeBurnReservedOnlyTest` keeps its never-authorized holder (under the mutant neither the lapse nor the end burns the slot) and loses only the `expire` step. |
| F6 random seeds 0x14 and 0x2a3 (`nontee_p1`, revision 3, `traces-sample/f6_nontee_p1_rev3/`) | State 40 is still reachable. Steps 0 to 40 hold no late expiry and no restart, and the only frame is held while the target is ORDERED (step 14, height 6, `exp_c = 9`). Request 1 has `exp = 16`. The recorded step 46 ticks to 17 and now expires request 1 with `any_release = false` (outcome VOID). The recorded RELEASE at height 18 (step 48) and the STALLED post at height 19 (step 50) are then refused as terminal (RQ-005). | The recorded suffix is moot (`replayF6Seed14RecordedTest`, `replayF6Seed14RecordedBlocked1Test`). F6 is still reachable on the NON_TEE path by a shorter suffix at height 16 = `exp`: the admit of step 41, the RELEASE of step 48 and the corrupt STALLED post of step 50. That suffix ends MIXED and RELEASED on the current model (`replayF6Seed14UrgentTest`, `replayF6Seed2a3UrgentTest`) and STALLED under the mutant (`replayF6Seed14MutantTest`). The scripted TEE schedule `f6StalledAfterAdmitTest` runs at heights 1 to 5 with `exp = 13` and is unchanged. The ITF files stay as revision 3 artifacts; they are not traces of the current model. |

Other schedules that used a late `expire` lose only that step: `sl006EcdsaPrecTest` (request 2 now has `exp = 16`, so it is still ADMITTED when request 1 expires at height 14), `rq068ReEndTest`, `rq068NonTeeRestartTest`, `cp013BatchTest`, and the kill tests of `d058_b`, `d058_b_nontee`, `committee_burn_reserved_only`, `ecdsa_burn_by_namer`, `settle_per_request` and `root_omit`. `killRootOmitTest` still needs the expiry at the checkpoint's own board height, and request 1 expires on the last tick.

Rulings D and E change two more schedules:

- `killRestartVoidUnspentTest` killed `restart_void_unspent` only because the lost tail cleared `any_release`. Under RQ-076 that schedule settles RELEASED under the mutant too. It is kept as `killRestartVoidUnspentReleasedSurvivesTest`, and the kill now uses an admitted request that released nothing.
- `rq054CarveOutTest`: the restart no longer ends again the reissued request whose carried VOID leaf Midnight holds (`restart_end` stays false). `replace_held` re-ends it and replaces the held leaf, and `killReplaceHeldTest` still kills it.

## F7 (CP-040, CP-014, SL-004, SL-013; revision 6): a precedence below the landed pending floor blocks the honest checkpoint

Fixed in revision 7 by DECISIONS 71 (owner ruling, 2026-11-15, fix (a)). It was a liveness defect, not a safety defect. The text below describes the revision 6 specs.

Spec sentences:
- SL-004: "When the header of a request opens and names a committee slot with `prec = none` and `bstat = UNNAMED`, the slot ledger SHALL set `prec` to the namer". The sentence has no window clause.
- CP-014: "sign `pending_root` only over the sorted list of the committee slots that live requests hold on the board, with `pending_min` its lowest entry or `h + 1`".
- CP-040 (DECISIONS 69): "If a checkpoint has `pending_min` below the `pending_min` of the previous landed checkpoint ... refuse the checkpoint with the code `pending_min_lowered`." Its note says an honest committee never lowers the floor because it reserves in increasing order.
- SL-013: a header that names an index below `cp.pending_min` gets VOID SLOT_TAKEN posts.

Schedule `test_tee_p2::cp040PendingMinLoweredBlocked1Test`:
1. Request 1 reserves committee slot 2, and checkpoint 1 lands with `h = 2` and `pending_min = 2`.
2. Request 2, never authorized, names slot 1, which is UNNAMED, and its header opens. SL-004 gives it `prec`, so slot 1 is a slot that a live request holds.
3. The honest checkpoint (CP-014) now has `pending_min = 1`, and CP-040 refuses it (`w_cp_pending_min_lowered`).

The floor counts precedence, not reservations, so an envelope from anyone lowers it. The block ends when request 2 ends: by `f + 1` SLOT_TAKEN posts (SL-013), or at its lapse, when SL-010 burns slot 1 (`cp040LapseUnblocksTest`, after `Δ_c` blocks). Until then no checkpoint lands, so no `settle_root` lands either. A spammer who posts such envelopes again and again delays every checkpoint. The random design runs reach the state (`w_cp_pending_min_lowered`, rates in README).

Possible readings for the owner: CP-014 lists only indices at or above the previous `pending_min`, or SL-004 gives no precedence on an index below the window.

Fix, DECISIONS 71 (owner ruling 2026-11-15, the first reading): CP-014 now signs `pending_root` "only over the sorted list of the committee slots that live requests hold on the board at or above the `pending_min` of the previous landed checkpoint for that pool". A pool that the previous landed checkpoint does not list has no floor. SL-004 is unchanged. In the model `pendingOf` keeps only the slots at or above `st.cp.pending_min` (`cpZero` has `pending_min = 1`, the lowest index, so the first list has no floor).
- Regression test `test_tee_p2::f7SpamPrecedenceLandsTest`: the same schedule. Request 2 holds precedence on slot 1 (`w_prec_below_floor`). The honest checkpoint lands with `pending_min = 2` and without `(1, 2)` in its list. Then the `f + 1` SLOT_TAKEN posts of SL-013 end request 2 VOID, and SL-010 burns slot 1. The revision 6 schedule `cp040PendingMinLoweredBlocked1Test` is removed, because its checkpoint now lands. `cp040LapseUnblocksTest` is kept: the checkpoint after the lapse also lands with `pending_min = 2`.
- Gate invariant `inv_CP014_CP040_honestFloorKept`: the checkpoint that the signers compute in any state has `pending_min` at least that of the landed checkpoint. A landed-chain invariant cannot see the old listing, because CP-040 refuses its checkpoint before it lands.
- Mutant `m_pending_unwindowed` restores the revision 6 listing. `killPendingUnwindowedTest` breaks the invariant on the F7 schedule (`w_cp_pending_min_lowered` again), and `killPendingUnwindowedBlocked1Test` shows that the checkpoint is refused.
- CP-040 is now unreachable from honest checkpoints, so `m_pending_min_unchecked` survives every random run. `killPendingMinUncheckedTest` checks the contract rule on the CP-040 scenario "Old index pending again" with hand-built checkpoints (`pending_min = 1` after a landed 3). Its design twin is `cp040OldIndexRefusedTest`.
