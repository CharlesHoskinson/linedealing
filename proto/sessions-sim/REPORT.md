# Sessions discovery simulator

Deterministic, single-epoch model of the read-only `.spec/` snapshots through SS-135, with the frozen per-checkpoint Midnight commitment rules applied below.
The regression tests replay the findings in [QUESTIONS.md](QUESTIONS.md) under old and fixed rules.

| Files | Purpose |
|---|---|
| `src/sim.rs`, `node.rs`, `board.rs`, `ledger.rs`, `params.rs`, `faults.rs` | Protocol model, application driver and fault injection |
| `src/oracle.rs` | Persistent release/erasure history, CONCURRENT default and selectable LITERAL reading |
| `src/experiments.rs` | Reachable replacement schedules, seeded faults and safety/liveness aggregation |
| `src/measurements.rs` | SS-134/135 body encoding, accounted sizes and window/restart measurements |
| `src/main.rs` | Fixed and old-rule 300-seed tables, fixed series and measurements |
| `tests/regressions.rs` | Paired Q-01/02/03/05/06/09/11 regressions and uncovered-put test |
| `tests/commitments.rs` | Board loss, root replay, pending membership, restart bounds and Midnight accounting |
| Other `tests/` files | Protocol, contract, fault, mutation, encoding and 200-seed sweep tests |
| `QUESTIONS.md` | Original specification questions and traces |

## Model boundaries

- One epoch, sequential Schnorr and account ECDSA pools, and `anchor_before_release=false`.
- SHA-256 abstractions replace cryptography. Typed record bodies become protocol-visible only after authentication.
- Operations are serialized, with explicit crash points. IO, network time, rekey, anchors and attestation are excluded.
- Share repair installs an abstract share only with t available honest holders. The repair protocol is excluded.
- SS-102 fetches at least w+1 current peers. The model extends a short experimental source set in ascending seat order. An incomplete fetch stays unavailable. Owners cannot supply their own entries under the default rules.
- SS-126/127 rebuild matching replicas from answering non-owners. A missing replica leaves the signed entry intact and does not block fetch completion.
- SS-120..125 add restart statements and checkpoint markers. Late account opens burn older generations. Free account binds wait for the restart checkpoint. The body digest includes the marker.
- SS-133 resets `whole_restart` after a newer restart checkpoint has w+1 continuous seats. A second continuity loss in the same uptime burns again.
- Each seat has a board log of `Put { digest, tag }` and `Restore { boot, seq, whole_restart }` entries. Board posts land immediately. The board is separate from node disks and snapshots. Rolling back every disk leaves the board unchanged.
- Account puts use `SHA-256("VT1/slot-put" || share)` and a fresh 16-byte tag. Tags remain in session bodies and roll back with them. Duplicate digests in that seat's covered log or tail return `slot_used`, at any index. Different seats have independent logs.
- Each landed checkpoint covers every entry posted before its construction. Board positions are global monotone u64 values. A batch hashes `"VT1/seat-batch"`, then each position and typed entry in board order. Put encoding is byte 0, digest32, tag16. Restore encoding is byte 1, boot64, seq64, whole_restart8. Integers are big-endian. The empty batch is `SHA-256("VT1/seat-batch")`.
- The contract computes `SHA-256("VT1/seat-log" || previous_root || batch_root)` per seat, starting from a zero32 root. It discards the batch-root submission inputs after computing the chained roots. Ledger history retains checkpoint roots, fixed fields and carried RestoreDone statements. No per-put records or separate RestoreDone map remain.
- A node replays the board's batches against checkpoint history before accepting its own seat log. Only the first covered Put with the matching digest and the slot's tag permits a new bind. A visible tail entry returns `put_pending`. A missing entry is reposted once with the stored tag. `put_pending` leaves the free body unchanged and is not a BindRefused event.
- `withhold(seat)` stops serving that seat's log. `serve(seat)` restores service. `lose_tail()` drops all uncovered entries. `lose_covered(seat)` drops that seat's covered entries. Missing or modified covered data returns `log_unavailable` on account puts and binds and prevents release. Checkpoint construction stalls before submission if any seat's prior root cannot be reproduced. Roots never reset after board loss.
- RestoreDone is a board post. The next checkpoint carries its interval's statements. SS-117 and SS-121/122 inspect the current submission and earlier checkpoints, including repeated boot counters. Boot tickets remain separate `admitBoot` transactions. The current recovery statement stays in RAM for retransmission if the board loses it before coverage. Recovery retries do not duplicate a visible statement.
- Sequential checkpoints store `pending_min`, `pending_root` and `pending_count`. The board retains the committed pending set. Its hash is SHA-256 of `"VT1/pending"` followed by sorted big-endian u64 indices. Binds below `pending_min` are stale. Binds through `h` require membership and a matching root and count. SS-104 requires both `h >= old.h + B` and `pending_min > old.h + B` after a restart. SS-068 burns the complete interval `[pending_min, h+B]`, including holes. SS-108 prunes below `pending_min`, retaining an owner's live-slot witness until that slot is burned or absent.
- The normal driver retries pending puts on later app steps and posts only at checkpoint cadence. A request can expire before its put is covered. Crash experiments explicitly checkpoint their setup batch before arming a bind crash cut.
- The body encoder implements SS-134/135. Measurement records have a 52-byte header, 24-byte nonce and 16-byte tag. The model retains its abstract 32-byte MAC. JSON envelopes, size-limit enforcement and real AEAD are excluded.
- CONCURRENT is the default oracle reading. A completed SS-102 replacement fetch retires that seat's loss. Rollbacks and Byzantine seats remain counted for the rest of the run, even through later replacements. This is conservative relative to design G2's retirement of rollback losses after later session commits.
- LITERAL counts all distinct lost seats for the rest of the run. Both readings check peak unavailable seats against f. G2/G3 is always scored. Only out-of-bound G4 can be an expected Limits event. An in-bound run cannot use expected Limits to excuse a G2/G3/G4 event.
- Experiments observe without halting on violations. Ordinary tests retain fail-fast behavior. The blank-fetch mutation observes through the first G4 event to test its subsequent second release.
- The app retains counters across faults. Hostile probes use actual previously released keys and the original share retained outside node state. The app does not automatically retry voided tickets.
- G2/G3 counts same-index, two-digest runs. The separate Share count requires the same share bytes at both releases.
- Table violations count affected runs. Expected events and burn operations can occur more than once per run. `distinct` counts complete per-run outcome tuples, excluding seeds, seat identities and random bytes.
- Each normal row varies the faulted seat, app step and crash cut: none, after fsync, after fewer than w seeded acks, after slot acks or during restore.
- An operation cut crashes seald before the named fault. A restore cut occurs after that fault, after sync and before candidate recovery.
- Byzantine rows also reboot or replace another seat. The adversary answers first and retains stale replicas while the owner advances. C/F/S/P counts actual conflicting slot reports, forged reports, stale fetch responses and refused partials.
- Recovery latency counts complete sweeps after the last fault, with a three-sweep budget. Censored runs are excluded from the mean.
- The fixed 200-seed sweep has an empty allowed-violation list. The old-rule sweep requires the original series, absent-account and missing-replica classes. Finite sweeps do not prove safety.

Every knob defaults to false. Each `old_*` knob selects one rule-family branch. `Knobs::old_rules()` enables the five behavioral mutations and per-event write accounting.

| Knob | Branch |
|---|---|
| `old_no_restart_marker` | Bypass SS-120..125 marker hooks in `restart_marker` |
| `old_fetch_w_sources` | Use the original w sources and source-relative fetch projection |
| `old_no_replica_fetch` | Skip SS-126/127 ciphertext reconstruction |
| `old_no_put_record` | Bypass all account-put log hooks and checks |
| `old_no_restart_rearm` | Skip the SS-133 generation reset |
| `old_per_event_ledger` | Account for the previous design: one 146-byte put transaction per successful account put and one 115-byte transaction per RestoreDone. Protocol decisions still use checkpoint commitments. |
| `fetch_owner_statement` | Independent candidate: admit signed owner statements and owner slot entries during fetch |
| `no_restart_burn` | Skip SS-068 sequential restart burns |
| `no_slot_stale` | Skip the SS-064 lower-bound refusal |
| `no_version_fence` | Skip the SS-016 partial-version fence |
| `no_blank_fetch` | Skip SS-102 reconstruction |
| `no_account_burn` | Skip SS-114/123 account burns |
| `no_witness_before_bind` | Skip the SS-050 peer slot-ack round |

`defer_put_records` is removed. All board posts land immediately, and all fixed-rule puts wait for checkpoint coverage. There is no disk outbox.

## Run

Run from this crate directory. Cargo uses the existing lockfile and cached dependencies.

```sh
CARGO_TARGET_DIR=/tmp/sessions-sim-target cargo fmt --check
CARGO_TARGET_DIR=/tmp/sessions-sim-target cargo clippy --offline --locked -j 8 --all-targets -- -D warnings
CARGO_TARGET_DIR=/tmp/sessions-sim-target cargo test --offline --locked -j 8
CARGO_TARGET_DIR=/tmp/sessions-sim-target cargo test --offline --locked -j 8 --test sweep -- --nocapture
CARGO_TARGET_DIR=/tmp/sessions-sim-target cargo run --release --offline --locked -j 8
```

The optional first program argument sets checkpoint cadence in app steps (default 4):

```sh
CARGO_TARGET_DIR=/tmp/sessions-sim-target cargo run --release --offline --locked -j 8 -- 8
```

The program prints 300 seeds for each of nine fault kinds at both profiles, first fixed and then old rules. Both tables use CONCURRENT. It then prints fixed series and measurements. Fixed rows report zero G2/G3/G4 violations. The suite has 76 integration tests, including nine regressions, twelve commitment tests and 800 mixed sweep runs (200 seeds, two profiles, fixed and old rules). Formatting, offline Clippy with warnings denied, offline tests and the offline release run pass.

## Safety table

`cargo run --offline --release`, 300 seeds per row, `B = 8`, checkpoint every 4 app steps, CONCURRENT reading. The fixed rules show no G2/G3, Share, G4 or G1 violation in any row. The old-rule rows reproduce the findings: Q-11 in `coordinated_rollback` (286 of 300 runs at both sizes) and the series A outcomes at `4/1`.

```text
fixed rules (default)
kind n/f seeds distinct I/O G2G3_I/O Share_I/O G4_I/O G1_I/O expected A Q11 reopened% releases refused_W/S/N/C voided burned mean_recovery censored Byz_C/F/S/P Midnight_tx/run Midnight_bytes/run
seald_crash 4/1 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 7000 0/0/0/3031 0 3528 1.00 0 0/0/0/0 8.98 2951.35
vm_reboot 4/1 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 7152 0/0/0/2988 0 3672 1.00 0 0/0/0/0 8.95 2952.33
replace_slot 4/1 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 7188 0/0/0/2998 0 3672 1.00 0 0/0/0/0 9.02 2982.93
whole_committee_restart 4/1 300 20 0/300 0/0 0/0 0/0 0/0 1896 0 0 100.00 5974 0/0/1025/0 93 15532 1.00 0 0/0/0/0 11.96 3514.17
coordinated_rollback 4/1 300 36 0/300 0/0 0/0 0/0 0/0 7207 0 0 100.00 5934 0/704/932/1284 108 14772 1.00 0 0/0/0/0 11.99 3548.15
byzantine_peer 4/1 300 108 0/300 0/0 0/0 0/0 0/0 1176 0 0 83.67 6385 0/0/0/2994 0 3445 1.00 147 1362/2194/1176/3900 8.95 2965.80
ledger_read_failure 4/1 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 7056 0/0/0/3030 0 3616 1.00 0 0/0/0/0 8.91 2939.72
replace_series_then_rollback 4/1 300 2 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 191 0/0/0/191 0 0 1.00 0 0/0/0/0 11.27 3876.67
mixed 4/1 300 224 121/179 0/0 0/0 0/0 0/0 5618 0 0 93.93 11578 0/1588/988/5156 188 18239 1.00 43 1208/2275/1036/4840 17.36 5863.73
seald_crash 7/2 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 12025 0/0/0/5224 0 6174 1.00 0 0/0/0/0 11.98 4525.07
vm_reboot 7/2 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 12291 0/0/0/5142 0 6426 1.00 0 0/0/0/0 11.95 4531.84
replace_slot 7/2 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 12354 0/0/0/5161 0 6426 1.00 0 0/0/0/0 12.02 4570.71
whole_committee_restart 7/2 300 20 0/300 0/0 0/0 0/0 0/0 3192 0 0 100.00 10369 0/0/1949/0 93 26848 1.00 0 0/0/0/0 17.96 5653.10
coordinated_rollback 7/2 300 36 0/300 0/0 0/0 0/0 0/0 12190 0 0 100.00 10296 0/1232/1775/2247 108 25851 1.00 0 0/0/0/0 17.99 5708.47
byzantine_peer 7/2 300 109 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 12022 0/0/0/5947 0 6272 1.00 0 1362/1312/165/3872 11.95 4540.35
ledger_read_failure 7/2 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 12123 0/0/0/5205 0 6328 1.00 0 0/0/0/0 11.91 4514.26
replace_series_then_rollback 7/2 300 2 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 191 0/0/0/191 0 0 1.00 0 0/0/0/0 18.27 7757.45
mixed 7/2 300 224 156/144 0/0 0/0 0/0 0/0 7429 0 0 99.90 21205 0/2933/1875/9519 188 32838 1.00 2 1624/1480/159/5401 23.31 9272.57
old rules
kind n/f seeds distinct I/O G2G3_I/O Share_I/O G4_I/O G1_I/O expected A Q11 reopened% releases refused_W/S/N/C voided burned mean_recovery censored Byz_C/F/S/P Midnight_tx/run Midnight_bytes/run
seald_crash 4/1 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 8328 0/0/0/3631 0 3528 1.00 0 0/0/0/0 24.92 4611.57
vm_reboot 4/1 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 8472 0/0/0/3584 0 3672 1.00 0 0/0/0/0 24.92 4620.34
replace_slot 4/1 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 8472 0/0/0/3646 0 3672 1.00 0 0/0/0/0 24.99 4642.06
whole_committee_restart 4/1 300 20 0/300 0/0 0/0 0/0 0/0 2328 0 0 100.00 7854 0/0/0/0 93 15964 1.00 0 0/0/0/0 30.85 5408.95
coordinated_rollback 4/1 300 36 0/300 0/286 0/286 0/0 0/0 8615 0 286 100.00 9750 0/704/0/2246 108 14772 1.00 0 0/0/0/0 37.22 6344.19
byzantine_peer 4/1 300 110 0/300 0/0 0/0 0/0 0/0 1176 0 0 83.67 7464 0/0/0/3588 0 3445 1.00 147 1544/2194/1176/4289 25.22 4638.17
ledger_read_failure 4/1 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 8416 0/0/0/3614 0 3616 1.00 0 0/0/0/0 24.94 4616.24
replace_series_then_rollback 4/1 300 3 300/0 191/0 191/0 300/0 300/0 0 300 0 100.00 382 0/0/0/0 0 0 1.00 0 0/0/0/0 18.58 4036.93
mixed 4/1 300 216 121/179 54/77 54/77 75/0 75/0 7248 75 77 93.48 16106 0/1580/0/6886 188 18309 1.00 46 1755/2384/1095/5680 54.43 10053.27
seald_crash 7/2 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 14574 0/0/0/6274 0 6174 1.00 0 0/0/0/0 38.97 7360.59
vm_reboot 7/2 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 14826 0/0/0/6185 0 6426 1.00 0 0/0/0/0 39.01 7380.98
replace_slot 7/2 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 14826 0/0/0/6295 0 6426 1.00 0 0/0/0/0 39.06 7408.05
whole_committee_restart 7/2 300 20 0/300 0/0 0/0 0/0 0/0 4056 0 0 100.00 13884 0/0/0/0 93 27712 1.00 0 0/0/0/0 50.89 8959.78
coordinated_rollback 7/2 300 36 0/300 0/286 0/286 0/0 0/0 14459 0 286 100.00 16974 0/1232/0/3842 108 25851 1.00 0 0/0/0/0 61.25 10481.69
byzantine_peer 7/2 300 112 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 14487 0/0/0/7147 0 6272 1.00 0 1544/1312/165/4628 39.35 7399.21
ledger_read_failure 7/2 300 21 300/0 0/0 0/0 0/0 0/0 0 0 0 100.00 14728 0/0/0/6227 0 6328 1.00 0 0/0/0/0 39.06 7376.31
replace_series_then_rollback 7/2 300 3 300/0 0/0 0/0 0/0 300/0 0 0 0 92.86 191 0/0/0/0 0 0 NA 300 0/0/0/0 30.58 7917.71
mixed 7/2 300 216 156/144 0/77 0/77 0/0 75/0 10280 0 77 97.93 29993 0/2933/0/13024 188 33059 1.00 79 2461/1504/133/6422 87.49 16688.61
```

## Midnight writes

The safety table reports mean Midnight transactions and bytes per run across each 300-seed row. Counters include initial boot admissions. A submitted checkpoint counts even if the contract refuses it. A board verification failure prevents submission and adds no transaction.

The comparison below uses the same workload for both modes: seed 731, 12 app steps, cadence 4, one whole-committee restart and one recovery checkpoint. Only `old_per_event_ledger` differs. The safety table's old mode also enables the behavioral mutations.

| Rules | n/f | Checkpoints | Boot tickets | Put transactions | RestoreDone transactions | Midnight tx | Midnight bytes |
|---|---|---:|---:|---:|---:|---:|---:|
| Fixed | 4/1 | 5 | 8 | 0 | 0 | 13 | 4,620 |
| Old per-event | 4/1 | 5 | 8 | 16 | 8 | 37 | 6,956 |
| Fixed | 7/2 | 5 | 14 | 0 | 0 | 19 | 7,450 |
| Old per-event | 7/2 | 5 | 14 | 28 | 14 | 61 | 11,538 |

Checkpoint bytes are `88 + 52*sequential_pools + 8*n + 8 + 32*n + 64*q + 115*carried_RestoreDone`, with `q = ceil((n+f+1)/2)`. This model has one sequential pool. Each boot ticket adds 150 bytes. The fixed checkpoint base is 500 bytes at 4/1 and 748 bytes at 7/2.

The fixed run carries eight or fourteen RestoreDone statements across its checkpoints. The old accounting mode charges those statements as separate 115-byte transactions, excluding them from checkpoint bytes. Each successful account put adds a separate 146-byte transaction. This knob models write costs only. It retains checkpoint validation so that the two comparison workloads have identical protocol traces.

## Commitment tests

| Test | Required outcome |
|---|---|
| `q11_absent_account_slot_after_whole_rollback` | A covered share cannot be put at its original or another index after rollback. `old_no_put_record` still exposes the G2/G3 violation. |
| `q11_put_pending_then_bind` | A tail put leaves the slot free without duplicate posts or refusal events. Coverage permits one release. After rollback and tail loss, only the old knob permits a second digest and triggers G2/G3. |
| `uncovered_put_cannot_bind` | Tail duplicates return `slot_used`. Bind returns `put_pending` without a Midnight write, then succeeds after coverage. |
| `q11_lost_tail_covered_put_not_rebound` | Covered share history survives rollback of every disk and `lose_tail()`, at both committee sizes. |
| `withheld_log_refuses_bind_never_releases` | Put and bind return `log_unavailable` after rollback. The checkpoint stalls. Restoring service reveals the old share as `slot_used`. |
| `rollback_across_checkpoint_boundary` | A snapshot before checkpoint k-1 cannot erase a put covered by k. A lost tail put never released and needs new coverage. |
| `lost_covered_entries_stall_checkpoint_and_fail_closed` | Repeated attempts leave the ledger root and transaction count unchanged. Account operations and releases remain blocked. |
| `lost_tail_resubmits_once_and_needs_coverage` | Bind reposts a lost tail entry with its stored tag exactly once, then waits for coverage. |
| `restore_lost_after_recovery_is_reposted_before_checkpoint` | Tail loss after RestoreDone triggers retransmission during recovery, allowing boot counters and the marker to advance. |
| `roots_chain_empty_batches_and_detect_changed_bytes` | Empty intervals extend each seat root. Changed covered bytes fail replay and block checkpoint construction. |
| `pending_min_restart_jump_refused_and_accepted` | SS-104 rejects either a short h jump or a pending_min at the burn boundary, then accepts both valid fields. |
| `sequential_pending_membership_requires_matching_root` | A missing index, a below-minimum index or a forged pending set cannot bind. A matching committed set permits its members. |
| `restart_burn_is_one_run_including_pending_holes` | SS-068 burns the complete minimum-to-window interval, including absent indices. |
| `fixed_midnight_writes_only_checkpoints_and_boot_tickets` | Fixed runs make only checkpoint and boot transactions. Old accounting adds transactions and bytes with identical protocol traces. |
| `rejected_contract_submission_counts_but_builder_stall_does_not` | Contract rejection counts a submitted transaction. Unavailable board data prevents submission. |
| `first_covered_tag_wins_and_seats_are_independent` | Later tags cannot replace the first covered tag. Different seats can hold the same share digest independently. |

## Series results

All rows use seed 731, fixed rules and `fetch_owner_statement=false`. F/S/A denotes fence, sequential and account traces.
Series schedules checkpoint between replacements to retain continuity and the pending sequential request.
The session checkpoint column adds one owner checkpoint after holder replacements, before owner rollback.
The blank-owner column replaces the owner with empty storage instead of rolling it back.

| n,f | t | w | c | Owner + non-holders | Rollback F/S/A | With session checkpoint F/S/A | Blank owner F/S/A |
|---|---|---|---|---|---|---|---|
| 4,1 | 3 | 2 | 1 | 2 | All reopen safely | All reopen safely | All reopen safely |
| 7,2 | 5 | 4 | 2 | 3 | All reopen safely | All reopen safely | All reopen safely |
| 5,1 | 4 | 3 | 2 | 2 | All reopen safely | All reopen safely | All reopen safely |
| 6,2 | 4 | 3 | 1 | 3 | All reopen safely | All reopen safely | All reopen safely |
| 9,2 | 7 | 6 | 4 | 3 | All reopen safely | All reopen safely | All reopen safely |

All rows are CONCURRENT in bound (peak one loss). LITERAL counts the completed replacements and classifies these traces out of bound. Rebuilt replicas preserve G1. The fence entry stays erased, and the sequential and account rebinds return `slot_bound_other`.

With the old fetch and replica knobs, Q-01/02/03 reproduce at 4/1 and 6/2. The other three profiles return `GroupUnavailable`. With only replica fetch disabled, Q-05 returns `GroupUnavailable` at all five profiles. The independent owner-statement candidate retains fences under the old fetch rule but cannot restore missing replicas.

## Measurements

SS-134 uses big-endian integers, u16 purpose/name/share lengths, u32 value lengths and counts, u64 indices and restart markers, and compressed burned runs. Measurement purpose is `schnorr-slots`. Each bound 64-byte Schnorr share occupies 107 bytes. SS-135 counts free slots at that bound size. Record size adds 92 bytes to the body.

| Slots | State | Body | Accounted body | Record | Base64 line including LF |
|---|---|---:|---:|---:|---:|
| 1000 | all_free | 75,035 | 107,035 | 75,127 | 100,173 |
| 1000 | all_bound | 107,035 | 107,035 | 107,127 | 142,837 |
| 1000 | all_burned | 51 | 51 | 143 | 193 |
| 1000 | alternating_burned_free | 45,535 | 61,535 | 45,627 | 60,837 |
| 1000 | after_restart_burn_B | 74,451 | 106,195 | 74,543 | 99,393 |
| 10000 | all_free | 750,035 | 1,070,035 | 750,127 | 1,000,173 |
| 10000 | all_bound | 1,070,035 | 1,070,035 | 1,070,127 | 1,426,837 |
| 10000 | all_burned | 51 | 51 | 143 | 193 |
| 10000 | alternating_burned_free | 455,035 | 615,035 | 455,127 | 606,837 |
| 10000 | after_restart_burn_B | 749,451 | 1,069,195 | 749,543 | 999,393 |

All measured accounted bodies fit S_max=2,097,152. Payload lines fit 4,194,304 bytes before the RPC envelope. A 10,000-slot bound record is 21,551 bytes above 1 MiB. Its accounted body is exactly 1,070,035 bytes. The record is exactly 1,070,127 bytes.

## Specification notes

- SS-031/032/094 order restore candidates by descending version, then matching report count for equal versions.
- SS-036/068/114/123 expose burned slots only after the restart checkpoint succeeds. Raw rollback records can still contain free slots.
- SS-124 says an account bind must be refused when there is “no checkpoint after `cp_boot` with `restart_seq` above `cp_boot.seq`.” Thus disabling only put records cannot reproduce Q-11's immediate second bind. The regression checks this barrier, then posts the checkpoint and demonstrates exact-share reuse with only `old_no_put_record`. The old-rule trace also includes the initial put checkpoint, then reproduces the original second release. The fixed re-put returns `slot_used` under both the original and another index.
- SS-102 keeps the highest signed version of each `(node_index, sid)` and each `slot` entry that a non-owner reports. Slot entries carry no version. The model keeps non-owner slot entries and marks conflicting digests as SS-116 requires.
- The frozen account-put rule refuses a digest already in that seat’s board log. It does not reserve the index. After a whole rollback and the SS-124 checkpoint, a fresh share at a reused index can still trigger the index-based G2/G3 oracle. `fresh_share_index_reuse_is_distinct_from_nonce_reuse` retains this distinction: the share-based nonce-reuse oracle stays clear. This is a difference between index uniqueness and the new durable share-uniqueness rule.
- Q-09's original trace establishes an omitted burn, not a second-digest release. The paired regression checks the restart flag, changed boot checkpoint and slot release eligibility directly.

## Spec inputs

The frozen task rules supersede the snapshot rules for put records, RestoreDone storage, pending fields and Midnight accounting. SHA-256 of the underlying snapshots (`.spec/`, not committed):

| File | SHA-256 |
|---|---|
| `veritee/wt-sessions/openspec/changes/add-seald-sessions/specs/seald-sessions/spec.md` | `9cc144ddecde7154d61fd122330d811bd6c37677724b21d731fd2bfcc16a6392` |
| `veritee/wt-sessions/openspec/changes/add-seald-sessions/design.md` | `442aebd3258a07e0c46c3546b57a2f8c5b6006a15552800793c0d547baec56e3` |
| `mpcexperiments/design/enhancement/sessions-review/QUINT-ITEMS.md` | `7a6f94b380179ca338ccc509e895ffb06c9c38dad6b4a80bfd359d0eea50074c` |
