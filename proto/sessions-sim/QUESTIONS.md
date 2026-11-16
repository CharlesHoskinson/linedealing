# Specification questions

All traces use one epoch and `anchor_before_release=false`. Unless stated otherwise, `B=8` and `(n,f,t,w,c)=(4,1,3,2,1)`.
The numbered steps use application calls, faults and node restore operations. A restored source version differs from the new version sealed by SS-036.

## Q-01: Owner answers in a fence reconstruction quorum

**SS IDs:** SS-003, SS-016, SS-036, SS-102, SS-111. **Property:** QI-02, G4.

**Question:** May an owner count toward reconstruction of its own fence without supplying its latest signed statement?

**Shrunk trace:** `fence_series_owner_rollback_counterexample`, seed 731.

1. Seat 0 commits v1 with entry `erased`. Peers 1, 2 and 3 acknowledge. Snapshot seat 0's disks.
2. Seat 0 destroys `erased` in v2. Exactly peers 1 and 2 acknowledge.
3. Replace seat 1. Its two SS-102 answers come from seats 0 and 3. Seat 0 has no peer entry for itself.
4. Seat 1 keeps peer 3's v1 fence, completes fetch and repairs its share. Post a ledger checkpoint.
5. Replace seat 2. Its answers come from seats 0 and 1. It completes fetch with v1. Post another checkpoint.
6. Roll back only seat 0's tier 0 and persist to the snapshot. Reboot seat 0.
7. Seat 0's own restore authenticates v1, seals v2 and opens with `erased` present.

**Observed outcome:** G4 reproduces with the option OFF. No direct stale `derive` call is needed.
LITERAL counts seats 0, 1 and 2, so the trace is out of bound. CONCURRENT peaks at one lost seat and is in bound.
G4 is an expected Limits event under LITERAL and an oracle violation under CONCURRENT.
Across `(n,f)=(4,1),(7,2),(5,1),(6,2),(9,2)`, this trace reproduces at `(4,1)` and `(6,2)` only.
The source-set condition is `1 + (n-1-w) >= w`, equivalently `w-1 <= f`.
When this condition fails, a retained holder supplies the v2 fence and the final restore returns `GroupUnavailable`.

**Precondition:** The owner rolls back after holder replacements and before a successful checkpoint of the affected session replenishes `w` replicas.
`checkpoint_after_replacements_closes_series_exposure_window` adds one such checkpoint before rollback. All five parameter sets reopen safely without resurrection.

**Classification:** Spec gap under CONCURRENT. Known Limits gap under LITERAL. The intended reading is ambiguous (Q-04).

**Candidate EARS change:** When a seat answers an SS-102 fetch, the service SHALL include its own signed latest durable session statement.
This candidate is implemented by `fetch_owner_statement=true`, together with the slot rule in Q-02.

## Q-02: Sequential slot entries in owner answers

**SS IDs:** SS-050, SS-051, SS-054, SS-055, SS-064, SS-102, SS-108. **Properties:** QI-01, QI-02, G2.

**Question:** Does SS-102 require a source to return its own slot entries, or only entries for other seats?

**Shrunk trace:** `sequential_series_owner_rollback_counterexample`, seed 731.

1. The app reserves sequential index 1 and posts `h=1, pending={1}`.
2. Seat 0 commits free slot 1 in v1 at all peers. Snapshot its tier 0 and persist.
3. Seat 0 binds slot 1 to d1. Exactly peers 1 and 2 acknowledge both the slot entry and v2. Release d1.
4. Replace seat 1 with sources `{0,3}`, then seat 2 with sources `{0,1}`. Complete each fetch and share repair.
5. Post a checkpoint after each replacement. Index 1 stays pending, so SS-108 does not remove its protection.
6. Roll back only seat 0. Its restore opens the free slot from v1 and seals v2.
7. The hostile app calls `slot_bind(1,d2)`, committing v3, then `slot_release_ok(1,d2)`.

**Observed outcome:** d2 releases with the option OFF. SS-064 permits index 1 because it remains pending.
The oracle records G2/G3 under both readings. The trace is LITERAL out of bound and CONCURRENT in bound.
G4 during restore is also recorded. Non-halting observation permits the subsequent G2 check.
Across the five parameter sets, d2 releases only at `(4,1)` and `(6,2)`.
This trace reproduces iff owner plus non-holders can fill the answer set: `1 + (n-1-w) >= w`, or `w-1 <= f`.
The other three sets return `GroupUnavailable` without a second release.

**Precondition:** Index 1 remains pending, and rollback occurs before a successful owner checkpoint of the affected session replenishes `w` replicas.
One such checkpoint after all replacements prevents the second release in all five parameter sets and permits safe reopening.

**Classification:** Spec gap under the source-relative reading of “entries for each other seat”. That phrase is ambiguous about the owner.
OFF excludes a source's own entries. ON includes its own slot entries and latest session statement.

**Candidate EARS change:** When a seat answers an SS-102 fetch, the service SHALL include its own slot entries and conflict markers.
A second candidate is to require `w` answers per entry from seats other than its owner and the fetching seat. That alternative is not implemented.

## Q-03: Account slot entries in owner answers

**SS IDs:** SS-050, SS-051, SS-055, SS-065, SS-102, SS-114. **Properties:** QI-01, QI-02, G2.

**Question:** What prevents an account slot from releasing twice after a completed series of replacements and a single owner rollback?

**Shrunk trace:** `account_series_owner_rollback_counterexample`, seed 731.

1. Seat 0 commits account slot 1 as free in v1 at all peers. Snapshot its disks.
2. Seat 0 binds slot 1 to d1 in v2, with slot and record acknowledgements from exactly seats 1 and 2. Release d1.
3. Replace seat 1 using sources `{0,3}`, then seat 2 using `{0,1}`. Complete each fetch and repair, then post a checkpoint.
4. Roll back seat 0 alone. Three peers remain continuous, so its boot is not a whole restart.
5. Seat 0 restores free slot 1 from v1 and seals v2. The app binds d2 in v3 and releases it.

**Observed outcome:** G2/G3 reproduces with the option OFF. SS-114 does not burn the slot during this single-seat restore.
LITERAL is out of bound. CONCURRENT is in bound. ON prevents the second release but can leave the session closed (Q-05).
Across the five parameter sets, this trace reproduces at `(4,1)` and `(6,2)` only.
The condition is `1 + (n-1-w) >= w`, equivalently `w-1 <= f`. Otherwise restore returns `GroupUnavailable`.

**Precondition:** Rollback occurs after holder replacements and before a successful owner checkpoint of the affected session replenishes `w` replicas.
One such checkpoint closes this exposure window in all five parameter sets. Each session reopens safely without a second release.

**Classification:** Spec gap under CONCURRENT and the source-relative SS-102 reading. Known Limits exposure under LITERAL.

**Candidate EARS change:** When a seat answers an SS-102 fetch for an account pool, the service SHALL include its own slot entries and conflict markers.

## Q-04: Lifetime versus concurrent loss accounting

**SS IDs:** SS-016, SS-074, SS-102, SS-112. **Properties:** design G2, QI-02.

**Question:** Does a replaced seat remain in `c` after its SS-102 fetch completes?
The design counts each seat whose tier 0 was lost, but also says fetch prevents a replacement series from erasing fences without collusion.

**Shrunk trace:** All three `*_series_owner_rollback_counterexample` tests, plus `concurrent_loss_peak_and_overlapping_unavailability_are_counted`.

1. For n=4, replace seat 1, complete fetch, replace seat 2 and complete fetch.
2. Roll back seat 0 alone. No two replacements are active together.
3. LITERAL counts three distinct lost seats forever. CONCURRENT counts a peak of one active loss.
4. For n=7, seed 731 commits v2 at seats `{5,2,1,6}`. Non-holders are `{3,4}`.
5. Replacement seat 5 needs four answers. Owner 0 plus non-holders 3 and 4 supply only three.
6. Source seat 2 supplies the fourth answer and the v2 fence. Subsequent valid fetches retain it.

**Observed outcome:** The n=4 A outcomes occur under both readings, with different classifications.
For n=7, all A tests prevent stale opening and second release. Losing every v2 replica can still prevent reopening.
The n=7 run is LITERAL out of bound (five lost seats, c=2) and CONCURRENT in bound (peak one).
Byzantine seats count against loss and availability bounds. A simultaneous reboot adds its seat to the availability count.
The three series also test `(5,1)`, `(6,2)` and `(9,2)`, with `t=n-f`, `w=n-1-f` and `c=n-1-2f`.
All five series lose `w+1` distinct seats and peak at one active loss. Thus all are LITERAL out of bound and CONCURRENT in bound.
Only `(4,1)` and `(6,2)` satisfy `w-1 <= f` and reproduce the stale-opening and second-release outcomes.

**Classification:** Ambiguity. The n=7 owner-plus-non-holder-only source set is impossible under SS-102.

**Candidate EARS change:** When an honest replacement completes verified SS-102 reconstruction, the service's fault model SHALL retire that seat from concurrent loss accounting.
Adopting this candidate requires resolving Q-01 through Q-05. The simulator defaults to LITERAL.

## Q-05: Fences survive but ciphertext replicas disappear

**SS IDs:** SS-003, SS-033, SS-034, SS-038, SS-102. **Property:** G1.

**Question:** Must reconstruction also restore the ciphertext replica matching the retained signed statement?

**Shrunk trace:** `owner_statement_prevents_series_safety_counterexamples`.

1. Enable `fetch_owner_statement`. Seat 0 commits v1 at all peers and v2 at exactly seats 1 and 2.
2. Replace seat 1, then seat 2, completing each fetch from the Q-01 sources and repairing each share.
3. The owner supplies its signed v2 statement. Both replacements retain the v2 fence but have no v2 ciphertext replica.
4. Roll back seat 0 to v1. Its own restore sees v2 reports but cannot fetch a matching record.
5. The v1 fallback cannot collect enough partials because the replacements retain v2 fences.

**Observed outcome:** No erased entry opens and no second digest releases. Restore returns `GroupUnavailable` after the failed v1 fallback.
The v2 attempt lacks a record. The session stays closed and G1 fires under CONCURRENT. LITERAL reports expected Limits events.
The n=7 valid OFF trace also retains fences while losing every v2 replica.

`blank_owner_after_holder_replacements_documents_g1_and_stale_fallback` disables the option and replaces the owner blank after the holder replacements, with no rollback.
At `(5,1)`, `(7,2)` and `(9,2)`, the latest candidate has no matching record. The stale v1 fallback cannot obtain enough partials.
The final error is `GroupUnavailable`, not `RecordUnavailable`, because SS-034 returns the last candidate's failure.
These are plain G1 losses in bound under CONCURRENT, for all three series kinds.
At `(4,1)` and `(6,2)`, the fences also disappear. The blank owner opens stale v1 and reproduces the Q-01 through Q-03 safety failures.

**Classification:** Spec gap if completed replacement is meant to restore an in-bound durable quorum.

**Candidate EARS change:** When an SS-102 fetch retains a signed session statement, the service SHALL fetch and durably store its matching ciphertext before retiring the loss.

## Q-06: Late account boot after cp2

**SS IDs:** SS-065, SS-067, SS-104, SS-112, SS-114. **Property:** QI-07, G2/G3.

**Question:** What prevents account-slot reuse when an owner first synchronizes after the recovery checkpoint?

**Shrunk trace:** `late_boot_account_reports_known_limits_gap`, both profiles.

1. All seats commit account slot 1 as free in v1. Snapshot all disks.
2. All seats bind d1 in v2 and release it.
3. Roll back every disk to v1. Leave seat 0 unsynchronized.
4. Seats 1 through n−1 synchronize and open. Their restored slot 1 burns. The app posts cp2.
5. Seat 0 synchronizes after cp2. Enough peers are continuous, so it classifies `whole_restart=false`.
6. Seat 0 opens free slot 1 from v1, seals v2, binds d2 in v3 and releases it.

**Observed outcome:** G2/G3 fires for both profiles. Both loss readings are out of bound because all disks rolled back together.
Sequential slot 1 instead receives `slot_stale`, as `late_boot_sequential_refuses_after_cp2` demonstrates.

**Classification:** Known Limits gap.

**Candidate EARS change:** When an account session restores after a recovery checkpoint, the service SHALL enforce a durable account reservation floor before accepting a bind.

## Q-07: Body encoding and the 10,000-slot claim

**SS IDs:** SS-002, SS-004, SS-008, SS-088, SS-109.

**Question:** Which canonical serialization defines accounted size, and does the 1 MiB claim include slot metadata and bindings?

**Concrete measurement:** `encoding_sizes_and_fragmentation_ss088`. Seat 0, a Schnorr pool, indices 1 through 10,000, empty entries.

1. Encode each live slot as index:u64, state:u8, share:64 bytes, plus a 32-byte digest when bound.
2. Use u64 counts and length prefixes. Encode each burned run as start:u64 and end:u64.
3. Add the 52-byte header, 24-byte nonce and 16-byte AEAD tag to the body.
4. Measure all-free, all-bound, all-burned, alternating burned/free and first-B-burned bodies.

**Observed outcome:** All-free records occupy 730,131 bytes. SS-088 accounts them at the bound size of 1,050,131 record bytes.
The bound body is 1,050,039 bytes. Its base64 payload line plus LF is 1,400,177 bytes.
The bound record exceeds 1 MiB by 1,555 bytes. It fits S_max=2,097,152 and the 4,194,304-byte line limit before an RPC envelope.
One burned interval yields a 147-byte record. Fragmented intervals cost more. Version does not change these fixed-width sizes.

**Classification:** Spec gap in serialization. The under-1-MiB design claim is conditional on per-slot overhead.
For 10,000 bound slots, `1,048,576 / 10,000 = 104.8576` bytes per slot before fixed overhead.
A 64-byte share leaves less than 40.8576 bytes of overhead. A 32-byte digest leaves less than 8.8576 bytes for index and tag.
Thus overhead beyond the share must stay under about 40 bytes. This encoding uses 41 bytes: index 8, tag 1 and digest 32.
These are measurements, not enforcement of SS-088 or measurements of the simulator's abstract SHA-256 record representation.

**Candidate EARS change:** When calculating SS-088 accounted size, the service SHALL use a specified canonical body encoding and count free slots at bound size.

## Q-08: Checkpoint cadence versus continuity and B

**SS IDs:** SS-063, SS-064, SS-067, SS-068, SS-104, SS-113.

**Question:** What checkpoint cadence prevents serial harmless reboots from triggering a restart burn, and which reservation rate determines B?

**Shrunk trace:** `staggered_reboots_faster_than_checkpoint_cadence`, both profiles.

1. Each seat commits a v1 session containing `keyshare`.
2. Reboot seats 0 through f one at a time. Complete recovery after each reboot, but post no checkpoint.
3. After f+1 different boots, only w seats match the old checkpoint. Running nodes classify a whole restart.
4. The app posts the recovery checkpoint, advancing h by at least B.
5. Independently, `restart_windows_and_different_boot_checkpoint_union_ss068` attempts reservations at rates 1, 4 and 16 per checkpoint interval.

**Observed outcome:** A continuity loss can trigger burns although only one seat is down at a time.
For B=8, normalized refusals are 0, 0 and 500 per 1,000 binds at those three rates.
The smallest zero-refusal B values are 1, 4 and 16. Window cost is B plus pending indices outside that window.
The safety table accepts cadence as its first CLI argument. Series experiments deliberately checkpoint after each replacement.

**Classification:** Operational ambiguity. The supplied rules use checkpoint-relative continuity, not simultaneous outages.

**Candidate EARS change:** When selecting committee parameters, the deployment SHALL set B at least as large as its maximum reservations between successful checkpoints.

## Q-09: SS-113 never resets within an uptime

**SS IDs:** SS-067, SS-068, SS-113, SS-114. **Property:** QI-06.

**Question:** Which event resets the restart flag and account burn marker after cp2?

**Shrunk trace:** `second_continuity_loss_does_not_reset_ss113`.

1. Reboot and synchronize seats 1 and 2. Seat 0 observes insufficient continuity and sets `whole_restart=true`.
2. Post cp2. Seat 0 remains running.
3. Seat 0 creates account slot 1 and binds it in v1.
4. Reboot and synchronize seats 1 and 2 again before another checkpoint.
5. Seat 0 observes the ledger again. Its flag is already true, so SS-113 does not run again.

**Observed outcome:** Seat 0 retains its old `cp_boot`. Its new account slot remains bound and releasable during the second continuity loss.
This trace establishes the missing transition. It does not by itself establish a second-digest release.

**Classification:** Spec gap in repeated restart handling.

**Candidate EARS change:** When a recovery checkpoint completes the active restart generation, the service SHALL reset `whole_restart` and that generation's account burn markers.

## Q-10: Two boot snapshots produce different burn sets

**SS IDs:** SS-067, SS-068, SS-104, SS-112. **Property:** QI-06.

**Question:** Must all nodes use one recovery generation's checkpoint for the restart window?

**Shrunk trace:** `restart_windows_and_different_boot_checkpoint_union_ss068`, n=4, B=8.

1. cp1 has seq=2, h=1 and pending={1}. All seats hold sequential slot 1 and account slots 1 through 16 in v1.
2. Reboot all seats. Seats 0 and 2 synchronize and submit RestoreDone against cp1.
3. Seat 0 opens its sequential session and burns `{1} ∪ [2,9]`.
4. Post cp2 with seq=3. Two changed counters trigger SS-104, advancing h to 9 and removing pending index 1.
5. Seat 1 synchronizes against cp2. Only seats 0 and 2 are continuous, so it also classifies a whole restart.
6. Seat 1 burns `[10,17]`.

**Observed outcome:** The sequential union is `[1,17]`, or 2B+1 indices. It exceeds either original window.
For equal cp_boot snapshots, each seat burns B+1 sequential indices and 16 account indices. The recovery checkpoint voids one pending request.

**Classification:** Contradiction with a literal “every node burns the same sets” reading of QI-06. SS-067/068 prescribe per-boot snapshots.

**Candidate EARS change:** When a restart generation begins, the ledger SHALL identify one checkpoint whose pending set and window all members use for that generation.

## Q-11: Account slot absent from the rollback snapshot

**SS IDs:** SS-041, SS-048, SS-050, SS-055, SS-114. **Property:** QI-07, G2/G3.

**Question:** What prevents recreation of an account slot that did not exist in the restored snapshot?

**Shrunk trace:** `absent_account_slot_after_whole_rollback_counterexample`, both profiles.

1. Snapshot all disks while the account session has no records or slots (v=0).
2. Seat 0 inserts account slot 1 with share `[7;64]`, binds d1 in v1 and releases d1.
3. Roll back every disk to the snapshot. Reboot and recover all seats.
4. Seat 0 classifies `whole_restart=true`, but SS-114 finds no slot 1 to burn.
5. The hostile app reinserts `[7;64]` again at index 1, binds d2 in v1 and releases d2.

**Observed outcome:** G2/G3 fires even though the owner correctly classifies the restart. Both loss readings are out of bound.
This differs from late boot: the snapshot contains an absent slot, not a free slot.
The mixed sweep counts this class only for exact previously released account keys absent from a coordinated-rollback snapshot.
The owner-statement option does not prevent a coordinated rollback of every copy.
The oracle stores the first share put under each `(seat,pool,index)` outside node state and records the share for every release.
The table probe reinserts that original share. It reports both “same index two digests” and “same share two digests”.
The directed test supplies `[7;64]` twice and asserts both digests in that exact share's release history.

**Precondition:** The second release leaks the key only if the app can obtain and re-put the same share after rollback, for example from the board.
Index reuse with a newly dealt share is a distinct outcome and does not establish nonce reuse.

**Classification:** Spec gap in the unconditional out-of-bound nonce-reuse claim. G2/G3 remains a violation, not an expected G4 event.

**Candidate EARS change:** When an account slot is first reserved, the service SHALL durably record its index or recovery generation outside the rollback domain before release.

## Resolutions in the spec

Spec of record: `veritee/wt-sessions`, change `add-seald-sessions`. Each original trace stays as a test in `tests/regressions.rs`. It fails with the old-rule knob and passes with the fixed rules.

| Question | Resolution | Requirements | Decision | Old-rule knob |
|---|---|---|---|---|
| Q-01, Q-02, Q-03 | The blank-tier-0 fetch takes `w + 1` answers, ignores the owner about its own entries and rebuilds the replicas. At least `w` answers come from non-owners, and at most `f` of them miss a committed version. | SS-102 (amended), SS-126, SS-127 | D-025 | `old_fetch_w_sources`, `old_no_replica_fetch` |
| Q-04 | A loss counts in `c` while it lasts. A lost tier 0 stops counting when its fetch completes. A rollback stops counting for a session when a later version commits. G2 now states this reading. | SS-102, SS-016, design G2 | D-026 | LITERAL reading |
| Q-05 | The fetch moves the replica of each kept entry. With no replica on any peer, the entry still fences, and the next owner checkpoint sends a new record. | SS-126, SS-127 | D-025 | `old_no_replica_fetch` |
| Q-06 | Closed by the restart marker that the spec already holds. The crate now models it. | SS-120 to SS-125 | D-024 | `old_no_restart_marker` |
| Q-07 | One canonical body encoding. The accounted size is its length with free slots at bound size. 10,000 bound Schnorr slots: body 1,070,035 bytes, record 1,070,127 bytes. | SS-134, SS-135, SS-088 | D-029 | none |
| Q-08 | `B` covers the reservations of one checkpoint interval. The committee posts a checkpoint after each `RestoreDone`. Both rules bind the committee application (handoff Q-008). | SS-004, SS-063, SS-067 | D-030 | none |
| Q-09 | A restart generation ends at a checkpoint with a higher `restart_seq` and `w + 1` continuous seats. SS-113 can then fire again. | SS-133 | D-028 | `old_no_restart_rearm` |
| Q-10 | The union is the bound: at most `B` indices and the pending slots for each checkpoint read. Design G3 and "Running nodes" state it. | SS-067, SS-068, SS-104 | D-031 | none |
| Q-11 | A put record on Midnight for each account-pool share. A re-put of a share whose digest is on the ledger returns `slot_used`, under any index. A bind waits for its own record. | SS-128 to SS-132, SS-089, SS-090 | D-027 | `old_no_put_record` |
