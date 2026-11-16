The change does not establish G1–G5 as written. The quorum arithmetic is sound under retained witness history; several recovery paths violate that assumption or leave durable state undefined.

All examples below use seats `N0…N8`, `t = 7`, `w = 6`, and, where applicable, `B = 200`.

| Goal | Verdict |
|---|---|
| G1 | Not established: epoch closure, conflicting records, and incomplete checkpoints can prevent recovery with seven or more live nodes. |
| G2 | The two-round binding protocol is sound under the stated witness-history assumption. Replacement peers do not preserve that assumption: F2. |
| G3 | Not established for newly recreated sessions or without the checkpoint contract changes: F3–F4. |
| G4 | False for coordinated rollback; also broken by the burn retry path: F1–F2, F5. |
| G5 | False literally: one enclave reconstructs the complete session key. A narrower threshold-authorization claim is supportable: F14. |

**F1 — Coordinated rollback resurrects erased entries and shares**

**Severity:** blocking — **decision challenge**, Decisions 2 and 4.  
**Location:** [design][design], Goals, Versions and the witness fence, Reservation window; [spec][spec], SS-016, SS-030–SS-036, SS-046, SS-068, SS-074–SS-075.  
**Claim affected:** G4; witness fence; whole-committee restart.

**Failure scenario:** All disks have a snapshot containing session version 7, entry `a`, and slot 700 bound to a ticket. The committee subsequently burns slot 700 and destroys `a`, committing versions 8 and 9. The latest ledger checkpoint has `h = 1000` and no pending slots. Roll every disk back to the snapshot and obtain new boot tickets. Every peer again reports version 7, and the restored epoch shares derive its key. SS-068 burns 1001–1200, leaving entry `a` and slot 700 untouched. Both secrets become readable again.

A mixed rollback can also succeed: if only one peer retains version 9, a six-peer sync and subsequent quorum can exclude it.

**Fix:** Persist session version floors and deletion commitments outside the rollback domain, and require peers to consult them before serving partials. Otherwise explicitly limit G4 to periods in which sufficient witness history survives. The nonce-window burn cannot provide general cryptographic erasure.

**F2 — Replacement peers forget other seats’ witness history**

**Severity:** blocking.  
**Location:** [spec][spec], SS-003, SS-012–SS-019, SS-030, SS-067, SS-074–SS-077; [witness.rs][witness], `refetch`, `entries_for`; [node.rs][node], `sync_witness`.  
**Claim affected:** G2, G4; witness fence; partial restart.

**Failure scenario:** N0 commits version 8, deleting `a`; N1–N6 acknowledge it. Replace N1–N6 sequentially with blank-disk VMs, repairing each share before replacing the next. Each replacement refetches entries **for its own seat**, not the entries it previously witnessed for N0. It therefore loses N0’s version floor and slot bindings. Post ordinary checkpoints between replacements so their new boot counters become continuous.

Now roll only N0 back to version 7. Its eight peers are continuous relative to the latest checkpoint, so it performs a partial restart. None need retain N0’s version-8 floor. Version 7 opens and restores `a`. The same loss of history permits a second slot digest at the witness layer. Only N0’s operator needs to collude.

**Fix:** “A replacement or forgetful peer SHALL restore the witness state it maintains for other seats before serving witness acknowledgements or session partials.” Define authenticated state transfer and retirement of missing history. Boot-counter continuity alone does not prove retention.

**F3 — A recreated session bypasses the restart burn**

**Severity:** blocking.  
**Location:** [spec][spec], SS-041, SS-048, SS-063–SS-068, SS-098–SS-099.  
**Claim affected:** G3; whole-committee restart from rolled-back disks.

**Failure scenario:** Checkpoint `cp1` contains a pool with `h = 0`. Snapshot all disks before that pool’s session has a record. The committee then installs slot 120, binds it to `d1`, checkpoints, and releases partials. Roll all disks back to the snapshots.

Every node correctly sets `whole_restart = true`, but the session has `v_max = 0`. SS-041 opens an empty session; SS-068 applies only when restoring a session. The app can reinstall the same slot share—for example, by replaying the original encrypted dealing—and bind slot 120 to `d2`. The current window allows it, and all witness entries were lost.

**Fix:** Apply restart retirement to every pool before **either creating or restoring** its session. Persist the burned range independently of whether a session record exists. SS-041 must create the required tombstones before exposing the session.

**F4 — The checkpoint contract rule is missing from the normative requirements and contradicts two other rules**

**Severity:** blocking.  
**Location:** [design][design], “Contract rule for the next checkpoint”; [spec][spec], SS-005, SS-064, SS-067–SS-073.  
**Claim affected:** G3; late boots; checkpoints posted during restart; design/spec consistency.

**Failure scenario:** `cp1.h = 1000`, `cp1.pending = {990}`. After a restart, a checkpoint records the new boot counters but keeps these pool values. No normative requirement requires the contract to reject it; SS-064 merely describes a scenario in which the design’s rule has already been satisfied. A late node sees continuous seats, skips the burn, and can bind restored-free slot 1100.

Even importing the design rule verbatim leaves contradictions:

- If no request reserved anything above 1000, SS-005 defines `h` as 1000, while the contract requires `cp2.h ≥ 1200`.
- With `anchor_before_release = true`, anchored pending slot 990 is supposed to continue. The unconditional contract rule nevertheless requires removing it from `cp2.pending`.

**Fix:** Add normative contract requirements. Define `h` as an allocation/retirement floor that includes burned ranges, require monotonic pool state and verified current boot counters, and apply the forced retirement rule only to the unanchored profile. Explicitly cover checkpoints accepted before every node has restored its sessions.

**F5 — Retrying a failed burn reports durable success without a checkpoint**

**Severity:** blocking.  
**Location:** [spec][spec], SS-057–SS-059, SS-100.  
**Claim affected:** G4; successful-burn semantics.

**Failure scenario:** Version 7 contains slot 120’s share. `slot_burn(120)` changes RAM to `burned`, but its record write fails before any witness message. SS-100 returns `internal`; version 7 remains current. Retrying `slot_burn(120)` takes SS-058 and returns success with version 7, without checkpointing.

Reboot N0. Its peers still hold version 7, which opens with slot 120’s share intact, despite the successful retry.

**Fix:** Track burns awaiting durable commit. “SS-058 SHALL return success without a checkpoint only if the current committed version already records the slot as burned.” Otherwise retry the checkpoint.

**F6 — Local epoch closure can strand other seats**

**Severity:** blocking.  
**Location:** [spec][spec], SS-009–SS-010, SS-078–SS-080.  
**Claim affected:** G1; epochs.

**Failure scenario:** All nine seats hold epoch-5 shares. N0, N1, and N2 rekey their own sessions to epoch 6, then successfully close epoch 5. Each satisfies SS-079 because none of its own sessions uses epoch 5.

Only six epoch-5 shares remain. N3’s epoch-5 session cannot open or rekey, although all nine nodes are live. N3’s own share plus the five other remaining shares is insufficient.

**Fix:** Epoch closure needs a committee-wide retirement condition. “A node SHALL retain its share while any recoverable session or tier-1 state anywhere in the committee requires that epoch.” Bind closure to an authenticated completion barrier, including temporarily offline seats.

**F7 — Epoch accounting ignores locally sealed, uncommitted versions**

**Severity:** blocking.  
**Location:** [design][design], Epochs; [spec][spec], SS-020–SS-024, SS-030, SS-078–SS-080, SS-094.  
**Claim affected:** G1; rekey crash recovery; `epoch_in_use`.

**Failure scenario:** Each node has version 7 in epoch 5. Rekeying seals version 8 under epoch 6 and writes it locally, but no witness message succeeds. The current `epoch` and witness-log epoch remain 5.

`close_epoch(6)` is therefore permitted. If the nodes close epoch 6, no epoch-6 key can be derived. After reboot, SS-030 selects the local version 8 and SS-094 promotes it through witnessing. Opening then fails permanently with `group_unavailable`; the usable epoch-5 version is not a permitted fallback.

Separately, SS-078 enumerates only sessions represented in the witness log, whereas the design says every session. A first locally sealed record with no witness entry is omitted.

**Fix:** Enumerate the union of open sessions, local records, and witnessed records. Epoch-use accounting must include pending checkpoint/rekey records and tier-1 dependencies, not just the epoch of the committed version.

**F8 — The majority-digest rule cannot recover a split version with two unavailable peers**

**Severity:** blocking.  
**Location:** [spec][spec], SS-024–SS-035, SS-094–SS-095.  
**Claim affected:** G1; replication; conflicting records.

**Failure scenario:**

1. N0’s version 6 is current. It seals version 7/A, witnessed only by N1 and N2.
2. Roll N0’s disk back to version 6. Its six-peer sync uses N3–N8, all at version 6.
3. N0 restores version 6 and creates version 7/B. N3–N8 acknowledge B, so B becomes current.
4. N7 and N8 become unavailable. N0 reboots.
5. The six answering peers report A twice and B four times. SS-031 selects B.
6. N1 and N2 must refuse B under SS-095. Only four acknowledgements are obtainable, so SS-035 prevents opening.

Seven nodes are live, only two are unavailable, and only one operator performed rollback. No permitted operation on the closed session advances it past the split version.

**Fix:** Define recovery from competing prepared records, including advancement to a fresh version. Preserve commit certificates or equivalent evidence so recovery can distinguish a committed record from an abandoned candidate. Plurality selection alone does not establish an available write quorum.

**F9 — One incomplete checkpoint can make the committed session unrecoverable**

**Severity:** blocking.  
**Location:** [spec][spec], SS-024–SS-025, SS-030–SS-035.  
**Claim affected:** G1; replication.

**Failure scenario:** Version 7 is committed and widely replicated. A checkpoint of version 8 reaches only N1 and returns `no_quorum`. N0 is subsequently replaced with a blank disk. N1 retains its tier-0 metadata for version 8 but loses its replica.

The sync selects version 8. No copy exists, so SS-034 returns `record_unavailable`, even though the committed version 7 and its required shares remain available on the other peers.

**Fix:** Preserve a recoverable committed head separately from incomplete candidates. Specify how recovery establishes that a candidate never committed before abandoning it. Selecting the highest version reported by any single peer is insufficient for G1.

**F10 — “No checkpoint” is indistinguishable from a failed ledger read in the current interface**

**Severity:** blocking.  
**Location:** [spec][spec], SS-005, SS-067, SS-098; [ledger_file.rs][ledger], `read`, `latest_checkpoint`; [fence.rs][fence], `check`.  
**Claim affected:** G3; restart classification; current-code consistency.

**Failure scenario:** After a complete rollback, all nodes obtain new boot tickets and finish witness sync. At each node’s checkpoint read, a transient file read or parse failure occurs. `FollowerLedger` returns `None`, exactly as it does when no checkpoint exists. Interpreting that as SS-098 freezes `whole_restart = false`.

The snapshot becomes readable again. The real checkpoint has `h = 1000`; restored-free slot 1100 passes the current bind window and can be reused without a burn.

The interface also reads tickets and checkpoints through separate snapshot reads, so it provides no common ledger revision for the continuity calculation.

**Fix:** Distinguish verified absence from unavailable or invalid ledger state. Classify a boot from one coherent finalized snapshot; keep operations `not_ready` until that classification succeeds. Define the freshness condition needed for “latest” boot-ticket checks.

**F11 — Anchor restoration creates a bound slot that can never pass the release check**

**Severity:** blocking.  
**Location:** [spec][spec], SS-055–SS-056, SS-073, SS-092–SS-093.  
**Claim affected:** G1; anchored whole-committee restart.

**Failure scenario:** Slot 1100 is anchored to `d`, but every disk rolls back to a state where the slot is free and its witness entry is absent. SS-073 changes the restored slot to `bound(share,d)`. SS-092 leaves it out of `unsealed`, because the anchor exists.

SS-055 still requires the **local witness log** to map the slot to `d`; it does not. Release is always false. Retrying `slot_bind(1100,d)` takes SS-093, returns success, and leaves the missing witness entry unchanged.

**Fix:** During anchor reconciliation, install the anchored binding into the local witness log and durably record the reconciled session, or expressly make a verified matching anchor satisfy the release predicate.

**F12 — A successful anchor submission does not clear `unsealed`**

**Severity:** major.  
**Location:** [spec][spec], SS-023, SS-051, SS-070–SS-071.  
**Claim affected:** Anchor release behavior.

**Failure scenario:** Binding slot 120 obtains both witness quorums. The anchor is not yet on the ledger, so SS-023 retains index 120 in `unsealed`. SS-070 submits the anchor; it becomes finalized, and `slot_bind` returns success.

No subsequent requirement removes index 120. `slot_release_ok` remains false until an additional bind/checkpoint operation happens to clear it.

**Fix:** “After verifying the exact anchor record in the ledger, the service SHALL remove that slot from `unsealed` before returning successful `slot_bind`.”

**F13 — An unrelated checkpoint can clear a binding it did not seal**

**Severity:** blocking.  
**Location:** [spec][spec], SS-020, SS-023, SS-050–SS-055; [api.rs][api], `serve_app`.  
**Claim affected:** The requirement that release follows a current session version containing the binding.

**Failure scenario:** Connection A seals version 8 while slot 120 is free and waits for acknowledgements. Connection B obtains the slot-witness quorum for `(120,d)`, changes RAM to bound, and adds 120 to `unsealed`, but has not committed its session checkpoint.

A’s acknowledgements now arrive. SS-023 removes **every** non-anchor-waiting index from `unsealed`, including 120. The working copy is bound and its local witness entry matches, so SS-055 returns true. Current version 8 still contains a free slot.

The current API serves connections concurrently; the new requirements specify no session serialization.

**Fix:** Serialize session mutations and checkpoint commits, or associate each pending binding with the particular serialized version containing it. Clear only bindings present in the committed record, and reject obsolete checkpoint completions.

**F14 — G5 contradicts reconstruction of the complete symmetric key**

**Severity:** blocking — **decision challenge**, Decision 3.  
**Location:** [design][design], G5 and Keys; [spec][spec], SS-007, SS-009, SS-011.  
**Claim affected:** G5.

**Failure scenario:** N0 combines seven valid partials and computes `K_sess`. Stop every other enclave immediately afterward. Until N0 erases that key, it alone holds everything required to open the corresponding record. This is normal execution, without a broken enclave.

A compromised authorized recipient can also retain the reconstructed key; subsequent witness refusal cannot revoke it.

**Fix:** State the achievable property: “Deriving a session key requires participation by `t` distinct authorized share holders; the recipient temporarily reconstructs and then erases the key.” If G5 literally forbids any enclave from possessing a complete opening key, the design requires distributed decryption rather than ordinary symmetric-key reconstruction.

**F15 — Re-acknowledgement does not restore a lost replica**

**Severity:** major.  
**Location:** [spec][spec], SS-003, SS-025–SS-026, SS-038–SS-039, SS-101.  
**Claim affected:** Replication; “a peer that acks holds the ciphertext”; storage-failure behavior.

**Failure scenario:** N1 has `(pv=7,pd=A)` but loses its `/mnt/persist` replica while retaining tier 0. N0 resends version 7/A, including the complete record. SS-026 requires N1 to acknowledge and leave state unchanged: it acknowledges without storing the supplied replica.

The same state satisfies SS-038’s `pv > 0` success condition and SS-039’s missing-replica refusal condition.

There is also no transaction rule for replacing the replica successfully and then failing the tier-0 write: SS-101 preserves old metadata, potentially pointing at an overwritten old replica.

**Fix:** Before every acknowledgement, verify or repair the replica from the supplied record and fsync it. Require replica presence for SS-038. Retain the previous record until the corresponding metadata update commits, with defined crash recovery.

**F16 — Moving ciphertext out of tier 0 does not bound the witness log**

**Severity:** major.  
**Location:** [design][design], Sizing; [spec][spec], SS-003, SS-050, SS-059; [witness.rs][witness], `persist`; [committee-mode.md][mode], Sealed persist volume.  
**Claim affected:** Replication sizing; sustained availability.

**Failure scenario:** Eight seats each consume a 10,000-slot pool. A peer can accumulate 80,000 slot witness entries, in addition to its other witness entries and session metadata. The current representation stores committee identifiers, slot identifiers, and digests in JSON and rewrites the whole log atomically. That representation exceeds the 16 MiB partition at this scale; the temporary replacement file requires additional space.

Even a compact representation eventually exhausts the partition because the specification bounds neither the number of sessions nor retained slot entries, and supplies no safe compaction rule.

**Fix:** Specify a storage budget and checkpoint-backed compaction that preserves pending bindings and version floors. Alternatively move the authenticated witness body to appropriately sized storage while retaining a bounded verification structure in tier 0.

**F17 — Legal session records exceed the existing peer transport limit**

**Severity:** major.  
**Location:** [spec][spec], SS-022, SS-040, SS-087–SS-088, SS-091; [api.rs][api], `MAX_LINE`, `serve_lines`.  
**Claim affected:** Checkpoint availability; current-code consistency; error contract.

**Failure scenario:** Set `S_max = 2 MiB`. Put two individually legal 524,288-byte entries into a session. Its ciphertext already exceeds 1 MiB before JSON encoding. SS-022 sends that record in one peer request, but the current peer socket uses the shared 1 MiB `MAX_LINE`.

Every peer rejects the request despite having space and being live. The framing layer emits the app-shaped `too_large` error, rather than a specified peer refusal or SS-101 `unavailable`.

**Fix:** Define bounded framing or chunked transfer for session records, including encoded overhead and responses. Align the transport limit with `S_max`, and specify the peer error for an oversized record.

**F18 — Session persistence does not make a daemon crash restartable**

**Severity:** major.  
**Location:** [design][design], G1; [tpm.rs][tpm], `load_or_create_k_tpm`; [node.rs][node], `Local::unseal`; [committee-signing-mode.md][guide], recommendation 6.  
**Claim affected:** G1; current-code consistency.

**Failure scenario:** `seald` unseals `K_tpm`, caps PCR14, and then crashes. The restarted process attempts to unseal the existing TPM blob under the capped PCR state and fails before it can load tier 0 or open sessions. Repeated process restarts cannot recover it.

**Fix:** Add a protected key-holder process or another explicitly specified crash-recovery mechanism. Otherwise qualify G1: recovery from a daemon crash requires a VM reboot and a new boot ticket.

**F19 — Sparse reservations permanently discard slots outside the advertised burn sets**

**Severity:** major — **decision challenge**, Decision 2’s loss bound.  
**Location:** [design][design], G3 and Reservation window; [spec][spec], SS-005, SS-063–SS-064; [split-line DESIGN][protocol], §4.1.  
**Claim affected:** Pool preservation; the bounded-loss claim.

**Failure scenario:** Starting at `h = 0`, reserve slot 200, complete its request, and checkpoint `h = 200`, pending empty. Slots 1–199 were never reserved, but SS-064 makes all of them unusable.

Repeat with slots 400, 600, 800, and 1000. There are now 995 unused but unusable slots below `h`. A restart additionally burns 1001–1200. The assertion that all slots outside the window and pending set remain usable is false.

**Fix:** Require contiguous allocation and account explicitly for skipped indices, or represent holes sufficiently to distinguish unused slots from retired slots. Otherwise include abandoned gaps in the stated loss model.

**F20 — Mandatory mutations can exceed `S_max`**

**Severity:** major.  
**Location:** [spec][spec], SS-004, SS-051, SS-057, SS-068, SS-088.  
**Claim affected:** The session-size contract; restart availability.

**Failure scenario:** A serialized session is at `S_max` and contains free slot 120. Binding adds its digest, increasing the serialized size, but SS-088 applies only to `session_put` and `slot_put`.

Likewise, a full restored session with no entries for indices 1001–1200 must acquire 200 burned tombstones under SS-068. No defined outcome both respects `S_max` and performs the mandatory burn.

**Fix:** Reserve capacity for binding metadata and mandatory tombstones, or represent burned intervals compactly. Define the size invariant for every transition, not just insertion calls.

**F21 — Opening an already-open, uncheckpointed session has contradictory requirements**

**Severity:** blocking: unimplementable as written.  
**Location:** [spec][spec], SS-041–SS-043.  
**Claim affected:** API state semantics.

**Failure scenario:** Open a new session: `open=true`, `v_max=0`. Put entry `a` without checkpointing. Call `session_open` again.

SS-041 applies because `v_max=0` and requires empty `work`. SS-042 applies because `open=true` and requires preserving `work`. The refusal orders do not resolve conflicting success rules.

**Fix:** Add `open=false` to SS-041’s condition and specify that SS-042 takes precedence over creation and restoration.

**F22 — Two key-derivation statements disagree with the normative behavior**

**Severity:** minor.  
**Location:** [design][design], Keys; [spec][spec], SS-009, SS-021, SS-094.  
**Claim affected:** Design/spec consistency.

**Failure scenario:** First, seal version 8, fsync it, and crash before sending any witness message. SS-021 expressly permits the resulting ciphertext, contradicting “No ciphertext exists under a version that no peer has witnessed.”

Second, a blank-disk replacement without its own share can receive seven valid peer partials. SS-009 permits their combination, while the design says its own partial is included.

**Fix:** Explain future-version access using the actual prepare/commit behavior, including locally durable unwitnessed records. Say the requester’s share counts when available, or explicitly require repair before derivation.

**F23 — Burning slots does not implement request reconciliation or VOID**

**Severity:** major.  
**Location:** [design][design], State classes and Whole-committee restart; [spec][spec], SS-002, SS-036, SS-044, SS-068.  
**Claim affected:** G1/G3 request behavior; design omissions.

**Failure scenario:** A restored session contains an opaque request entry saying request R is `ADMITTED`, with slot 990. `cp_boot.pending` contains 990. SS-068 burns the slot but leaves `work.entries` unchanged. `session_open` succeeds, and `session_get` still returns R as admitted.

No requirement makes the app reconcile R against the board, publish VOID, or retire its other secret entries. An implementation can satisfy all session requirements while leaving R waiting for a release that will never become possible.

**Fix:** Add an application requirement to reconcile restored request caches with authoritative board state and to terminate requests holding restart-burned slots as VOID. Specify the ordering relative to exposing restored request state and enabling releases.

**Required checks found sound, subject to the failures above**

- **Ordinary witness intersection:** Two six-peer acknowledgement sets intersect in at least four peers. With a colluding requester and at most three forgetful peers, a conflicting digest cannot obtain both quorums. SS-050–SS-055 and SS-083 enforce the relevant steps; F2 concerns preserving that history over replacements.
- **Threshold version fence with retained history:** A committed six-peer version floor intersects any subsequent seven-share derivation sufficiently to prevent an older key under the same forgetfulness bound. SS-009 and SS-016 support this. An individual peer that missed the version can still return an old partial; the guarantee is about obtaining enough partials.
- **Superseded boots:** SS-014, SS-019, SS-023, SS-028, and SS-082 exclude superseded requesters and acknowledgements, provided “latest” comes from a trustworthy current ledger view; F10 identifies the missing view contract.
- **Crash between binding rounds:** A free restored slot cannot release under SS-056; SS-054 rejects another digest already present in its witness log. Retrying the same digest can complete SS-050–SS-052.
- **An incomplete binding checkpoint:** SS-051–SS-052 retain `unsealed`, and SS-055–SS-056 deny release until completion, assuming serialized session operations; F13 identifies the concurrency gap.
- **Same-ticket repetition:** With unchanged restored shares, the partial equations in split-line §4.2 and §4.4 are deterministic for the same ticket. Repeating that partial provides no additional independent equation.
- **Coverage of the two burn sets for an existing restored pool:** SS-063–SS-066 restrict new bindings to pending indices or the current window; SS-068 burns both sets, including absent indices. This does not cover creation under SS-041: F3.
- **Continuity arithmetic:** SS-067 correctly classifies eight continuous seats as partial and six as whole; SS-098 handles verified absence of a checkpoint. Neither arithmetic result proves that continuous seats retain historical witness entries.
- **Late boots and differing `cp_boot` values:** If the design’s checkpoint retirement rule is enforced, an early node burns the old window and a late node rejects its restored-free indices through SS-064. A checkpoint posted during recovery must satisfy that rule; F4 identifies its missing and contradictory parts.
- **Replica authenticity and catching up:** SS-025 allows a peer to jump from version 3 to 7; SS-033 checks the selected record digest, and SS-037 rejects failed authentication. These checks establish integrity, not the availability missing in F8–F9 and F15.
- **Cold-start PRF loading:** SS-074–SS-077 and SS-097 support startup without the recovery group when at least seven matching epoch shares remain available, including a late-arriving epoch record.
- **Refusal ordering:** SS-090 and SS-091 provide coherent precedence among their listed refusals. `group_unavailable`, `no_quorum`, `record_unavailable`, `corrupt`, `anchor_pending`, `internal`, and `unavailable` are separately specified operational outcomes, rather than missing refusal entries. The inherited peer framing error is the concrete exception in F17.

[design]: bundle/change/design.md
[spec]: bundle/change/specs/seald-sessions/spec.md
[witness]: bundle/seald/src/witness.rs
[node]: bundle/seald/src/node.rs
[ledger]: bundle/seald/src/ledger_file.rs
[fence]: bundle/seald/src/fence.rs
[api]: bundle/seald/src/api.rs
[tpm]: bundle/seald/src/tpm.rs
[mode]: bundle/docs/committee-mode.md
[guide]: bundle/docs/committee-signing-mode.md
[protocol]: bundle/split-line/DESIGN.md