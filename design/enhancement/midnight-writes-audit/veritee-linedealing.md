# Midnight writes audit: Veritee committee-signing mode, line dealing, split-line dealing

Date: 2026-11-14. Read-only audit. No design, code or loop file was changed.

Owner rule (2026-11-14): no design writes to Midnight per event. Midnight takes one transaction per checkpoint, epoch or batch, with one Merkle root or a few fixed-size fields. Item data stays off-chain and is checked against the root.

Scope:

- A. Veritee `committee-signing-mode` (`~/Projects/veritee/wt-merge`, HEAD `12b51cf`): `docs/committee-signing-mode.md`, `docs/committee-mode.md`, `PR.md`, `README.md`, `server/veritee_verify/README.md`, and the ledger code in `server/seald` and `server/veritee_verify`. The Sessions change is out of scope, because another lane batches it.
- B. `design/SCHEME.md` (line dealing) and `design/enhancement/DESIGN.md` + `DECISIONS.md` (split-line dealing). Item 25 already removes the Sessions put records and the `slot_anchor` (O32) per-slot writes. They are listed in section 4 for completeness only.

Classes:

- **OK**: one write per checkpoint, epoch or rarer, or one write per user request that the user's own transaction carries.
- **PER-EVENT**: the count or the bytes scale with internal events or with the request rate, and a committee party submits the write. Batch it. (No text names who pays Midnight fees; "committee-submitted" below means only that the committee sends the transaction.)
- **UNCLEAR**: the text does not settle whether Midnight is written, or how many bytes.

## 1. Rate basis

DESIGN §11.3 (line 1169) gives the node capacity as "about 160 to 400" requests per second and core at `n = 9`, and "about 95 to 260" at `n = 17`. This is a per-core capacity estimate, not a demand figure. A node with more cores scales it. The rates below use 160 to 400 per second (`n = 9`, one core). For each 60 s checkpoint interval (DESIGN §2.3, line 130) that is 9,600 to 24,000 requests.

DESIGN §11.2 (line 1127) says Midnight makes a block about every 6 s and publishes no finality time. `F_M` stays a symbol here. This audit does not use Midnight transaction size, throughput or fee figures, because no source in scope states them. The only stated Midnight byte figure is DESIGN §11.1 line 1105: `authorize` is a "proof plus about 300 B of public inputs". Every other byte figure is "not stated" unless the table gives a formula.

## 2. Summary table

| # | Site | What is written | Writes per event | Rate at 160 to 400 req/s | Class | Proposed batch |
|---|---|---|---|---|---|---|
| V1 | Veritee boot ticket, `fence.rs:48` via `node.rs:212`, doc lines 168 to 176 | `BootTicket` (committee, index, counter, Ed25519 boot key, PCR4, app root, prev digest) | 1 per VM boot on the normal path; 1 more per 10 s retry if `Node::boot` fails after the submit | per boot; unbounded on the fault path | OK (normal path); **PER-EVENT on the fault path** | record the ticket last in `Node::boot`, or reuse the recorded ticket and boot key on retry |
| V2 | Veritee epoch key set, doc lines 206, 402, rule 3 at line 617 | `EpochKeySet`: `n` `NodeKeys` + `n` PRF commitments | 1 per (committee, epoch) | per epoch | OK; evidence bytes UNCLEAR | store a digest of the evidence, not the bundle |
| V3 | Veritee checkpoint, `ledger.rs:28-41`, rule 4 at line 619 | `Checkpoint{committee, epoch, seq, board_root}`: committee id, two integers and one root, fixed size | 1 per checkpoint | cadence not stated in Veritee (DESIGN: 60 s) | OK | already the batched form |
| V4 | Veritee cold start, doc line 434, rule 5 | `ColdStart{committee, epoch, checkpoint_seq, approvals}` | 1 per whole-committee restart | rare | OK | none |
| V5 | Veritee retire and image registry, rules 6 and 7, recommendation 4 | retire record; approved PCR4, app roots, TCB floors | per retire, per image approval | rare | OK | none |
| V6 | Veritee recommendation 11, doc lines 794 to 798 | "a Midnight record of its witness entry" for each release | 1 per release (if built) | up to 160 to 400/s for a profile that takes it | PER-EVENT (proposal) | seat-log root in the checkpoint, as DESIGN §7.7 line 901 already does |
| V7 | Veritee OS release registry query, `cli/veritee/os_release.py:153-163` | nothing: `query_registry` runs a registry action with `WALLET_SEED`, `WARDEN_WALLET_SEED` and `POINTER_ADMIN_SEED` removed from the environment, and parses the typed result | 0 | 0 | not a write | none |
| V8 | Veritee `register-app`, `README.md` line 47 | the Warden records the DApp registration on Midnight (`veritee-smart-contracts`, not in this repository) | 1 per DApp registration | per registration | OK | none |
| S1 | SCHEME board, line 44 | every board post if the board is a host chain and that chain is Midnight | about `3n` to `4n` posts per request (SCHEME §7) | 36 posts per request at `n = 9`; at DESIGN's capacity figure (SCHEME states no rate): 5,760 to 14,400/s | UNCLEAR (conditional) | exclude Midnight as the board; DESIGN §2.1 already fixes a committee BFT log |
| D1 | `authorize`, DESIGN §5.3 lines 537 to 577 | `auth`, `nf`, `rh`, proof; record to PENDING | 1 per request (user transaction) | 160 to 400/s | OK (user-carried) | O12 batching per Midnight block is optional |
| D2 | `settle(auth, outcome)`, DESIGN §5.6 line 625, §5.9 line 665, §11.6 line 1214 | outcome, `q` signatures, record to successor (change record), or to unspent with new nullifier, or RELEASED | 1 per request, committee-submitted; a reissue adds 1 VOID `settle` for the stalled request and 1 for the new one | 160 to 400/s; 9,600 to 24,000 per interval | **PER-EVENT** | settlement root in the checkpoint, or the `q`-signed settlement carried in the record's next `authorize`, whichever lands first |
| D3 | Board-first relay, DESIGN §5.3 step 5, line 585 | the user's `authorize` call + board QC, sent by the committee | 1 per board-first request, committee-submitted. It replaces D1 for that request and adds nothing to it: a board-first request still costs 2 transactions (relay + `settle`). Do not sum D1, D2 and D3 | up to 160 to 400/s | **PER-EVENT** (it is the committee, not the user, that submits) | relay root per checkpoint |
| D4 | Checkpoint `pending` field, DESIGN §4.1 line 306, §7.13 line 961, §11.6 line 1217 | every slot index of every live request, per committee pool | 1 transaction per 60 s, but bytes grow with live requests | about `4 B · G·L · λ · T_live`: 3.8 MB per checkpoint at 400/s and `T_live` = 600 s | **PER-EVENT (bytes)** | `p_min` per pool (8 B), optional `pending_root`; list on the board. The contract keeps its restart rule as `cp2.p_min > cp1.h + B` |
| D5 | Checkpoint board-first `nf` pending set, DESIGN §5.3 step 3, line 583 | 32-byte nullifier of every ordered board-first call not yet on Midnight | grows with board-first requests in flight | up to 400 · 32 B per second in flight; about 768 KB per checkpoint if relays wait one interval | **PER-EVENT (bytes)** | `nf_root` |
| D6 | Checkpoint, rest of the fields, DESIGN §7.13 line 961 | `seq, epoch, board_height, board_root, witness_root, h, boot_counters, restart_seq, seat_roots, restores` | 1 per 60 s, +1 after each `RestoreDone` | 1,440 per day plus one per node restore | OK | optional: fold the `n` seat roots into one root |
| D7 | Address birth, DESIGN §3.1 step 4, line 188 | shielded asset record, charter commitment, `Γ`, initiator list, pool keys, slot roots, `D_exit`, approvers; P2 hold tag and escrow certificate | 1 per address (user transaction) | per new address | OK (user-carried) | none |
| D8 | ECDSA refill slot roots, DESIGN §11.6 line 1216, DECISIONS line 145 | new `slr_own` (and `slr_G`) + `q` signatures | 1 per refill session; a session serves about 5 P2WPKH spends or 32 Ethereum spends | 0.2 per P2WPKH spend, 0.03 per Ethereum spend | OK (submitter not stated; the session parties start the session) | carry the new root in the next `authorize` |
| D9 | Actor pool keys, DESIGN §2.2 line 85, §3.10 line 273 | a fresh pool-key pseudonym "registered in the shielded charter record" for each pool | 1 per pool refill per actor; one pool of 64 pairs lasts about 2 requests at `N_h = 30` | about 0.47 per request per named non-initiator actor; 0 in the single-user launch form | UNCLEAR (likely PER-EVENT for multi-actor charters) | register a root over a batch of future pool keys |
| D10 | Receive key `U` and `E_c`, DESIGN §3.1 step 1, line 178 | `U` once per charter (shielded); `E_c` "posted", place not named | `U`: 1 per charter; `E_c`: 1 per network-created address | per address | OK (`U`); UNCLEAR (`E_c`) | carry `E_c` inside the birth record (D7) |
| D11 | Node Registry `admitBoot`, `replaceSlot`, `retire`, DESIGN §7.3 line 827, §7.9, §7.10 | boot ticket; slot replacement; retirement | 1 per boot, per replacement, per retire | rare | OK | none |
| D12 | Key Registry, DESIGN §7.5 line 866, §11.6 line 1220 | one `NodeKeys` record with `w` peer acks per node | `n` per epoch | `n` per epoch | OK (per epoch) | one `EpochKeySet` per epoch, as Veritee V2 does |
| D13 | Hold: `revoke` + `SetHold`, DESIGN §5.5 line 602 | revocation of one `auth_id`; tag into the hold accumulator | 1 per hold action (P2 authority) | per authority action | OK | none |
| D14 | Revocation check before release, DESIGN §5.5 line 604 | nothing: a read at a finalized height | 0 | 0 | not a write | none |
| D15 | Hold handle `rh`, DESIGN §5.5 | carried inside `authorize` (D1); trial decryption is off-chain | 0 extra | 0 | not a write | none |
| D16 | Seizure order, DESIGN §5.8 step 1, line 640 | registry order with `D_reg` | 1 per order (P2 authority) | rare | OK | none |
| D17 | `recover(committee_id)` and successor charter, DESIGN §5.8 line 649 | recovery transition | 1 per recovery | rare | OK | none |
| D18 | `coldStart(committee_id)`, DESIGN §7.11 line 944 | record signed by `q` operators | 1 per whole-committee restart through `E` | rare | OK | none |
| D19 | Charters, Image Registry, recovery group keys, guardian set, DESIGN §7.13 lines 958 to 965 | charter fields; image approvals (7 of 9); `E` keys; P2 guardian set, `D_reg`, `PK_H` | 1 per charter, per image, per group change | rare | OK | none |
| D20 | Rotation, DESIGN §8.1 | `ROTATE`, reshare dealings, READY, HANDOVER: all on the board; new nodes then do D11 and D12 | 0 on Midnight beyond D11 and D12 | per rotation | OK | none |
| D21 | Fees | no Midnight fee record found (searched "DUST", "service fee", "protocol fee", "fee" near "Midnight") | 0 | 0 | none found | none |

## 3. Findings in detail

### 3.1 Veritee committee-signing mode (A)

The code has one submit site outside tests. `register_boot` (`server/seald/src/fence.rs:48`) appends one `BootTicket` to the follower outbox (`server/seald/src/ledger_file.rs:84-98`). `Node::boot` (`server/seald/src/node.rs:212`) calls it once.

**V1 is one ticket per VM boot on the normal path, and unbounded on one fault path.** In `server/seald/src/main.rs`, `Local::unseal` (lines 155 to 157) runs before `Node::boot` (line 199). After a crash past the PCR14 cap, every restart that `Restart=on-failure` / `RestartSec=5` makes (`services/veritee-seald.service`) fails at the unseal and records no ticket. Recommendation 6 (doc line 742) still applies, but that path makes no Midnight write.

The fault path is inside `Node::boot` (`server/seald/src/node.rs:210-292`). `register_boot` appends the ticket at line 212. Two later steps can still return an error: `LocalNodeIdentity::generate(...).map_err(NodeError::Memory)?` (key set in locked memory) and `WitnessStore::load(local.tier0.clone())?` (tier-0 witness log). The evidence loop cannot fail, because `main.rs` sets `attest_retries = u32::MAX`. The boot loop in `main.rs` (lines 198 to 208) then calls `Node::boot` again every 10 s, with a new boot key and a new ticket at `boot_counter + 1`. Its comment "Only the ledger submit can fail here ... no ticket was recorded, so retrying is safe" is wrong for these two errors. A persistent `mlock` limit or a corrupt tier-0 witness log therefore writes one ticket every 10 s, 8,640 per day per node, until an operator stops the VM. If the follower lands them, each ticket also advances the counter. Fix: run the fallible local steps before `register_boot`, or keep the boot key and the recorded ticket across retries and submit once. Classify the normal path OK and the fault path PER-EVENT.

The other three record types of `LedgerRecord` (`server/veritee_verify/src/ledger.rs:84-89`) are written by the committee application, which is not in the repository:

- **V2** `EpochKeySet`: one write per (committee, epoch). That is the batched form. Contract rule 3 (doc line 617) says "Each entry has the current boot counter and verified class `0x02` evidence". It does not say whether the evidence bundle is stored. An SNP report with its certificate chain, the HCL report and a TPM quote come to several KB per node. The contract should store only a digest of the evidence, or a verifier signature like the one rule 2 requires for tickets. The class is UNCLEAR for the bytes and OK for the count.
- **V3** `Checkpoint{committee, epoch, seq, board_root}` is fixed size: a 32-byte committee id, two integers and a 32-byte root. It is the form the owner asks for. Veritee does not state a cadence.
- **V4** `ColdStart` is one record with `approvals: Vec<u32>` (at most `n` entries). It is written once per whole-committee restart.

**V6, recommendation 11, is a per-event proposal.** It reads "A release that waits for a Midnight record of its witness entry ... The cost is one Midnight finality for each release". As worded, it is one Midnight record per release. It is an opt-in profile, not built, but the wording breaks the owner rule. DESIGN §7.7 (line 901) already has the batched form. The node appends the `release` entry to its seat log on the board and releases after a checkpoint root covers it, with "no Midnight transaction of its own". Fix: change recommendation 11 to "a release waits until a Midnight checkpoint root covers its witness entry". The latency is up to one checkpoint interval plus `F_M` per release.

The Veritee docs name no other Midnight write. Witness entries, PRF partials and repair stay on the peer channel. The CLI has two Midnight sites. `register-app` makes the Warden record one DApp registration (`README.md` line 47, V8), which is OK. `query_registry` in `cli/veritee/os_release.py` is a read (V7): it strips the wallet seeds from the environment of the registry command.

### 3.2 SCHEME.md, base line dealing (B)

SCHEME.md does not mention Midnight. Every protocol message is a board post. SCHEME line 44 lets the board be "a BFT log run by the committee, or a host chain". If a deployment chose Midnight as that host chain, each request would write about `3n` to `4n` posts (ACK, OBS, PREVOTE, PARTIAL, FINAL; SCHEME §7 counts `4n` posts on the open path and `3n` on the sealed path). At `n = 9` that is about 36 writes per request, or 5,760 to 14,400 per second. Classify S1 as UNCLEAR and conditional. Recommended text: "The board is not Midnight". DESIGN §2.1 already fixes the board as a committee BFT log, so split-line dealing is not affected.

### 3.3 Split-line dealing DESIGN (B)

DESIGN §11.6 already moves puts, bindings, release anchors and boot statements into seat-log roots. Three per-event items remain. The first is a transaction count. The other two are checkpoint fields whose size grows with the request rate.

**D2, `settle`: one committee transaction per request.** §5.6 line 625: "The committee then submits `settle(auth, FINAL)` to Midnight with `q` signatures". VOID, EXPIRED and RELEASED settle the same way, and a reissue adds one more `settle` for its new request (§5.9 line 666). At capacity this is 160 to 400 committee transactions per second and core, or 9,600 to 24,000 per checkpoint interval. This is the main per-event finding.

Proposed batch: the checkpoint carries a `settle_root`. The root is a Merkle root over the leaves `(auth, outcome, successor)` of the requests that ended in the interval. `outcome` is FINAL, VOID or RELEASED. `successor` is the change-record commitment, the fresh-nullifier state, or the pinned input for RELEASED. The `q` checkpoint signers sign it with the other fields. No separate transaction exists.

- The contract treats a record whose `auth` is PENDING as settled once a leaf in a landed `settle_root` names it. The next `authorize` for that record proves membership of its leaf under one of the landed roots. In a shielded design that proof sits inside the `authorize` circuit (statement item 1), so nothing becomes public.
- Latency after FINAL: the next spend of the same asset record waits up to one checkpoint interval (60 s) plus `F_M`. That costs little, because a FINAL request already waited for host-chain confirmation depth.
- Latency after VOID: STALLED, SLOT_TAKEN, restart-burn and revoked requests end VOID with no host confirmation, and the owner needs the fresh nullifier to post again. Today §5.9 item 7 lets the VOID `settle` and the new `authorize` land in one Midnight block. With a root per checkpoint, every reissue waits up to 60 s plus `F_M` more. To remove that cost, the next `authorize` of the record may carry the `q`-signed settlement of the previous request itself (the VOID posts or the FINAL votes are already `q`-signed on the board). The contract, or the `authorize` circuit, checks the `q` signatures, at `q = 6` Ed25519 checks. The settlement then counts from whichever lands first: that `authorize` or the next `settle_root`. The settlement goes in the user's own transaction, and the committee submits nothing per request.
- Data availability: the leaves stay on the board, and each wallet keeps its own leaf and path. Nodes and `E` archive the board up to each landed root. A wallet that lost its path asks any node for it and checks it against the root on Midnight. Board loss past the last landed root loses only unsettled leaves, which the next checkpoint settles again from the board state of the replaying nodes.
- Nullifier rule: if the contract must insert the successor's nullifier or commitment into a global set, it inserts one subtree root per checkpoint, not one leaf per request. The contract must accept a commitment tree of roots. This is a contract design question for `FenrirAssets` (§14.3).
- RELEASED lock: the leaf carries the pinned input, so a later `authorize` must spend it. That keeps decision 47.

**D3, board-first relay: one committee transaction per board-first request.** §5.3 step 5 (line 585): "The committee relays the call to Midnight with the QC of the block that ordered it." The authorization is already in force by board order (step 4), so the relay does not gate any release. It can be batched without any latency on the request path.

Proposed batch: the checkpoint carries `bf_root`, a root over the `(auth, nf, rh, proved-against root)` tuples of the board-first calls ordered in the interval, with the QC of their blocks. Two costs:

- The contract cannot reject a duplicate `nf` inside the batch by itself. The board already refuses a second verified call per `nf` (step 3), and the `q` signers check it before they sign. For board-first charters the single-spend rule then rests on the board and the checkpoint quorum, not on a Midnight nullifier insert. That is the same trust that board-first already accepts. If a Midnight-side nullifier set is required, it takes one subtree root per checkpoint, not one insert per call.
- The root-age bound of step 2 must allow for the relay delay. It becomes "one checkpoint interval plus `F_M`" instead of one relay.

**D4, checkpoint `pending`: item data in a per-interval transaction.** §4.1 line 306: each checkpoint records, per committee pool, "the **pending** indices: the slots of every request that is live at the checkpoint". It is one transaction per 60 s, but its bytes are about

`size ≈ 4 B (index ℓ) · G·L slots per request · request rate · T_live`.

At `G·L = 4`, 400 requests per second and a request lifetime `T_live` of 600 s, this is 960,000 indices, about 3.8 MB per checkpoint. At `T_live` = 3,600 s (Bitcoin at confirmation depth) it is about 23 MB. DESIGN does not state `T_live`. The field is item data on Midnight, and its size grows with the request rate, so it breaks the owner rule.

Proposed batch: replace the list with `p_min`, the lowest pending index of each pool (8 bytes; empty pending set = `h + 1`). The list stays on the board, under the board root that the checkpoint already carries. An optional `pending_root` over the sorted list lets a node check a board copy, but the safety rules below do not need it.

Why `p_min` alone is enough. Indices are reserved in increasing order, and every pending index is at or below `h`. An index at or below `h` that is not pending can never bind (§4.1: it was reserved, skipped or burned). So the restart burn of §7.11, "every index in `(h, h + B]` and every pending index", has the same effect as burning the whole range `[p_min, h + B]`. Burning the non-pending indices in that range costs nothing, because they were already dead.

The contract keeps its rule with fixed-size fields. §7.13 line 968 refuses, after a restart, a `cp2` with `cp2.h < cp1.h + B`, or whose pending set meets `cp1.pending` or `(cp1.h, cp1.h + B]`. Because `cp1.pending ⊆ [cp1.p_min, cp1.h]`, both pending conditions together say that `cp2.pending` must avoid `[cp1.p_min, cp1.h + B]`. Every index reserved after the burn lies above `cp1.h + B`, so the rule becomes `cp2.h ≥ cp1.h + B` and `cp2.p_min > cp1.h + B`. The contract reads two integers per pool. This keeps the property that DESIGN line 895 and DECISIONS line 192 rest on: the burns hold after a rollback of every disk, because Midnight enforces them, and seald cannot (line 968). A form that moved the disjointness check to the `q` checkpoint signers would weaken exactly that case. This form does not move it.

Costs:

- A slot whose request is live keeps `p_min` low until that request ends. A restart then burns every index from that slot upward, including indices that later requests used and released. Those indices were already dead, so no live slot is lost beyond what DESIGN burns today.
- `E` (§7.11 item 2) concerns ECDSA account pools, which have no floor or pending set on Midnight. It is not affected.
- Board-side vote rule (§4.1): a header may name "pending indices of its own request" at or below `h`. A node checks this against the board, as it does today. Midnight never checked it.

**D5, checkpoint `nf` pending set (board-first).** §5.3 step 3 (line 583): "The pending set is part of every Midnight checkpoint." It holds 32 bytes per board-first call that is ordered but not yet on Midnight. With D3 batched, a call stays pending for one interval, about 768 KB per checkpoint at 400 per second. Replace it with `nf_root` over the same set. With D3 in the form above, `bf_root` and `nf_root` are one root.

**D9, actor pool keys (UNCLEAR, probably per-event).** §2.2 line 85: the pool key is "a pseudonym registered in the shielded charter record". §3.10: the key is "a fresh pseudonym per pool", and a pool holds `N_pool = 64` pairs while a request takes `N_h = 30` pairs per named actor. If each new pool key needs a Midnight registration, a multi-actor charter writes about 0.47 times per request for each named non-initiator actor. The launch single-user form writes nothing, because the initiator uses fresh nonces and no pool. The text does not say whether a refill writes Midnight. Proposed fix: the actor registers once a Merkle root over a batch of future pool keys, for example 1,024 keys, in the shielded record. Each pool post carries the key, and `authorize` proves membership in zero knowledge, so the pseudonyms stay unlinkable. The actor writes one root per batch of pools.

**D8, ECDSA refill slot roots.** One record update per refill session (DECISIONS line 145: "Refill sessions update the root on Midnight"). A session serves about five P2WPKH spends or 32 Ethereum spends of one address. The session parties start it, so it is user-carried and OK. Better: carry the new `slr_own` with its `q` signatures in the next `authorize` of that record, which updates the record anyway. That removes the separate transaction.

**D10, `E_c`.** §3.1 step 1: "A creator ... posts `E_c = e_c·G` encrypted to the holder". The text does not name where. If the post goes to Midnight, it is one write per network-created address, the same rate as birth. Carry it in the birth record (D7) and say so.

**D12, Key Registry.** `n` records per epoch (§7.5 line 866, §11.6 line 1220), each with `w` peer acks. This is per epoch, so OK. Veritee (V2) writes one `EpochKeySet` per epoch. Align DESIGN to one record per epoch with a `keylist_hash`. That saves `n − 1` transactions per epoch.

**D6, fixed checkpoint fields.** `seat_roots` is `n` × 32 B (288 B at `n = 9`, 544 B at `n = 17`), `boot_counters` is `n` × 8 B, and `restores` holds at most `n` statements per restart. All of these are bounded by `n` and do not grow with the request rate, so they are OK. One root over the seat roots would bring the checkpoint to "a few fixed-size fields". The cost is that a seat-log check then needs one more path level.

**Reads that are not writes.** The revocation check before release (§5.5 line 604), the boot ticket check at admission (§7.3 step 5), and the reads of `EKS_e`, charters and checkpoints write nothing.

**Fee generation 2.** It makes no Midnight write. Its OBS set is a board commit (§11.2), and the request settles once.

**Reissue count in §11.6.** The row "Reissue of a stalled request | 1 more `authorize`, then the one `settle` of the new request" (line 1215) leaves out the VOID `settle` of the stalled request, which §5.9 item 6 requires ("The committee settles the authorization as VOID"). A reissue today costs 2 `authorize` and 2 `settle` in total.

**Change addresses.** These make no separate write. §5.6 line 625 moves the record "to its successor state (the change record if any)" inside `settle`, so it rides on D2 and its batched form.

## 4. Items already being changed by other lanes

These are listed for completeness only.

- Sessions put records: Veritee `add-seald-sessions` SS-070 to SS-073, SS-105, SS-128 to SS-132. DESIGN §7.4 line 856 already says the seat log replaces them.
- `slot_anchor` (O32), DESIGN §4.1 line 310 and §12 line 1262; seald `anchor_before_release`. DESIGN states "no Midnight transaction per slot", and the latency is one checkpoint interval plus `F_M` per generation.

## 5. Stale per-event wording to correct

These lines contradict the batched design and could lead a reader or a lane to build per-event writes:

- DECISIONS entry 14 (line 25): "Midnight finality before every output (Astra) is a high-value profile". Say "a checkpoint root covers the release entry before output".
- DECISIONS entry 42 option (c) (line 89): "anchor the slot-to-ticket entry on Midnight before release ... at one Midnight finality per generation". Say "seat-log entry covered by a checkpoint root" (O32 form).
- DECISIONS line 185: "A put record on Midnight stops a second put of one share". This is superseded by the seat log (DESIGN line 856). The Sessions lane owns this line.
- DECISIONS line 98, option (b): "a Midnight record per ECDSA slot". It is a rejected option, so it needs no change. Keep it rejected.
- Veritee `docs/committee-signing-mode.md` recommendation 11 (lines 794 to 798), see V6.
- DESIGN §11.6 row "Spend request | 2: `authorize` ..., `settle` by the committee" (line 1214). It must change with D2.

## 6. Recommended changes, in priority order

1. D2: replace the per-request `settle` with `settle_root` in the checkpoint. The record's next `authorize` may also carry the `q`-signed settlement, so a reissue does not wait for a checkpoint. This removes 160 to 400 committee transactions per second and core.
2. V1 fault path: make `Node::boot` record the ticket only after its fallible local steps, so a retry loop cannot write one ticket every 10 s.
3. D4 and D5: replace the `pending` list with `p_min` per pool, and rewrite the line-968 restart rule as `cp2.h ≥ cp1.h + B` and `cp2.p_min > cp1.h + B`. Replace the `nf` pending set with `nf_root`. This removes megabytes of item data per checkpoint, and the contract still enforces the restart rule.
4. D3: batch board-first relays into `bf_root` per checkpoint.
5. V6: reword Veritee recommendation 11 to the checkpoint-root form.
6. D9, D10: state where pool keys and `E_c` are written. Register pool keys as a root over a batch of future keys, and carry `E_c` in the birth record.
7. D12 and D8: one Key Registry record per epoch; carry refill slot roots in the next `authorize`.
8. S1: state in SCHEME.md that the board is not Midnight.
9. V2: store an evidence digest, not the evidence bundle, in the epoch key set.

After these changes, the committee writes one checkpoint per 60 s with fixed-size fields, one key set per epoch, and one record per boot, restart, retire or recovery. The writes that scale with requests are the user's own `authorize` transactions, one per request, plus their birth and refill records.
