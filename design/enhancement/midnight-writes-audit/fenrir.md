# Fenrir: Midnight writes audit

Date: 2026-11-14. Read-only audit. No Fenrir design file, contract, code or loop file was changed.

Owner rule (2026-11-14): no design writes to Midnight per event. A design commits per checkpoint, epoch or batch (one Merkle root or a few fixed-size fields), keeps item data off-chain and checks it against the root.

Scope: `~/Projects/projectfenrir`: StrawAnchor Compact contracts, rollup module specs, PROPOSED-DESIGN, sequencer, recursion, integration, FeesAndMarketplace, dao and the in-repo `proforma/`. Also `~/Projects/fenrir-proforma`. Its `proforma/model` and `engine/src` are byte-identical to the in-repo copy (`diff -rq` gives no output). The canon `design/ASSET-INGRESS-CUSTODY-EGRESS-CONTROL.md` is byte-identical to the FeesAndMarketplace copy. Seizure, freeze and hold are a per-charter profile, so this audit counts none of them as a protocol write.

Repository paths below are relative to `~/Projects/projectfenrir` unless they start with `~`.

## Design of record and throughput basis

- Fenrir is a validium that settles on Midnight through the StrawAnchor contract (README.md sections 7 and 8). Its data is on Celestia.
- A header covers 6 s and a batch is up to 50 headers, about 5 minutes (README.md:424). That gives 14,400 headers and about 288 batches a day (CELESTIA-AUTH.md:67 uses the same 14,400 a day).
- The settled rate at launch is 100 TPS, about 30,000 transactions per 50-header batch (README.md:505-509), so about 8.64 million L2 transactions a day.
- Contracts of record: `contracts/strawanchor/{bundle,lifecycle,liveness,validity}.compact`, `contracts/strawanchor/da/da.compact` and `contracts/rollup/cel/cel.compact`, a pre-seal test contract.
- Module specs: `design/rollup/modules/{VALIDITY,LIVENESS-EXIT,CELESTIA-AUTH,DA-PROOF,LIFECYCLE}.md`. Planning parameters: `formal/rollup/lean/FenrirRollup/Defs/Params.lean`.

## Summary

The settlement path itself is batched: one accept, one DA accept and one settle per batch. One per-event write sits on the core rollup path: **header anchoring**. Every 6 s header gets its own on-chain record `H_at[h]` and its own Celestia pointer `ptr_at[h]`, which is 14,400 records of each kind a day. Today that is up to 14,400 anchor transactions a day, because PROPOSED-DESIGN ID-97 sends one `anchor_header` per header and the contract caps a range at 4 headers. The Sovereign Signature `respond` path adds one operator-paid Midnight write per foreign operation. The financial model has no per-batch settle or anchor cost line at all, and it prices Midnight DUST per user or covenant event for many L2-internal kinds.

## Table

Class key: **OK** means the write happens per checkpoint, epoch or batch or more rarely, or it is one write per user transaction the user pays for anyway. **PER-EVENT** means the write scales with internal events. **UNCLEAR** means the write location or rate is not pinned.

| # | Site (file:line) | What is written | Trigger, writes per event | Bytes | Rate at stated throughput | Class |
|---|---|---|---|---|---|---|
| 1 | `contracts/strawanchor/validity.compact:153-200` (`anchorRange`; per-header inserts :179, :192); VALIDITY.md:59 (V1); PROPOSED-DESIGN.md:1380 (ID-97, "header duty seat for header h ... U6 submits `SettlementPort::anchor_header`"); README.md:376, :542 | One `H_at[h]` record per header (`HRec`: acc, snap, atime, ep, synth, delta, fdac, has_fdac), a second write to `H_at[h-1]` that sets its fdac, three running chain fields, and the window entries `ws/dws/drain_time/rot_win` at a new window. One aggregate signature is checked per call. | Per header: about 2 map writes. Transactions: one per header (ID-97), or one per range of at most K_ANC headers. | About 120 B per HRec (computed from the struct; the spec does not state it). Call data is one 5-field preimage per header. | 14,400 HRec a day. Transactions: 14,400 a day (ID-97), at least 3,600 a day at the contract's K = 4, or at least 150 a day at the Lean planning K = 96 (Params.lean:213). | **PER-EVENT** |
| 2 | CELESTIA-AUTH.md:41 (O4 `admitPointer`); `validity.compact:178` (`celAdmitPointer`); INTERFACES.md:44 (IF-CEL-DA-3) | One `ptr_at[h]` per header (delta digest, cel_height, ns, share_start, share_len) | Per header, inside the anchor call | Not stated | 14,400 a day | **PER-EVENT** (goes with #1) |
| 3 | `validity.compact:206-215` (`acceptValidity`); README.md:542-551 | Statement hash in `v_ok[k]`, after Ledger 9 verifies the 6,432-byte decider proof | Per batch: 1 transaction (pipeline window W_PIPE = 2) | Transaction 10 to 12 KB (`recursion/stagenet-strawman/STRAWMAN.md:377`) | About 288 a day | OK |
| 4 | `da/da.compact:30-37` (`acceptDa`); DA-PROOF.md:73 | `stmt_da` in `da_ok[k]` after the DAD decider | Per batch: 1 transaction | Not stated | About 288 a day | OK |
| 5 | `validity.compact:232-325` (`settleValidity`), `:299` (`v_settled.insert`); `liveness.compact:239-320` (`settleBatch`, `:315` `settled_gen`) | New state digest, height, batch_no, settled statement, settled generation, cursors, `wd_roots[k]` (spec V4 step 9) | Per batch: 1 transaction | Transaction 11 to 14 KB (STRAWMAN.md:378). The `v_settled` set grows by 32 B a batch and is never pruned. | About 288 a day | OK |
| 6 | `rollup/cel/cel.compact:92-128` (`acceptLC`, `advanceCelestiaLC`); CELESTIA-AUTH.md:65-67; README.md:565 | Light-client header (`lc_hdr`, `lc_next`, `lc_top`) | Time-driven: 2 transactions per append, one append every ADV_PERIOD of 20 min. Each of the 16 seats runs an advancer. | Header: 3 x 32 B + 2 x 8 B fields | 114 transactions a day as the stated floor (CELESTIA-AUTH.md:67). 144 a day at a 20 min period. Up to 16 times that if the seats race. | OK (traffic does not change it). The redundant race should be removed. |
| 7 | README.md:621; PROPOSED-DESIGN.md:45, :373 (ID-37 step 5), :1018 (ID-73), :1473 (ID-115) | `SettlementPort::respond`: the execution attestation under the threshold `obs` key answers `respondBidirectional` on the Midnight custody singleton. Operator U6 pays. | Per foreign operation that started as a Midnight request: 1 transaction | Not stated | Not stated (the design gives no foreign-operation rate) | **PER-EVENT** |
| 8 | PROPOSED-DESIGN.md:1384-1386 (ID-99) | Committee-signed call to the Compact custody singleton `(contract_address, custody_nonce)` | Per Midnight-side custody operation | Not stated | Not stated | UNCLEAR. It is the value movement itself; it becomes OK if the singleton pays out against a settled root. |
| 9 | `liveness.compact:161-170` (`escape`), `:185-194` (`claim`), `:198-213` (`enqueueForced` behind `forced_enqueue_v2`); LIVENESS-EXIT.md:80, 85, 116, 125, 134; SEALED-FORCED.md:100-101 | Escape-set key and accumulator, claim key, forced due time and FENC counter, deposit | Per user exit, deposit or forced request, paid by the user. `refundDeposit` during an escape may be called by anyone. | The `claimed` and `escape_set` sets are never pruned (by design, P-LIV-26) | Scales with users; each is an L1 crossing | OK |
| 10 | `liveness.compact:141`, `:173`; `da.compact:63-66` (`acceptDaMiss`); `lifecycle.compact:240`, `:273` (`propose`, `activate`); `cel.compact:189` | Escape window, DA miss, rotation and light-client reset | Per incident or rotation | Not stated | Rare | OK |
| 11 | PROPOSED-DESIGN.md:899-907 (ID-57, ID-58), :1028, :1041; FENRIR-CONSTITUTION.md:90 (I12); dao/GOVERNANCE-ACTIONS.md:18-20 | Roster and manifest hashes (inside settle), seat auction bids, bonds, insurance pool, slashing by fraud proof, DAO proposal commitment | Per epoch, seat, fault or proposal | Not stated | Rare | OK |
| 12 | README.md:58 (roadmap 4, "nullifier uniqueness enforced on chain"); NULLIFIER-DECISION.md:287 (NF-013) | Nullifiers stay in L2 scopes, and only `nf_root` goes into the settled S5 digest | Per batch | None extra | 0 extra | OK. The README wording should read "enforced in the settled root". |
| 13 | `recursion/stagenet-strawman/brainstorm-l9/CONVERGED.md:10, 47` (A2) | Each wallet proof is its own ledger call that registers its hash (16 per batch) | Per L2 transaction | About 3.2 DUST more per batch (stated) | About the transaction rate | **PER-EVENT**, superseded by the recursion tree (README.md section 7) but not marked superseded |
| 14 | design/ASSET-INGRESS-CUSTODY-EGRESS-CONTROL.md:107, :302 (AIC-302), :340-341; FENRIR-CONSTITUTION.md:148 (T7); `~/Projects/fenrir-proforma/FeesAndMarketplace/design/PATTERNS.md:28-29` | Custody mode: the coin moves onto Midnight's private pool as a shielded representation (construction OPEN, OBL-20) | Peg-in and peg-out: 1 per user crossing. Internal custody transfers, conversions and policy moves: 1 each if the pool is Midnight Zswap. | Not stated | Not stated (the proforma assumes 2 transfers per account-month) | Peg-in and peg-out: OK. Internal moves: **PER-EVENT** |
| 15 | design/ASSET-INGRESS-CUSTODY-EGRESS-CONTROL.md:343 (AIC-301); FeesAndMarketplace/design/paper/paper.tex:360; `~/Projects/fenrir-proforma/FeesAndMarketplace/design/VPN-TIERS-SPEC.md:26, :63` | Private-transfer pool: "Midnight holds commitments, nullifiers and aggregate accounting" (verifier of record OPEN) | 1 commitment per entry, 1 nullifier per exit or refund | Not stated | 2 per pool transfer | **PER-EVENT** if Midnight is chosen |
| 16 | FeesAndMarketplace/design/value-flows.html:500; design/ASSET-INGRESS-CUSTODY-EGRESS-CONTROL.md:108, :553, :555 (AIC-620); dao/research/gemini-consensus.md:16 | Dead-man-switch heartbeat per signing domain every `P_hb` blocks, missed-heartbeat slashing, lock-batch secrets per account per epoch | Per domain per period; per account per epoch | Not stated | Not stated (`P_hb` is unset) | UNCLEAR. OK as an L2 record; the diagram draws it on Midnight. |
| 17 | design/ASSET-INGRESS-CUSTODY-EGRESS-CONTROL.md:471 (AIC-513); PROPOSED-DESIGN.md:888 (ID-55, "verifiable from Midnight") | Admission ticket issuance and burn | 1 per admitted envelope | Not stated | Up to 8.64 million a day if it is on Midnight | UNCLEAR (location not stated) |
| 18 | dao/research/codex-tooling.md:27-33; dao/research/agy-precedents.md:28; dao/research/agy-security.md:10 | Compact voting circuit: one nullifier plus choice per ballot | Per voter per proposal | Not stated | Scales with voters | UNCLEAR. Voters pay, but the cost scales with turnout. |
| 19 | dao/CURRENT-FINANCIAL-DIRECTION.md:34-39 | Operator rewards "linked to finalized blocks, batches or verified useful work" | Payout cadence not stated | Not stated | Not stated | UNCLEAR |

No Midnight write was found in the sequencer code. `sequencer/crates/gw-midnight/src/gateway.rs:571-573` returns `Unsupported` for `broadcast`, and `SettlementPort` only reads (`:583`). FSYS records, `StateDigestVote`, observations, watcher alarms, key loss, DKG and reshare all stay in the SYSTEM lane of the log (README.md:325; PROPOSED-DESIGN.md:355). ONCHAIN-FREEZE checkpoint imports run on Ethereum and Solana and read Midnight, so they are not Midnight writes. Prepaid fee notes are L2 state (PREPAID-CREDIT-DESIGN.md:75, :154, :292).

## Proposed batched forms

### #1 and #2: anchor ranges, not headers

Anchor once per checkpoint: once per batch, or at most once every N headers, with N bounded by `SNAP_LAG_MAX` = 1,800 s (Params.lean:206), so N ≤ 300.

- **What one anchor call writes.** A fixed set of fields: `h_to`, `hdr_acc_to`, `snap_chain_to`, `fdac_chain_to`, `atime`, and one Poseidon root `hdr_root` over the per-header tuples `(pz_hdr_digest, snap_time, delta, fdac, ptr)`. Window entries are written only for the first header of a new window, at most once per checkpoint.
- **Where the item data goes.** The tuples go to Celestia under the existing `Headers` namespace, where FHDR is already published, and to the archive tier.
- **What changes in the readers.**
  - `settleValidity` already needs `H_at` only at the two ends of the range (VALIDITY V4 step 4; `validity.compact:265-280`). The check that each interior header is retained and not synthetic is replaced by the range chains.
  - DAD (`daLock`) and DMD take `hdr_root` as a statement input and open the pointers inside the decider.
  - `admitDaMiss` and the escape's `anchorTimeAt(h)` take a Merkle path to `hdr_root`.
  - The `admitPointer` order checks (P-CEL-8) move into the range fold, or run over the opened leaves.
- **Costs.**
  - The ANCHORED level moves from about 6 s + T_final (≤ 144 s) to the checkpoint period + T_final, about 5 min + 144 s at a 50-header checkpoint.
  - Signing cells that release at ANCHORED under the exposure cap (README.md:557; VALIDITY V8) wait that long. So does `ROSTER_EPOCH` activation (ID-57).
  - Interior headers now depend on Celestia or the archive to serve the tuples for a miss or an escape proof. Today they are read from Midnight state.
- **Writes after the change.** 288 anchor transactions a day with a fixed record each, in place of 14,400 records and up to 14,400 transactions. The anchor can also ride in the settle transaction of the previous batch, which gives 288 transactions for both.
- **Contradiction found.** P-VAL-26 requires `K_ANC_MAX x 6 s ≥ 1.5 (T_prove + T_incl + T_final)`. At planning values (180 + 60 + 144 = 384 s) that needs K ≥ 96 (Params.lean:208-213). But `validity.compact:67` caps K at `VAL_H_ARR = 4`, and its init check `4K ≥ T_prove + T_incl + T_final` (`:94`) then fails for the planning file. PROPOSED-DESIGN ID-97 still describes one `anchor_header` per header. The design and the contract must agree on range anchoring before the anchor format is batched.

### #6: one advancer duty per period

Give the append duty to one seat per period (`period mod 16`, with the ID-34 ladder), and count a batch's own append, as CELESTIA-AUTH.md:67 already allows. The total then stays near 114 to 144 transactions a day, not that many per seat.

### #7 and #8: Sovereign Signature responses and custody payouts

- Fold each execution attestation into the settled statement. `sign_fold_root` already carries the signing authorizations (README.md:405), so a leaf `(request_id, attestation)` goes into the same root, or into a sibling root in `S5`.
- The singleton exposes `respond(batch_no, idx, attestation, path)` against `settled_record[b]`. The requester pulls the response and pays for it, as `claim` does against `wd_roots`.
- The in-circuit check of the `obs` signature (ID-73) moves into the leaf circuit.
- Midnight-side custody payouts (ID-99) pay against a per-batch authorization root in the same way.
- Cost: the response and the payout wait for SETTLED, about 5 min plus proving, instead of FOREIGN_FINAL or ANCHORED.

### #13: mark A2 superseded

Mark `CONVERGED.md` A2 as superseded by the recursion tree, so no later lane revives per-proof ledger calls.

### #14 and #15: custody pool and private-transfer pool

- Custody notes and pool commitments and nullifiers live in Fenrir L2 trees.
- Each Fenrir batch statement carries the pool roots and one supply field `M_a` per asset.
- Only peg-in and peg-out touch Midnight, and the user pays for each.
- Pool exits reach Midnight finality at SETTLED, which is inside the pool's existing delay window (VPN-TIERS-SPEC.md:28).
- Pin this before OBL-20 closes.

### #16 to #19

- **Heartbeats.** A field in the header or batch statement, with `P_hb` ≥ the batch interval and `N_sil` greater than the batch latency.
- **Lock batches.** One root per epoch.
- **Admission tickets.** A spent-serial set in L2 with its root per batch, and one issuance root per credential epoch.
- **DAO ballots.** Signed off-chain, as `dao/research/gemini-night.md:78` already recommends. Per proposal, one tally root, one ZK tally proof and one timelocked execution go on chain.
- **Operator rewards.** Accrue in L2, with one reward root per epoch that operators claim against.
- **Liveness slashing.** Only with a proof over the aggregated heartbeats, never from per-heartbeat posts.

## Proforma (`proforma/`, identical in `~/Projects/fenrir-proforma/proforma/`)

The model prices Midnight as DUST per action, multiplied by event counts. It never prices per-batch settlement.

| Site | Formula | Per-event count assumed | Class |
|---|---|---|---|
| `model/params.json:16286-16458` `midnight.dust_per_action.*` (19 kinds, values null, note "once per action"); MODEL-DETAIL.md:66-67 | DUST per Midnight action | 1 L1 action per event | **PER-EVENT** structure (unpriced, so it contributes $0 today) |
| `model/capacity.py:41-46` `action_cost` | `units x count x USD/DUST` (+ `base_price x count` under `exchange_quote`) | count = events | **PER-EVENT** |
| `model/economics.py:85-86, :212-216, :235-239` | One "DUST action" row per user event: entry and exit settlement, mint, redeem, conversion, mirror, ethereum_events, leverage swap and liquidation | 1 per event | Entry and exit: OK (L1 crossings). The rest: **PER-EVENT** |
| `model/economics.py:251-259` `policy_rows`; `model/model.py:550-554` | "Midnight policy transfer" row plus a DUST row on chain `midnight` | 1 per custody transfer, `tx_per_account_month` = 2 (`params.json:1949, :2016`) | **PER-EVENT** while custody moves are Midnight transactions (see #14) |
| `model/economics.py:491-510` `l3_rows`; `model/model.py:588-591` | L3 settlement DUST x accounts per month; L3 deposit DUST x entries | 1 per account-month; 1 per deposit | Settlement: **PER-EVENT** (should be per L3 batch). Deposit: OK |
| `model/markets.py:74`; `flows/exocovenant-layer.md:7` ("the cost of appending to the skein on Midnight") | Overlay base = DUST/action x n over 16 covenant kinds (compose, register, bind, admission per effect, encumber, skein_append, signing, ...) | 1 per covenant event (defaults off, drivers null) | **PER-EVENT** |
| `model/capacity.py:37` | Fenrir-owned "heartbeats/reconciliation/unattributable skein appends" | Quantity None | UNCLEAR. It implies Fenrir posts heartbeats and skein appends to Midnight. |
| `model/costbuild.py:17, :48-49`; `params.json:2812` `costs.catalogue.midnight_capacity` = $0.1496 per action; COSTS.md:24 | `midnight_actions = total['dust_actions']`, the sum of the event counts above | Per event | **PER-EVENT** |
| `params.json:29292` `network_capital...midnight.classes.custody_transfer.gas_usd_per_transaction` = $0.01; `engine/src/network_capital.rs:187`; `data/network-capital.json:1607-1616`; NATIVE-CAPITAL-MODEL.md:95 | Cost-plus fee per "distinct encumbered transaction on Midnight", 20% of MAU x 2 a month | 1 Midnight transaction per custody transfer | **PER-EVENT** |
| `engine/src/costbuild_typed.rs:363-369`; `engine/src/finance.rs:420-422, :1053`; `engine/src/routes.rs:1279, :1578, :2131, :2146` | Rust port of the same drivers | Same | **PER-EVENT** (mirror) |
| `params.json:2821` `settlement_da`; `costbuild.py:17` `da_transactions = transactions` | One Celestia transaction per user transaction ("batching and settlement fees unknown") | 1 per transaction | PER-EVENT (Celestia, not Midnight) |
| `params.json:2830` `proof_verification`; `costbuild.py:18`; `params.json:3824` `proofs_per_transaction` = 1 | One Ethereum Groth16 verification per transaction, "no batching" | 1 per transaction | PER-EVENT (host chain) |
| `model/verification.py:22-29` | Light-client updates, `days x 24 / update_interval_hours` | Per checkpoint (Midnight zeroed at :7, :14, :25) | OK |
| **Missing** | No line for the per-batch StrawAnchor accept, DA accept and settle, the anchor transactions or the Celestia light-client appends | n/a | GAP |

Model volume: `model/results.json` `base.capacity.action_count` gives 7,302 Midnight actions in month 1, 906,352 in month 12 and 3,045,100 in month 60. Under the batched design the Midnight count is fixed by time, not by volume:

- about 288 batches a day x 3 transactions (accept, DA accept, settle), plus 288 anchors (or 0 if the anchor rides in the settle);
- 114 to 144 light-client transactions;
- user-paid L1 crossings (deposit, claim, forced request, escape) on the user's bill.

That is about 1,300 to 1,600 transactions a day, or 40,000 to 48,000 a month, whatever the volume.

Proposed proforma change:

- Replace `dust_per_action x event_count` for the L2-internal kinds with `DUST_settle x batches + DUST_anchor x checkpoints + DUST_lc x appends`, a fixed operator cost.
- Keep per-event DUST only for the L1 crossings the user pays for.
- Move the per-event cost to L2: prover share and Celestia bytes per transaction.
