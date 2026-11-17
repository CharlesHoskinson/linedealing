# Recovery trigger: when Midnight declares a committee lost or dishonest

This document defines the condition under which Midnight records a **recovery transition** for one committee. It analyzes each candidate condition for soundness (it never fires while the committee serves), completeness (it fires when the committee does not serve) and its Midnight transaction count. It does not choose the recovery mechanism. The mechanism that acts on the transition (a reshare of the committee half from a backup holder, a recovery vault, or a hybrid) is specified in `RECOVERY.md`. The honest-committee handoff is DESIGN §8 (LOOP item 41).

Section numbers without a file name refer to `DESIGN.md`. Parameters are the launch values of §2.3: `n = 9`, `f = 2`, `q = 6`, `t = n − f = 7`, and later `n = 17`, `f = 5`, `q = 12`, `t = 12`.

## 1. Summary

The trigger is a disjunction of three Midnight-provable conditions, each checked by the committee contract from state that Midnight already holds:

1. **Silence.** No checkpoint signed by at least `t` seats of the committee has landed for `Δ_sil` Midnight blocks.
2. **Unanswered forced request.** A request that a third party forced onto Midnight was not answered by a settlement leaf with service evidence within `Δ_fr` Midnight blocks.
3. **Equivocation.** Two statements signed by `q` seats conflict: two checkpoints with one `seq`, or two settlement leaves with different outcomes for one `auth`.

A fourth input, the end of the handoff deadline of §8 without a new epoch, fires the transition only through condition 1 or 2, or behind a delay that the committee can cancel with proof of service (§5.4). Governance never fires the transition alone (§5.5).

Every clock is in Midnight blocks. A clock that counts board heights or checkpoints stops when the committee stops. In steady state the trigger adds no committee transaction and no user transaction. The dispute path costs one transaction per challenge and one per resolution, both sent by non-committee parties.

The conditions catch omission (a committee that stops or refuses) and provable commission (equivocation). They do not catch a committee in which at least `q` seats are corrupt and keep signing consistent false statements. Against that adversary no condition built from committee-signed data is sound, and the residual is stated in §6.

## 2. What Midnight can read

The trigger may use only state that Midnight holds or verifies. The table lists that state (§7.13, §5.3, §5.6, §11.6).

| Record | Fields the trigger can use | Written by | Frequency |
|---|---|---|---|
| Checkpoint | `seq`, `epoch`, `board_height`, `board_root`, `settle_root`, `bf_root`, `restart_seq`, `q` signatures, and the Midnight block height at which it landed | committee, `q` signatures | every 60 s |
| Key Registry | `EKS_e` per epoch with `q` signatures | committee | per epoch |
| Node Registry | `committee_id`, `node_id`, `boot_ctr`, status | operators, nodes | per boot or event |
| FenrirAssets | `authorize` calls (`auth`, `nf`, `rh`, Midnight height), the `settle_root` of each landed checkpoint, carried VOID settlements, `revoke` | users, hold authorities | per request (user writes) |
| Recovery | `recover`, `coldStart` | anyone after `Δ_rec`; `q` operators | per event |

Midnight does not see the board, the envelopes, ROTATE or HANDOVER (these are board records, §8.1), the reason of a VOID tombstone, or any host chain. The contract holds roots, not leaves (§5.3 step 5, DECISIONS 52). A settlement counts on Midnight only when a later transaction proves its leaf under a landed root, or when a reissue carries a VOID leaf (§5.6).

## 3. Model

### 3.1 What "serving" means

A committee **serves** at Midnight height `h` when all of the following hold over the window that a condition reads:

- **S1 (signing capacity).** At least `t` seats are up, hold valid shares of `x_f` for each curve, and follow the protocol.
- **S2 (progress).** The board orders and commits blocks. Partial synchrony has reached its global stabilization time (GST).
- **S3 (inclusion).** Midnight includes every valid committee transaction within `Δ_inc` Midnight blocks of its first submission.
- **S4 (settlement).** At least `q` of the seats of S1 sign checkpoints, and each checkpoint carries a `settle_root` over the requests that ended in its interval (§7.13).

S1 to S4 describe the committee and Midnight. They are not the negation of any trigger condition. The soundness target of §5 derives "no condition fires" from S1 to S4 and the timing bounds.

S1 and S4 differ at launch. A checkpoint needs `q = 6` signatures and a release needs `t = 7` partials. A committee with exactly six working seats lands checkpoints and cannot sign. At `n = 17`, `q = t = 12`, and the gap is closed.

### 3.2 Adversary classes

Let `c` be the number of seats that refuse or fail, and `k ≤ c` the number that are Byzantine. Honest seats are `n − c`. At `n = 9`:

| `c` | Release possible | Checkpoint possible | What the faulty seats can do |
|---|---|---|---|
| 0 to 2 (`≤ f`) | yes | yes | nothing that blocks service (C13) |
| 3 (`n − q`) | no: `n − c = 6 < t` | yes, by honest seats alone | block every release; honest seats still sign true checkpoints and settlement leaves |
| 4, 5 | no | only with faulty signers | withhold checkpoints; with honest co-signers only true roots land, because each honest signer checks the root (§7.13) |
| 6 (`q`) to 8 | no | yes, by faulty seats alone | sign checkpoints and settlement leaves with false content |
| 9 | no | yes | as above, and hold `x_f` whole |

For `c < q`, every landed checkpoint has at least one honest signer, so its `settle_root` is true. That fact carries conditions 1 and 2. For `c ≥ q`, a checkpoint proves nothing about service.

In every row the faulty seats cannot spend without an admitted signing set (C4, C5). A refusing or lost committee costs liveness. It costs custody only if `x_f` is lost with no backup.

## 4. The candidate conditions

### 4.1 Silence: no landed checkpoint for `Δ`

**Predicate today (§5.8).** `recover(committee_id)` succeeds when no checkpoint of the committee has landed for `Δ_rec` Midnight blocks (launch: 30 days). The contract compares its current height with the landing height of the latest checkpoint.

**Soundness.** Under S2 to S4, a checkpoint lands at most every `60 s + Δ_inc`. The predicate cannot fire while `Δ_rec > 60 s + Δ_inc + Δ_cold`, where `Δ_cold` bounds a whole-committee restart (§7.11). A restart with tier 0 intact on `t` nodes needs no Midnight transition, and its next checkpoint resets the clock. A restart with fewer than `t` intact nodes runs from `E` on the `coldStart(committee_id)` record that `q` operators sign (§7.11 item 2). That path must also land a checkpoint within `Δ_rec`, or it is indistinguishable from loss.

**Completeness.** The predicate fires when fewer than `q` seats sign, or when the faulty seats withhold their signatures in rows `c = 4, 5`. It does not fire:
- in row `c = 3`, where honest seats keep checkpointing while no release completes;
- for a committee with exactly `q` working seats at `n = 9` (the S1 to S4 gap of §3.1);
- for `c ≥ q`.

**Fix for the gap: count `t` signers.** Reset the silence clock only on a checkpoint that carries signatures from at least `t` distinct seats. A checkpoint with `q ≤ s < t` signatures still lands and still serves settlement, but does not reset the clock. Cost: one more 64-byte signature per checkpoint at `n = 9` (the payload grows from 1,008 B to 1,072 B), none at `n = 17`. This proves that `t` seats hold their posting keys. It does not prove that they hold shares of `x_f`.

**Stronger form: a threshold heartbeat.** The committee signs a fixed heartbeat message `(committee_id, seq, board_root)` under `X_f` of each curve with the committee's own nonce slots, and the checkpoint carries the signature. A valid signature needs `t` shares, so it proves S1. Each honest seat contributes only if every request it saw ordered in the interval reached release or a publicly checkable VOID. Then an honest seat withholds its partial in row `c = 3`, the heartbeat stops, and the silence clock runs. Three costs keep this form open:
- Midnight must verify a BIP340 or Ed25519 signature in a proof. Midnight's proofs are KZG on BLS12-381 (§5.3 item 5). The measured in-circuit Ed25519 verify in midnight-zk is 54,398 advice and 61,699 table rows (Exocovenant dossier §7.1). In-circuit secp256k1 is an upstream wish (dossier §8.5). One heartbeat per curve per day keeps the cost to two proofs a day.
- The adversary of C5 now also sees signatures under `X_f` alone, with key-prefixed challenges `H(R, X_f, m_hb)`. C5 needs a related-key argument for that oracle. That argument is a new obligation of O6.
- The heartbeat must draw its nonces from a pool that no request can name, so no heartbeat partial lands on a request slot.

### 4.2 Authorized but unsettled

**Plain predicate.** "An `authorize` for `auth` is final at height `h_a`, and no settlement for `auth` counts by `h_a + Δ`." The plain predicate fails in four ways:

1. **Midnight cannot see "unsettled".** The contract holds roots only. Absence of a leaf under many roots is not provable without the leaves.
2. **Anyone can fabricate it.** A party can call `authorize` and never post the envelope. The committee never sees the request and cannot settle it. The condition fires against a serving committee.
3. **Refusal settles honestly.** In row `c = 3` the request expires with no release, and honest seats sign the leaf `(auth, VOID)`. The plain predicate sees a settlement and does not fire.
4. **Board-first charters have no `authorize`.** Their calls reach Midnight only inside `bf_root` (§5.3). The predicate is undefined for them (O29).

**Forced form.** The condition becomes a challenge that puts the burden of proof on the committee:

1. **Challenge.** Any party posts `challenge(auth, frame)` with a deposit `D_ch`. `frame` is the 16,384-byte envelope of the request, copied from the board mempool or held by the initiator's companion. The contract checks that `auth` is a final `authorize`, that `frame.auth_ref` names it, and that no challenge on `auth` is open. The frame is now available on Midnight, so the committee cannot say it never saw the request. The challenge needs no owner action.
2. **Service evidence.** The challenge closes when anyone posts the leaf of `auth` under a landed `settle_root` with one of these outcomes:
   - FINAL or RELEASED;
   - VOID with a reason of class P (public). The class-P reasons are a `revoke` on Midnight, a verified share complaint against the initiator's dealing, a failing contribution equation, STALLED with an empty actor slot at `exp_c`, and SLOT_TAKEN under an earlier request in board order.
   The resolver takes the deposit `D_ch`. A VOID with a reason of class E (enclave-only, such as a failed TEE release check) or MIXED does not close the challenge.
3. **Fire.** If the challenge is open at `h_ch + Δ_fr`, anyone calls `fire(auth)`. The contract records the recovery transition.

**Leaf change.** The settlement leaf carries the reason class: `(auth, outcome, reason_class)`. Today the leaf is `(auth, outcome)` (DECISIONS 52, D2). Every class-P reason except `revoke` has its evidence on the board. The evidence is the complaint with its DLEQ proof, the failing equation with the `t` proved partials (§5.6 step 6), the frames of the collection, or the board order of the slots. A checkpoint signer signs a class-P leaf only after it checks that evidence against the board. For `c < q` every landed root has an honest signer (§3.2), so a class-P leaf under a landed root is evidence by itself, and the resolver posts only the leaf and its path.

**Soundness.** Under S1 to S4, an honest committee orders the forced frame, and the request ends FINAL, RELEASED, or VOID with a class-P reason (C13). Its leaf lands under the next `settle_root`. The challenge therefore closes by `h_ch + Δ_fr` when

`Δ_fr > Δ_inc + Δ_order + exp + Δ_conf + 60 s + F_M`,

where `Δ_order` is the time to order a frame after GST, `exp` is the request expiry, `Δ_conf` is the confirmation depth of the host chain and `F_M` is Midnight finality. The expiry `exp` already covers `Δ_c = 600` board blocks for a collecting request, `Δ_hold = 2` Midnight blocks in P2 and a second fee generation.

**Completeness.** For `c < q` the leaf is true (§3.2). A refused request ends with no release and no class-P reason, so no leaf can close the challenge, and the condition fires. For `c ≥ q` the faulty seats sign a false FINAL leaf, and Midnight cannot check the host chain. The forced form does not catch them.

**Residuals.**
- **Pretext VOID.** `f + 1` faulty seats can void a request and name its reason (§5.1, DECISIONS 61). A false class-P reason gets no honest checkpoint signer, so for `c < q` it never lands. A class-E reason lands but does not close the challenge, so the condition still fires. The reverse case is the residual: an honest TEE committee that voids a bad request for a class-E reason does not close the challenge either. Class E needs a public form, or the forced form gives a false positive for it.
- **One challenge per record state.** `auth` is unique per `nf` (§5.3), so a record state carries at most one open challenge.
- **Partial synchrony.** Before GST no bound holds. `Δ_fr` must cover the longest asynchronous period that the deployment accepts. A challenge posted during a long partition is a false positive.

### 4.3 Stalled handoff

Midnight sees a handoff only through the `epoch` field of checkpoints and the Key Registry record `EKS_e` (§7.13). ROTATE and HANDOVER are board records (§8.1).

- A single aborted handoff is a legitimate outcome. §8.1 step 8 keeps the old committee in place with its old shares.
- The new committee can cause the stall: fewer than `n' − f'` READY posts. A condition on one stall would fire against a serving old committee.
- The owner ruling of 2026-11-16 makes the handoff mandatory: keychains are never static. A committee that never completes a handoff violates that rule while it still signs.

**Predicate.** No Key Registry record for a new epoch has landed within `D_ho` Midnight blocks after the previous one, where `D_ho` is the handoff deadline that §8 fixes (item 41). The predicate is provable from the Key Registry heights alone.

**Use.** The predicate does not fire the transition by itself. It opens a cancel window of `Δ_cx` blocks. A threshold heartbeat (§4.1) landed in the window shows S1 and closes it. Without the heartbeat form, the stalled handoff is evidence for the owner's governance and for the silence clock, not a trigger. The reason: a stall caused by a faulty new committee says nothing about the old committee's capacity.

### 4.4 Equivocation

Honest seats sign one checkpoint per `seq` and one outcome per `auth` (§5.6). Two conflicting statements, each with `q` valid signatures, show at least `2q − n ≥ f + 1` seats that signed both: 3 seats at `n = 9`, 7 at `n = 17`.

- **Predicate.** `equivocation(stmt_1, stmt_2)` with two checkpoints of one `seq` and different roots, or two settlement leaves of one `auth` with different outcomes, each under `q` signatures of the key set of its epoch.
- **Soundness.** Under S1 to S4 with `k ≤ f` Byzantine seats, no two conflicting `q`-sets exist. A restart leaf that supersedes an uncovered leaf (DECISIONS 58) is not a conflict: the predicate counts only leaves under landed roots, or a carried VOID.
- **Cost.** One transaction by the reporter. The contract checks `2q` Ed25519 signatures, which it already does for each landed checkpoint.
- **Completeness.** It catches commission with `k ≥ f + 1` that shows two faces. It does not catch a coalition that signs one consistent false story.

### 4.5 Governance

A governance signature (Image Registry governance, 7 of 9, §2.2) or a Midnight stake vote can fire the transition while the committee serves, by construction. It is not a sound trigger. Two uses keep it within the rules:

- **Conjunct.** Governance co-signs a transition that one of §4.1, §4.2 or §4.4 already proves. Governance then adds a veto, not a power.
- **Delayed fire with cancel.** Governance posts `propose_recover(committee_id)`. The transition fires after `Δ_gov` blocks unless the committee lands a threshold heartbeat (§4.1) and closes every open forced challenge in that window. Governance then acts only against a committee that cannot prove service. This is the only path against the `c ≥ q` row, and its trust is the governance key set.

## 5. Soundness target

### 5.1 Statement

Let the committee serve over `[h_0, h_1]` (S1 to S4 of §3.1), with `k ≤ f` Byzantine seats, and let the timing bounds hold:

- `Δ_sil > 60 s + Δ_inc + Δ_cold`;
- `Δ_fr > Δ_inc + Δ_order + exp + Δ_conf + 60 s + F_M`;
- the window `[h_0, h_1]` starts after GST.

Then no condition of §1 fires in `[h_0 + max(Δ_sil, Δ_fr), h_1]`:

- silence does not fire, because a checkpoint with `t` signers lands at least every `60 s + Δ_inc`;
- no forced challenge stays open, because each forced request ends FINAL, RELEASED or VOID with a class-P reason (C13), and that leaf lands under the next `settle_root`;
- no equivocation exists, because two conflicting `q`-sets share an honest seat.

The proof obligations are C13 (open: O28), C11 for the one-outcome rule (sketched), and the timing bounds above. A Lean theorem for this target takes S1 to S4 as hypotheses over committee behavior and derives the conclusion. A theorem whose hypothesis is "no trigger condition holds" proves nothing.

### 5.2 False positives

| Cause | Condition that fires | Mitigation |
|---|---|---|
| Midnight congestion or censorship of committee transactions beyond `Δ_inc` | silence | `Δ_sil` far above any accepted inclusion delay; launch `Δ_rec` is 30 days |
| Region outage with fewer than `t` tier-0 seats and a slow `E` reprovision | silence | `Δ_cold` inside `Δ_sil`; `coldStart` must land a checkpoint in time |
| Long asynchronous period | forced challenge | `Δ_fr` covers the longest accepted partition |
| Grace-period overlap of two key sets (§2.3: one epoch boundary plus 2 days) | equivocation, if the contract mixed epochs | the contract checks each statement against the key set of its own epoch |
| P2 hold that revokes a forced request | forced challenge | a `revoke` is a class-P reason (§4.2) |
| Class-E VOID reason (enclave-only check) | forced challenge | a public form for that reason, or accept the false positive |
| Faulty new committee in a handoff | stalled handoff | not a standalone trigger (§4.3) |

### 5.3 What firing does

- The transition is per `committee_id`. `x_f` is shared by every address of the committee (§2.2), so one record's evidence acts on all of them. No transition selects an address.
- The contract fences the old key set. It refuses later checkpoints, `EKS_e` records and settlement roots signed by it. Honest old seats read the fence and stop releasing.
- A late checkpoint does not cancel a fired transition. Two live committees with shares of one `x_f` could release on one ECDSA slot, and two ECDSA signatures on one slot `R_ℓ` give the nonce and the key. The recovery mechanism must also reshare an ECDSA slot only when the covered seat logs show it unbound (§7.11 item 2).
- Requests in flight at the fence end and settle by the rule of §5.6 and DECISIONS 58, as at a whole-committee restart.

## 6. The dishonest committee before and after the trigger

**Before.** A committee with `c ≥ f + 1` faulty seats can refuse every release. It can break blindness and sealing with `t` or more seats (§6.4 item 14). It cannot spend: every spend needs an admitted signing set (C4), and all actors with `t − 1` nodes cannot sign (C5).

**After.** The old seats keep their old shares of `x_f`. Recovery does not change `X_f`, so a corrupt old committee with `t` shares still holds the committee half of every address. It still cannot spend without the user shard (C4). It can still read what its seats read before the fence. A recovery that reshares `x_f` gives the new committee new shares of the same secret. The old shares stay valid shares of that secret, so secrecy of `x_f` against the old seats is not restored. Only a key change (`X_f` replaced) would restore it, and that moves every coin.

**Residual with `c ≥ q`.** A coalition of `q` or more seats signs checkpoints with `t` signers if it has `t` seats, answers forced challenges with false FINAL leaves, and shows one face. No condition built from committee-signed data catches it. Two inputs remain:
- governance by delayed fire with cancel (§4.5);
- host-chain evidence that a claimed FINAL never confirmed, which Midnight cannot verify (Exocovenant dossier §7, §10).

## 7. Midnight transactions

The batched-writes rule allows one committee root per checkpoint and no per-event committee writes (DECISIONS 52, §11.6).

| Path | Committee transactions | Other transactions | At 133 to 136 requests per second |
|---|---|---|---|
| Steady state, silence clock | 0 extra: the checkpoint resets it | 0 | 1 checkpoint per 60 s, unchanged |
| `t` signers per checkpoint | 0 extra; +64 B per checkpoint at `n = 9` | 0 | unchanged count |
| Threshold heartbeat | 0 extra: one heartbeat proof per curve per day inside a checkpoint | 0 | 2 heavier checkpoints per day |
| Forced challenge | 0: the answer is the next `settle_root` | 1 `challenge` (frame 16,384 B plus deposit), then 1 `resolve` (leaf and a path of about 15 hashes) or 1 `fire` | 0 when nobody challenges; worst case one challenge per `auth`, 133 to 136 challenges and as many resolutions per second, each paid by its sender and bounded by the deposit |
| Equivocation report | 0 | 1 by the reporter | per event |
| Stalled handoff | 0: Key Registry is already one record per epoch | 1 `fire` after the cancel window | per event |
| Governance delayed fire | 0 | 1 `propose_recover`, 1 `fire` | per event |
| `recover` | 0 | 1 by anyone | per event |

The worst case of the forced path doubles the user writes for the challenged requests. Its cost falls on challengers who lose `D_ch` to the resolver when the committee served.

## 8. Integration edits

These edits apply after items 41 and 42 merge. Each names the place and the change.

- **§2.3.** Add `Δ_sil` (replaces `Δ_rec` as the silence window), `Δ_fr`, `D_ch`, `D_ho` (from item 41), `Δ_cx` and `Δ_gov`.
- **§5.6, Settlement.** The leaf becomes `(auth, outcome, reason_class)` with the classes P and E of §4.2 (MIXED counts as E). A checkpoint signer checks the board evidence of each class-P leaf before it signs `settle_root` (§7.13, signer rules).
- **§5.8, Exit through the recovery group.** Replace "no committee checkpoint lands on Midnight for `Δ_rec` blocks" with the disjunction of §1, and state the fence and the no-cancel rule of §5.3.
- **§7.13.** The Checkpoints row records the signer count and, if the heartbeat form is chosen, the heartbeat proof. The Recovery row adds `challenge`, `resolve`, `fire`, `equivocation` and `propose_recover`. The contract rules of §5.3 here are added to the paragraph after the table.
- **§8 (item 41).** The handoff deadline `D_ho` is defined in Midnight blocks, and each new epoch's `EKS_e` landing is the Midnight evidence of a completed handoff.
- **§9.1.** C15 is restated for the trigger: its adversary column names the `c ≥ q` residual. A new claim states the soundness target of §5.1.
- **§11.6.** Add the rows of §7.
- **§12.** Add the open items of §9.

## 9. Open items

- **Heartbeat verification on Midnight.** A proof that checks one BIP340 and one Ed25519 signature under `X_f` at `k ≤ 21`, measured.
- **Related-key oracle in C5.** The argument of O6 extended to signatures under `X_f` alone with key-prefixed challenges.
- **Public form of class-E reasons.** Each VOID reason that only an enclave checks gets a public check, or the deployment accepts the false positive of §5.2.
- **Timing bounds.** `Δ_inc`, `Δ_cold`, `Δ_order`, `exp` and `Δ_conf` measured, and `Δ_sil` and `Δ_fr` set from them.
- **Board-first charters.** A forced challenge for a board-first call, whose `nf` reaches Midnight only inside `bf_root` (O29).
- **`c ≥ q` without governance.** A Midnight-verifiable proof that a claimed FINAL confirmed on the host chain, or acceptance of governance as the only remedy.
