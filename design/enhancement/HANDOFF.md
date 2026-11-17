# Committee handoff

The Fenrir committee that holds the committee half `x_f` changes over time. Operators leave, new operators join, and every share must move to new keychains at a fixed cadence. The **handoff** is the protocol operation that moves the committee's secrets and authorities from the committee of epoch `e` to the committee of epoch `e + 1`. It is mandatory: no charter, profile, suite or mode can block it or opt out of it.

Three rules bind every step:

1. **The user's shard does not change.** The handoff touches no shard, no tweak, no actor pool, no sealed contribution and no wallet state. `X_f` per curve does not change, so every address `X = X_f + tw·G + Σ_a X_a` survives every handoff.
2. **No step waits on the owner.** The owner is online only to initiate a spend and to broadcast it. A request that is live during a handoff finishes with no re-deal, refill, re-post, acknowledgement or reissue by any actor.
3. **Midnight writes are batched.** A handoff adds no Midnight transaction. Its one write is the activation record, which replaces one ordinary checkpoint and also carries the epoch key set. Joining operators register their boots as before.

Two further rules make the handoff the same operation as a recovery (§12). No step of the outgoing committee follows the arming of the incoming one. Every clock counts Midnight blocks, so a stalled board cannot stop a deadline.

The design keeps `t = n − f` and the zero-knowledge path of every mode. No helper receives a plain witness.

DESIGN §8 states the mechanism in the protocol text. This document gives the reasons, the phases, the cadence, the secret table, the audit of every place that pinned the committee to fixed keys, and the costs. DECISIONS 79 to 86 record the choices.

## 1. Terms

| Term | Meaning |
|---|---|
| Epoch `e` | One committee: a roster of `n` seats, its parameters `(n, f, q, t)`, its epoch keys `EKS_e` and its sharings. An epoch is **current** from the activation that opens it, and **in grace** from the next activation until its grace end. |
| Roster `R_e` | The seats of epoch `e`: node id, operator key, VM id. A **continuing** seat is in `R_e` and `R_{e+1}`. A **departing** seat is in `R_e` only. A **joining** seat is in `R_{e+1}` only. |
| Binding epoch of a request | The epoch whose key list the envelope names: `pub.epoch` and `keylist_hash`. The binding epoch owns the request until a sweep carries it (§4.3). |
| Owning epoch of a request | The epoch whose seats open, admit and release the request at a board position. FINAL and VOID posts are counted for every epoch that serves the request in the sense of DECISIONS 56, which is a wider set. |
| Sharing | One Shamir sharing of one committee secret among one roster, with public Feldman commitments. A reshare makes a new sharing of the same secret among the next roster. The constant term does not change. |
| Standing secrets | `x_f` per curve and every ECDSA committee slot share pair `(w_f, μ_f)` that no request has used. They outlive every request. |
| Live material of a request | Every sharing that a request still needs: `κ_0` of its envelope, `κ_c` of each attached or pending contribution frame, the line dealings of a P0 request, and the committee slots it names and has not released. |
| Carry | A reshare of a sharing from the holders of epoch `e` to the roster of epoch `e + 1`, publicly checked against the existing commitments. |
| Governance key set `GK_e` | The operator keys of `R_e`. A ROTATE needs `q` of them. The set rotates with the roster at each activation. |
| Arm heartbeat | A threshold signature under `X_f` of each curve by `t'` seats of the incoming committee over `("fenrir/arm", e + 1, H(Q), h_S)`. It proves that the incoming committee holds its own live sharing of `x_f`. |
| Activation record | The Midnight record that makes the armed committee current: the checkpoint at board height `H`, `EKS_{e+1}`, the roster, the ROTATE and the heartbeat, signed by `t'` seats of epoch `e + 1` alone. The activation is the HANDOVER of the epoch. |
| Midnight height `m` | Every clock of the handoff: `m_R` at ROTATE, the deadline `m_D = m_R + Δ_rot`, the activation height `m_A`, the sweep `m_W` and the grace end `m_A + Δ_grace`. Nodes read Midnight at the finality depth `F_M`. |

## 2. Phases

```
 Midnight height ──────────────────────────────────────────────────────────────────────►

 epoch e current ─────────────────────────────────────────┐ epoch e in grace ──────┐
                                                          │                        │
 ROTATE ── JOIN ── CARRY (standing secrets, ── READY ── ARMED (H) ── ACTIVATION ── SWEEP ── CLOSE
 (m_R)              rate-capped, days)        (h_S)   heartbeat    record (m_A)   (m_W)   (m_A + Δ_grace)
                                                      under X_f        │
                                                                       │
                                            epoch e+1 current ─────────┴─────────────────────►

 ROTATE ── ... ── Midnight passes m_D with no activation record ──► ABORT: epoch e stays current
```

The handoff has one board state per committee change.

| State | Entered when | Who acts |
|---|---|---|
| QUEUED | a valid ROTATE is ordered while a precondition of §3.2 does not hold | nobody; the board re-tests the preconditions at each height |
| ROTATING | a valid ROTATE is ordered, or a QUEUED ROTATE meets its preconditions. Its Midnight height is `m_R`, its deadline `m_D = m_R + Δ_rot` | joining seats boot and register; every seat of `R_{e+1}` makes epoch keys; old seats carry |
| ARMED | the board block `H` commits the arm heartbeat with a quorum certificate of epoch `e` | epoch `e + 1` signs and submits the activation record; epoch `e` casts no block vote above `H`; the board makes no block until the activation |
| HANDED_OVER | the activation record is final on Midnight at height `m_A` | epoch `e + 1` validates the board from `H + 1` and owns every request that binds it; epoch `e` owns only the requests that bind it |
| CLOSED | the grace end of epoch `e`, `Δ_grace` Midnight blocks after `m_A` | epoch `e + 1` alone; old seats have erased |
| ABORTED | Midnight passes `m_D` in ROTATING or ARMED with no activation record | epoch `e` alone, as before ROTATE; after an armed abort it validates from `H + 1` |

### 2.1 ROTATE

A ROTATE names the target epoch `e + 1`, the roster `R_{e+1}` with each operator key, the parameters `(n', f', q', t' = n' − f')`, the source epoch whose holders deal, and a flag for an emergency rotation. It carries signatures of `q` keys of `GK_e`. Any party may post it, and every node checks the signatures against the governance key set of the latest landed checkpoint. A ROTATE that fails the check is not ordered.

A **scheduled** ROTATE comes from the epoch schedule of §3.1 and replaces at most `⌊f/2⌋` seats. An **emergency** ROTATE removes failed or hostile seats and replaces at most `f`. A ROTATE that replaces no seat is a **refresh**: it gives every share of every standing secret a new polynomial.

### 2.2 JOIN

1. Each joining operator boots its node and submits `admitBoot` with the ROTATE that names its operator key. The Node Registry accepts the boot of a seat that a ROTATE names. It records the seat as pending until the activation record lands.
2. Each node of `R_{e+1}`, continuing seats included, generates its epoch keys of §7.5 and gets `w'` acks on the board. The board then holds `EKS_{e+1}`. It reaches Midnight only with the activation record (§5).
3. TEE mode: peers admit a joining node on evidence and its boot ticket (§7.3). The roster `R_{e+1}` runs the DKG of the seal-group secret `σ_{e+1}`.
4. The roster `R_{e+1}` deals its first Schnorr nonce pools for epoch `e + 1`. No checkpoint lists them before the activation record, so no honest header names them before the activation. The target also reserves a nonce slot of its pool for each heartbeat.

### 2.3 CARRY

From the height at which `EKS_{e+1}` is complete, each seat of the source epoch carries the standing secrets: its share of `x_f` per curve and its share pair of every ECDSA committee slot that no request has used, in batches of `B_carry` slots. Each carry dealing is the reshare of DESIGN §8.1: a polynomial of degree `t' − 1` per share, Feldman commitments whose constant term is implied by the old commitments (base `G` for `x_f`, base `R_ℓ` for a slot), and one ciphertext per new seat. A new seat whose share fails posts the complaint of line dealing within the complaint window of `Δ_cw` Midnight blocks, and a valid complaint disqualifies the dealer for every dealing of the rotation. The qualified set `Q` is the first `t` old dealers with no valid complaint. A failed dealing disqualifies its dealer. It never burns a slot.

Carry dealings take at most the share `β` of the board's bytes per block, so the carry of a large ECDSA inventory runs for days beside normal traffic (§9).

The old committee keeps its full authority during CARRY. It orders, admits, releases and runs ECDSA sessions. A carried ECDSA slot that a request of epoch `e` uses after its carry is used once on the board. Each new seat burns its copy when it reads the use. A ticket on a slot comes from the board anchor, so the two copies can never sign two tickets (§7.1).

From ROTATE until CLOSE, every release of the old committee records RELEASE in a committed board entry before any partial leaves the node, in TEE mode as in non-TEE mode. Each carry dealing also lists the release entries that the dealer's witness log holds for live requests. A request is released when any committed RELEASE or any listed entry shows it, so the settlement outcome RELEASED survives the change of committee (DESIGN §5.6).

### 2.4 READY, ARMED and activation

At a snapshot height `h_S`, ECDSA sessions that have not started wait until the activation, and the sessions that are open finish. The last carry batch covers every ECDSA slot of a session that ended at or below `h_S`. A new seat posts `READY(e + 1, H(Q), h_S)` when it holds valid shares, under `Q`, of `x_f` per curve and of every ECDSA slot of the inventory at `h_S`, when it holds the slot-nullifier key `k_nf`, and, in TEE mode, when its share of `σ_{e+1}` is installed and its sessions of epoch `e + 1` are sealed.

With `n' − f'` READY posts for one `H(Q)` and one `h_S`, the complaint window of the last carry batch closed and no open whole-committee restart, the new seats sign the arm heartbeat. The board block `H` that commits it is the last block that epoch `e` validates. The handoff is ARMED. The new committee now holds its own sharing of `x_f` and of every ECDSA slot of the inventory, and the heartbeat proves `t'` live shares of `x_f`. The last carry is the last step of epoch `e` that the activation needs.

The new seats sign the activation record (§5.1), and any of them submits it to Midnight. When it is final, the handoff is HANDED_OVER at Midnight height `m_A`, and `R_{e+1}` validates the board from `H + 1`. The board makes no block between `H` and the activation, a pause of about one Midnight inclusion plus `F_M`.

### 2.5 After the arming

- **Epoch `e + 1`** validates the board, votes on every request that binds it, signs every checkpoint after the activation record, and runs every ECDSA session.
- **Epoch `e`** keeps owning the requests that bind it. Its members post their OPENED, ADMIT with OBS, RELEASE and FINAL entries as one signed **epoch post** per member and block. The board counts the posts of each epoch against that epoch's own thresholds (DECISIONS 56), as it counts votes. The epoch `e` members never validate a block above `H`.
- **Envelopes that bind epoch `e`** and are ordered after the activation are owned by epoch `e`, as above, until the sweep.
- **The sweep.** At the Midnight height `m_W = grace_end(e) − Δ_sweep`, every request that binds epoch `e` and has not ended has its live material carried to epoch `e + 1` in one batch. When `n' − f'` new seats post READY for the sweep batch, epoch `e + 1` owns those requests and epoch `e` stops owning them. An envelope that binds epoch `e` and is ordered after the sweep is refused at the public check with code `epoch_closed`.
- **CLOSE.** At grace end every seat of epoch `e` erases by the rules of §6, and departing seats retire.

The epoch posts and the sweep serve only the requests that bind epoch `e`. The activation and the standing state never depend on them. If epoch `e` stops after the arming, its own requests end at `exp` and their owners re-post. §12 names the item 42 rule that removes that case.

### 2.6 ABORT

If no activation record lands by the Midnight height `m_D`, the rotation ends ABORTED. The committee contract refuses a record after `m_D`, so both committees read one outcome from Midnight. Epoch `e` keeps every share it had. If it had armed the target, it validates the board again from `H + 1`. Each seat of `R_{e+1}` erases every share it received, its epoch `e + 1` keys and its new nonce pools. A joining seat retires. Nothing was written to Midnight except the joining seats' boots. Governance posts a new ROTATE to try again.

A ROTATE whose source is an epoch in grace replaces a committee of epoch `e + 1` that cannot sign. Its dealers are the holders of epoch `e`, which keep their shares until grace end (§6).

## 3. Authorization and cadence

### 3.1 Who triggers a handoff

Fenrir governance triggers every handoff with `q` signatures of the current governance key set, which is the set of operator keys of the current roster. Two sources produce a ROTATE:

- **The epoch schedule.** The committee posts a refresh ROTATE with the same roster at the first height where the preconditions of §3.2 hold, with the `q` operator signatures collected on the board. The governance key set adds or removes seats in the ROTATE it signs.
- **An operator change.** An operator that leaves, a seat that fails, or a seat that misbehaves leads governance to post a ROTATE that replaces the seat, scheduled or emergency.

No charter, profile, suite or mode takes part in the decision or can refuse it. Every address keeps `X_f`, every user keeps its shard, and the committee reshares its own secrets.

### 3.2 Preconditions and queueing

A ROTATE becomes ROTATING only when all hold:

1. no rotation is ROTATING;
2. the previous epoch is CLOSED, so at most two epochs are live at any height;
3. no whole-committee restart is open (DESIGN §7.11);
4. the source epoch is current, or in grace for the replacement of a committee that cannot sign.

A ROTATE that arrives while one fails is QUEUED, not refused. Each precondition becomes true by committee steps and time alone: a rotation ends HANDED_OVER or ABORTED by `m_D`, a grace period ends at a fixed Midnight height, and a restart ends with its checkpoint. A queued ROTATE therefore starts without any user action.

### 3.3 Cadence and seats per rotation

| Parameter | Launch value | Rule |
|---|---|---|
| Epoch length `L_e` | 7 days of Midnight blocks | one handoff per epoch, a refresh when no seat changes; `L_e = Δ_grace + Δ_rot` |
| `Δ_grace` | 2 days of Midnight blocks after `m_A` | lifetime of epoch `e` keys and shares after the activation; it replaces "1 epoch boundary + 2 days" |
| `Δ_rot` | 5 days of Midnight blocks | ROTATE to the deadline `m_D`; at least the carry time of §9 plus `Δ_cw`, the READY round and one Midnight inclusion |
| `Δ_sweep` | 1 hour of Midnight blocks | sweep before grace end; at least the carry of the live material of the sweep set plus `Δ_cw` |
| `Δ_cw` | set by measurement, in Midnight blocks | complaint window after each carry batch; the synchrony bound of O5 |
| `β` | 10 % | largest share of board bytes per block for carry dealings |
| `B_carry` | set by measurement | ECDSA slots per carry batch |
| Seats per scheduled rotation | `⌊f/2⌋`: 1 at `n = 9`, 2 at `n = 17` | a joining seat that fails counts against `f'`, and a departing seat that fails counts against `f`; `⌊f/2⌋` leaves `⌈f/2⌉` of each budget for other faults |
| Seats per emergency rotation | `f` | the failed seats already count against `f`; the `t = n − f` other seats deal |

At most two epochs are live at any height, so a node keeps at most two sharings of each secret, two seal-group shares and four committee pools (DESIGN §7.4, §11.6).

## 4. Requests during a handoff

### 4.1 The rule

A request is owned by its binding epoch until a sweep carries it, and by the successor epoch after that. Board position decides both. A request is never owned by two epochs at one board position, and every live request is owned by one epoch at every board position from its ordering to its end.

### 4.2 Why the binding epoch

The binding epoch holds every sharing the request needs: `κ_0` was dealt to its keys `PK_i`, and the request names slots of its pools. The user's sealed contributions fix `R = R_A + D_ℓ + ρ·E_ℓ` through those slot points, and `ρ` hashes the slot's epoch label and index. A new slot would need a new contribution, which is a user action and which C3 forbids the committee to make. The request therefore stays on its slots. Its owning committee is the one that holds them.

Ownership by the binding epoch moves nothing for the requests that end in grace, which is almost all of them. Wallets bind epoch `e + 1` once the activation record lands. The sweep set is the requests that bind epoch `e` and are still live at `m_W`, two days less `Δ_sweep` after the activation: envelopes that waited that long to be ordered, and requests whose collection or fee generation is still open.

### 4.3 The sweep

For each request of the sweep set, each old seat carries its share of `κ_0`, of `κ_c` of each frame attached to the request or pending for it, of each line dealing of a P0 request, and of each committee slot that the request names and has not released, with the release entries of its witness log. Each dealing is checked against the existing commitment: the envelope's outer commitments for `κ_0`, the frame's for `κ_c`, the line's for a P0 line, and the slot's in base `G` or `R_ℓ`. Nothing that the user dealt or sealed changes:

- `κ_0` has the same value, so `Z_lab = κ_0·H_c(dd ‖ lab)`, every body key, every `y_{v,g}` and every `P_{v,g}` are unchanged. Every sealed contribution opens as before.
- Each slot keeps its pool label `slots-s-e`, its index, its points and its nullifier under `k_nf`. Every `ρ`, `R` and challenge is unchanged.
- The board keeps the request's state: precedence, reservations, anchors, generations, contributions and tombstone posts.

The successor commits each carried slot's state from the board: a slot whose anchor fixed a ticket is `bound` to that ticket in the new seat's session before the seat signs on it (§7.1).

### 4.4 Requests that bind epoch `e + 1` before the activation

A wallet reads `EKS_{e+1}` from Midnight only after the activation record lands, so it builds no envelope for epoch `e + 1` earlier. An envelope that names epoch `e + 1` and is ordered before the activation waits: no seat of epoch `e + 1` sends a partial before it.

### 4.5 Sessions, births and P0

- **ECDSA birth and refill sessions.** A session that starts before `h_S` runs with epoch `e` and its slots join the inventory. A session that would start after `h_S` waits for the activation and runs with epoch `e + 1`. The session party is online for its session in any case (V-13), so the wait adds no new owner step.
- **Schnorr birth and ACK requests** are ordinary requests. They follow §4.1.
- **P0 spends** carry their line dealings in the sweep, as the reshare of SCHEME §5 does.

## 5. Midnight

### 5.1 The activation record

The activation record is the checkpoint at board height `H`. It holds the fields of an ordinary checkpoint and:

- `EKS_{e+1}` (the `n'` NodeKeys and `keylist_hash_{e+1}`);
- the roster `R_{e+1}` with each operator key, and the departing seats, which the Node Registry marks retired at grace end;
- the ROTATE with its `q` signatures of `GK_e`;
- the arm heartbeat under `X_f` of each curve;
- `t'` signatures of epoch `e + 1`. It holds no signature of epoch `e`.

The committee contract accepts the activation record only when the ROTATE signatures verify against `GK_e`, the `t'` signatures verify against `EKS_{e+1}`, the heartbeat verifies under `X_f`, every joining seat has a boot ticket, no operator key of `R_{e+1}` is a member of `E` or of any guardian set, and Midnight has not passed `m_D`. The contract verifies the edwards25519 heartbeat now. The secp256k1 heartbeat waits for secp256k1 verification in Compact (O43), and until then the nodes check it before they sign. From the activation record on, the contract accepts a checkpoint only with `t'` signatures of `EKS_{e+1}`. It never accepts a checkpoint of epoch `e` again.

Every checkpoint needs `t` signatures of its epoch's key set, the number that can sign under `X_f`. At launch `q = 6 < t = 7`, and six seats could otherwise keep checkpoints landing while no seven can sign (DECISIONS 86).

### 5.2 Writes per handoff

| Write | Transactions | Payload at `n = 9` | Payload at `n = 17` |
|---|---|---|---|
| Activation record, in place of one ordinary checkpoint | 0 extra | 1,072 B of the checkpoint with `t' = 7` signatures + 1,197 B of NodeKeys + 32 B `keylist_hash` + 324 B roster + 384 B ROTATE signatures + 128 B heartbeat, about 3.1 KB | 1,712 + 2,261 + 32 + 612 + 768 + 128 B, about 5.5 KB |
| `EKS_{e+1}` | 0: inside the activation record, in place of the separate per-epoch write | — | — |
| `admitBoot` of each joining seat | 1 per joining seat, by its operator | one boot ticket | one boot ticket |
| `retire` of departing seats | 0: the activation record lists them | — | — |
| Carries, sweeps, READY, heartbeat, epoch posts | 0: board only | — | — |
| Any user write | 0 | — | — |

At the launch cadence of one handoff per 7 days with one seat changed, a committee writes 52 activation records and 52 `admitBoot` transactions per year beside the 525,600 ordinary checkpoints. The per-epoch `EKS_e` write that DESIGN §11.6 counted before is gone.

### 5.3 Committee signatures are epoch-scoped

Every committee signature that Midnight checks names its epoch: checkpoints, birth certificates, acknowledgement certificates, slot-root certificates `slr_own` and `slr_G`, and the VOID leaf of a reissue. The contract checks each against `EKS` of its own epoch, and accepts it only while that epoch is current or in grace. A record that Midnight already holds stays valid after its epoch closes. `authorize` checks no committee signature inside its proof: it proves that the record and its roots are on Midnight, and the contract checked their certificates when it wrote them. A carried VOID leaf of an epoch past its grace end is refused, and the reissue uses the root path, since a checkpoint covers every leaf within one interval.

## 6. Secrets and authorities

Every committee secret and authority, what the handoff does with it, who does it, when, and the erase rule for old holders.

| Item | Action | By whom | When | Erase rule for epoch `e` holders |
|---|---|---|---|---|
| `x_f` per curve (secp256k1 for BIP340, ECDSA and Midnight; edwards25519 for Ed25519, Solana and Cardano) | moved: reshare to `R_{e+1}`, constant term `X_f` checked | source-epoch seats; `Q` | CARRY, before READY | grace end; the share is the dealer source of a replacement ROTATE until then |
| ECDSA committee slot shares, unused | moved: reshare in base `R_ℓ` | source-epoch seats; `Q` | CARRY, in batches up to `h_S` | grace end; each copy is burned at once when the board shows the slot used |
| ECDSA committee slot shares, named or reserved by a live request | owned by the binding epoch; moved in the sweep if the request is still live at `m_W` | binding epoch | sweep | grace end |
| Schnorr committee nonce slots, free | discarded | — | — | grace end; epoch `e + 1` deals its own pools in JOIN |
| Schnorr committee nonce slots named by a live request | owned by the binding epoch; moved in the sweep | binding epoch | sweep | grace end |
| `κ_0` of an envelope, `κ_c` of a frame, P0 line shares | owned by the binding epoch; moved in the sweep | binding epoch | sweep | at the request's end, as today (DESIGN §5.6 item 8), or after its sweep |
| Threshold PRF keys `Z_lab`, body keys, `y_{v,g}` | unchanged: functions of `κ_0` and `dd` | — | — | per request, as today |
| Dealing keys `PK_i`, `EK_i`, post keys `post_i`, `S_i` | regenerated: new epoch keys for every seat of `R_{e+1}` | each seat of `R_{e+1}` | JOIN | grace end; `post_i` stays valid for epoch `e` posts until then (DECISIONS 56) |
| Seal-group secret `σ` | regenerated: DKG among `R_{e+1}` | `R_{e+1}` | JOIN | `close_epoch` at grace end (DESIGN §7.8) |
| Boot keys, `PVK`, `K_tpm`, TLS keys | not moved: per VM and boot | each joining VM makes its own | boot | departing seats zeroize at retire |
| Slot-nullifier key `k_nf` | moved unchanged: a carried slot keeps its nullifier, and seat logs stay readable | TEE: enclave to enclave on the attested channel; non-TEE: in each dealer's carry, the value that `f + 1` dealers send alike | CARRY | grace end |
| Backup at `E` of `x_f`, of ECDSA slot shares and of `k_nf` | unchanged: its constant terms are the same values | — | — | `E` refreshes its own sharing only when its membership changes |
| CommitteeLedger write authority (checkpoints, `settle_root`, `bf_root`, pools, seat roots) | moved: the activation record switches `EKS_e` to `EKS_{e+1}` | `t'` of epoch `e + 1`, with the ROTATE and the heartbeat | activation, by `m_D` | epoch `e` signs no checkpoint above `H` |
| Key Registry record | regenerated: `EKS_{e+1}` | inside the activation record | activation | the epoch `e` record stays for its grace and for history |
| Governance key set | moved: the operator keys of `R_{e+1}` | the activation record | activation | departing operator keys sign no ROTATE after it |
| Board membership | moved: `R_{e+1}` validates from `H + 1` once the activation record is final | the activation record | activation | epoch `e` casts no block vote above `H` and posts epoch posts only |
| Node Registry entries | joining seats admitted on the ROTATE; departing seats retired | operators; the activation record | JOIN; grace end | the registry refuses boots of a retired seat |
| seald Sessions, TEE mode | continuing seats `rekey` to epoch `e + 1`; joining seats seal new sessions (`keys`, account pools, carried pool sessions); departing seats destroy theirs | each seat | CARRY to ARMED; grace end | `session_destroy` and `close_epoch` at grace end |
| Tier 1 keyring, TEE mode | not moved: bound to the VM | — | — | zeroized at retire |
| Witness logs | not moved: each seat's log names its own seats; new seats run the blank-tier-0 fetch (DESIGN §7.4) | each seat | JOIN | kept by continuing seats as today |
| User shards, tweaks, actor pools, sealed contributions, `slr_own`, `slr_G`, asset records | unchanged | — | — | — |

## 7. Safety

### 7.1 One ticket per slot across two committees

A carried slot has two sharings, one per epoch, until the old holders erase. Two tickets on one slot reveal `x_f`. Three rules stop it:

1. Every ticket on a slot comes from the board: the anchor of its generation selects the variant, and the header fixes the ticket. Both epochs read one board.
2. One epoch owns a request at each board position (§4.1). The owning epoch switches at the sweep position, which is a board fact.
3. A new seat installs a carried slot in the state the board gives it: `free`, or `bound(H(tk))` with the anchored ticket, or burned.

A repeat release of the same ticket by the new epoch gives the same signature, which harms nobody. In TEE mode the release entries of the witness logs reach the new epoch through the carry, and from ROTATE on every release is committed on the board first (§2.3).

### 7.2 No signing gap

At every board position, every live request has exactly one owning epoch, and that epoch holds every sharing the request needs:

- up to the activation, epoch `e` owns every request, and a request that binds epoch `e + 1` waits for the activation;
- from the activation, epoch `e + 1` owns the requests that bind it, and epoch `e` owns the ones that bind it until the sweep;
- after the sweep, epoch `e + 1` holds the live material of every swept request.

One committee validates each board position: epoch `e` up to `H`, nobody between `H` and the activation, epoch `e + 1` from `H + 1`. The new epoch is live at the activation because the heartbeat shows `t'` live shares of `x_f`, and under the complaint window of O5 every honest new seat holds valid shares of every ECDSA slot. Under partial synchrony a late complaint can leave fewer than `t'` good holders of a slot. The publicly verifiable reshare of O5 closes that case. Until O5 closes, a ROTATE whose source is epoch `e` in grace replaces a committee of epoch `e + 1` that cannot sign (§2.6).

### 7.3 Abort

An aborted rotation leaves epoch `e` with every sharing, every authority and every pool it had. Epoch `e` served throughout, except for the pause between `H` and `m_D` after an armed abort. Midnight's deadline decides the abort, so the two committees never both validate. Each new seat erases what it received.

### 7.4 Adversary across two committees

The adversary is the dual threshold of DESIGN §8 in each committee: at most `f` Byzantine seats and the exposed shares of at most `t − 1 − f` further seats of epoch `e`, and at most `f'` and `t' − 1 − f'` of epoch `e + 1`. A seat in both rosters counts in both. Each sharing lies inside one roster, so the adversary holds at most `t − 1` shares of every sharing of epoch `e` and at most `t' − 1` of every sharing of epoch `e + 1`. Secrecy of each reshare against that view is the obligation O5. Yurek, Xiang, Xia and Miller (USENIX Security 2023, Theorem 1) prove a dynamic-committee reshare in this model with Pedersen commitments. Its Algorithm 3 with the same committee on both sides is a refresh under the same proof.

### 7.5 Mobility and refresh

Each handoff gives every standing secret a new polynomial, also for continuing seats, and a refresh ROTATE does so with no seat change. The adversary's budget therefore applies per epoch, not over the life of the committee: shares stolen in different epochs do not combine. A seat that is corrupt during a handoff counts in both epochs. Das, Xiang, Kokoris-Kogias and Ren (USENIX Security 2023, §6.2) state the same condition for their refresh: it holds if the adversary corrupts at most `t` seats during the refresh, and up to `ℓ` shares after it. The launch cadence of one handoff per 7 days bounds the window in which an attacker must gather `t` shares of one sharing to one epoch plus its grace.

### 7.6 Old operators who keep their shares

The erase rules of §6 bind honest seats, and in TEE mode the enclave enforces them for every operator while the TEE holds. A non-TEE operator can copy its shares before it erases. `X_f` is fixed, so any `t` shares of any one epoch's sharing give `x_f` for good. Shares of two epochs never combine.

What `t` old seats of one epoch that kept everything can do:

- They know `x_f`. With the shard of an admitted signing set they hold the address key, as `t` current seats do. Without an admitted set's shards they sign nothing, because C3 and C17 hold against a committee that is corrupt in full.
- They open the envelopes of their epoch and read the requests, so blindness for those requests is lost.
- They complete a variant that an admitted set sealed for a request of their epoch and that the anchor did not select. Every variant spends the same pinned input or nonce and pays the intent's outputs, so the most they change is which fee variant confirms.
- They cannot sign on a slot that a later epoch dealt, and their posts count only during their epoch's grace.

The fix is the same one that protects a current committee: never let `t` seats of one epoch keep their shares. TEE mode enforces the erase rule. Non-TEE mode assumes it, and a stolen-share budget per epoch is what §7.4 states. No refresh helps against `t` colluding seats of one epoch, because `X_f` cannot change without moving every coin, which the owner rule forbids.

## 8. Modes

| Step | TEE mode | Non-TEE mode |
|---|---|---|
| Joining seat admission | evidence and boot ticket checked by peers (§7.3); `admitBoot` with the ROTATE | operator registration with the ROTATE |
| Carry transport | dealing ciphertexts to `PK'_j` of the joining enclave; `k_nf` on the attested channel | dealing ciphertexts to `PK'_j`; `k_nf` inside the dealing, taken when `f + 1` dealers agree |
| Carried state at rest | seald sessions of the new seat: `keys`, account pools, carried pool sessions; puts appended to the new seat's log | process memory |
| Release during the rotation | committed RELEASE before any partial, from ROTATE to CLOSE | committed RELEASE before any partial, as always |
| Old seat after grace end | `session_destroy`, `close_epoch`, enclave zeroizes | the operator erases; assumption of §7.6 |
| Seal group | DKG of `σ_{e+1}` in JOIN | none |

## 9. Costs at scale

All figures in this section are estimates from the sizes of DESIGN §11.1, not measurements.

**Standing carry.** One share of `x_f` costs a dealer `(t' − 1)·33 + n'·32` bytes: 486 B at `n' = 9` and 907 B at `n' = 17`. An ECDSA slot costs twice that, 972 B and 1,814 B, because it carries `w_f` and `μ_f`. Only the first `t` valid dealings count, and a dealer that sees `t` valid dealings of a batch on the board sends none. The board therefore carries about `t·972` B = 6.8 KB per ECDSA slot at `n = 9` and `12·1,814` B = 21.8 KB at `n = 17`.

| ECDSA addresses | Unused slots each | Board bytes per handoff, `n = 9` | Days at `β = 10 %` of 2.2 MB/s |
|---|---|---|---|
| 10,000 | 16 | 1.1 GB | 0.06 |
| 100,000 | 16 | 10.9 GB | 0.57 |
| 1,000,000 | 16 | 109 GB | 5.7 |

The board's request load of 133 to 136 envelopes per second of 16,384 B is about 2.2 MB/s (DESIGN §11.3). At one million ECDSA addresses the carry no longer fits in `Δ_rot = 5` days at `β = 10 %`. A committee at that size raises `β`, lengthens `L_e`, or carries ECDSA slots in TEE mode without public commitments (O41).

**Sweep.** A request costs one `κ_0` share plus two shares per unreleased slot: at `K = 8`, `L = 2`, nine polynomials, about `7·9·486` B = 31 KB at `n = 9`. The sweep set holds only requests that are still live two days after the activation (§4.2). Ten thousand of them cost 310 MB, about 2.4 minutes of a 2.2 MB/s board, so `Δ_sweep = 1` hour holds a sweep set far larger than any expected one. O41 measures the set.

**Midnight.** One activation record per handoff in place of an ordinary checkpoint, plus one `admitBoot` per joining seat (§5.2). No write per carry, per sweep, per request or per user.

**CPU.** A new seat checks each carry batch with one random linear combination per dealer (DESIGN §5.10 item 6) and one multi-scalar multiplication over the batch. The rate at 32 ECDSA slots per address is part of O41.

## 10. What pinned the committee to fixed keys

Each place below tied the committee to one roster or one key set. Each now rotates or is scoped to an epoch.

| # | Finding | Fix | Record |
|---|---|---|---|
| A1 | §8 left in-flight requests to end VOID and their owners to re-post. | The binding epoch owns its requests, and the sweep carries the live ones (§4). | DECISIONS 80 |
| A2 | ECDSA slot shares were dealt at birth to one committee, and §8 carried only unused ones. | Every unused slot share is carried in CARRY. A slot that a live request names is owned by the binding epoch and swept. | DECISIONS 80, 82 |
| A3 | The slot roots `slr_own` and `slr_G` carry `q` committee signatures, and nothing said under which key set the contract checks them later. | A slot root commits to slot ids and points, which a carry keeps. The contract checks its certificate once, at the write, against `EKS` of the signing epoch (§5.3). | DECISIONS 83 |
| A4 | The carried VOID leaf of a reissue was checked "against the epoch key set". | It names its epoch and is checked against that epoch's `EKS`, only while that epoch is current or in grace (§5.3). | DECISIONS 83 |
| A5 | CommitteeLedger write authority had no rule for a change of signer set, and `EKS_e` was signed by boot keys of Node Registry entries alone. | The activation record carries the ROTATE with `q` governance signatures, the heartbeat and `t'` new signatures, and switches the signer set. Every checkpoint needs `t` signers (§5.1). | DECISIONS 83, 86 |
| A6 | The contract's restart rule compared boot counters of seats across neighboring checkpoints, so a roster change at the activation record looked like a whole-committee restart and forced the window jump. | A joining seat is continuous from its first checkpoint, and the rule counts continuing seats across the activation record. At most `f` seats change, so `n − f ≥ w + 1` seats stay continuous. | DECISIONS 85 |
| A7 | seald Sessions take the committee descriptor (seats, `w`, peers) at configuration. | The descriptor is epoch-scoped: each epoch has its own descriptor, and a continuing seat holds two during grace. | DECISIONS 82 (Veritee follow-up outside this repository) |
| A8 | §3.9 dealt a new backup to `E` after every rotation, which tied a step of every handoff to `E`. | The backup holds constant terms that a handoff does not change, so it stays valid. `E` refreshes only for its own membership. `E` reads the seat logs of every epoch since a slot's birth. | DECISIONS 82 |
| A9 | Birth and acknowledgement certificates and `authorize` could be read as checking committee signatures against a fixed key. | Certificates are checked at the write against `EKS` of their epoch. `authorize` proves membership in Midnight state and checks no committee signature (§5.3). | DECISIONS 83 |
| A10 | Peers admitted only boots of Node Registry seats, and `replaceSlot` and `retire` were separate operator writes. | A ROTATE admits the boots of its joining seats; the activation record retires the departing ones. | DECISIONS 79, 83 |
| A11 | Envelopes name `keylist_hash` of one epoch, so a stale envelope would stop at a change of keys. | The binding epoch owns it through grace; the sweep carries it; only an envelope ordered after the sweep is refused. | DECISIONS 80 |
| A12 | A slot binds `ρ` to `epoch ‖ ℓ`, the pool session is `slots-s-e`, and seat-log entries use `k_nf`. | A carried slot keeps its pool label, its index and its nullifier, and `k_nf` moves unchanged (§4.3). | DECISIONS 82 |
| A13 | The Image Registry has its own governance set of 7 of 9 members. | Unchanged: it approves images, not rosters. A joining seat runs an approved image. | — |
| A14 | Checkpoints needed `q` signers, fewer than the `t` that can sign, so a committee that cannot sign could keep its Midnight record alive. | Every checkpoint, the activation record included, needs `t` signers. | DECISIONS 86 |
| A15 | The HANDOVER deadline counted board height and the old leader ordered HANDOVER, so a stalled or hostile source committee held the switch. | The deadline counts Midnight blocks, and the armed committee activates itself on Midnight. | DECISIONS 84 |

## 11. Open items

| Id | Obligation | Done when |
|---|---|---|
| O5 | the reshare at `t = n − f` | unchanged in scope; it now covers every carry of §6 and the sweep, with the dual threshold of §7.4 in each committee |
| O40 | Handoff liveness | a proof that a ROTATE with `t` honest live seats in the source epoch and `t'` in the target epoch reaches HANDED_OVER by `m_D`, and that every request it owns reaches an end with no user action, under the complaint window of O5 or with the publicly verifiable reshare |
| O41 | Handoff cost | the carry of §9 is measured on the node hardware at `n = 9` and `n = 17`: dealing and checking rate per ECDSA slot, board bytes per handoff, the sweep set at the measured request rate, and `Δ_cw`; the TEE-mode carry without public commitments is specified if the board cannot carry the inventory at the target address count |
| O42 | Contract rules of the handover | the committee contract checks the ROTATE signatures, both signature sets, the boot tickets of joining seats, disjointness from `E` and every guardian set, epoch-scoped certificates, the heartbeat, the `t` signer count, the `m_D` deadline and the continuity rule for joining seats, in Compact, with a test that refuses an epoch `e` checkpoint after the activation record |
| O43 | Heartbeat on Midnight | the committee contract verifies the secp256k1 arm heartbeat under `X_f` in Compact; the edwards25519 heartbeat is verifiable now. Shared with item 42 |

## 12. Where the handoff meets item 42

Item 42 (`research/recovery-debate/SYNTHESIS.md`) proposes, as a lead pick for owner confirmation, an armed reserve Fenrir committee in place of `E`, with one Midnight operation `activate(reserve)` for scheduled handoff, dead-man recovery and governance override. This document does not specify the reserve or the dead-man trigger. It fixes the handoff so that the two use one operation:

- **Arm, then activate.** The honest handoff arms the incoming committee with its own sharing of `x_f` and of the ECDSA inventory, proves it with the heartbeat under `X_f`, and activates it by a Midnight record that only the incoming committee signs (§2.4, §5.1). A reserve committee that is already armed reaches the same activation record with no carry.
- **Midnight clocks.** Every deadline of the handoff counts Midnight blocks (§3.3), as item 42's trigger does.
- **`t` signers per checkpoint.** A landed checkpoint shows `t` seats that can sign (§5.1), which item 42's dead-man clock reads.
- **What stays with item 42.** The activation of a reserve without a ROTATE, the dead-man and equivocation triggers, the governance override, and the requests of an outgoing committee that stops after the arming. Item 42's ruling to deal each envelope to both the active and the reserve committee would let those requests finish without the sweep. Its retirement of `E` would replace the `E` rows of §6 and the disjointness check of §5.1 with the reserve committee.
