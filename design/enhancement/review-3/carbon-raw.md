# Adversarial Cryptographic and Protocol Review: Split-Line Dealing

This review audits `bundle/DESIGN.md`, `bundle/DECISIONS.md`, and `bundle/vectors/{check.py,ed.py,sizes.py}` across the five focus areas in order. Base `SCHEME` ("line dealing") properties cited by the design are treated as given except where `DESIGN.md` modifies or composes them inconsistently.

Summary of findings: **11 blocking**, **11 major**, **1 minor** (`F1`–`F23`), followed by components verified as sound.

---

## 1. Key Algebra, Multi-Shard Split, and Threshold-PRF Keying (Decisions 26–41)

### F1 — Embedded actor contributions form a cryptographic hash cycle and cannot be constructed
- **Severity:** blocking
- **Location:** `DESIGN.md` §4.6, §5.1, §5.8, §5.9; `DECISIONS.md` #34, #35
- **Claim affected:** Implementability of the two-commit embedded multi-actor path (§4.6, §5.1, §5.8 guardian seizure embedding, §5.9) and C13 (Liveness for embedded multi-actor requests)
- **Failure scenario:**
  1. Initiator `a_0` and co-signer `a_1 ∈ S'` attempt to build a two-commit multi-actor envelope (or P2 guardians `T ⊂ G` attempt to embed contributions in §5.8 step 3) so that `a_1`'s contribution sits inside `header` (`body_0`) with no collection phase.
  2. By §4.6, `a_1`'s sealed contribution to variant body `(v, g)` is:
     `ct_{a_1,v,g} = (E_{a_1,v,g} = e·G, AEAD(KDF(e·P_{v,g} ‖ E_{a_1,v,g} ‖ hd ‖ position), s_{a_1,v,g,1} ‖ … ‖ s_{a_1,v,g,L}))`,
     and §4.6 states: *"An embedded contribution is the same sealed contribution inside the request's header, with no frame and no dealing."*
  3. However, `body_0 = AEAD(k_hdr, header)` encrypts `header` (which contains `ct_{a_1,v,g}`), and `hd` is defined as:
     `hd = H(pub* ‖ commitments ‖ ciphertexts ‖ E ‖ body_0 ‖ var… ‖ cap… ‖ tail)`.
  4. Constructing the envelope requires a circular dependency `ct_{a_1,v,g} → header → body_0 → hd → ct_{a_1,v,g}` through `AEAD` and cryptographic hash `H` (`2²⁵⁶` work). `vectors/check.py` (line 458) did not catch this because it passed the literal constant `b"hd|position"` instead of hashing `body_0`.
- **Fix:** Replace `hd` with `dd ‖ v ‖ g` in the sealed-contribution KDF: `KDF(e·P_{v,g} ‖ E_{a,v,g} ‖ dd ‖ v ‖ g ‖ position)`. Because `dd = H(pub* ‖ commitments ‖ ciphertexts ‖ E)` is fixed by the outer dealing of `κ_0` before `header` is encrypted (and `P_{v,g}` is derived from `Z_{v,g} = κ_0·H_c(dd ‖ (v, g))`), the cycle disappears while binding the contribution to the exact outer dealing and variant body; separate `CONTRIB` frames continue to bind target `hd` inside their own encrypted header (§4.7 item 6).

---

### F2 — Unauthenticated `pub.auth_ref` outside `hd` and `π` enables zero-cost envelope malleation and bricks Midnight `PENDING` asset records
- **Severity:** blocking
- **Location:** `DESIGN.md` §4.6, §4.7, §5.1, §5.2, §5.4, §5.6, §7.7
- **Claim affected:** C13 (Liveness), §6.2 (Censorship resistance), and envelope uniqueness (`eid`)
- **Failure scenario:**
  1. Honest holder submits `authorize` on Midnight, consuming nullifier `nf` and moving the asset record to `PENDING` under `auth_real = H(ic ‖ hd ‖ tkc ‖ nf ‖ rh)`, and broadcasts envelope `Env` with `pub.auth_ref = auth_real`.
  2. In §4.6, `hd` hashes `pub*` (`pub` with `auth_ref` zeroed), and the line-dealing encryption proof `π` binds `hd` alone as its context. `eid` is used throughout §§3, 5, 7 without a definition.
  3. A network observer or malicious board leader intercepts `Env`, overwrites `pub.auth_ref := r_bad` (32 random bytes) to produce `Env'`, and proposes `Env'` first. `Env'` has the exact same `pub*`, `dd`, `hd`, and valid `π`, passing every pre-ordering check of §4.7 with zero scalar multiplications.
  4. **If `eid = hd`:** `Env'` commits in Block `B_1` under `eid = hd`. In TEE mode, every honest enclave witnesses `open(eid) → pos(B_1)` (§7.7); when the real `Env` arrives in `B_2` with the same `eid` and `pos(B_2) ≠ pos(B_1)`, all `w` peers refuse the `open` witness. Meanwhile `Env'` fails §5.4 item 2 (`r_bad` never matches `auth_real`) and never settles `auth_real`. Because `auth_real` already consumed `nf` on Midnight bound to `hd` and only `q` committee signatures on `settle(auth_real, VOID/EXPIRED)` can release `PENDING` (§5.6), **the user's asset record is permanently frozen in `PENDING`**.
  5. **If `eid = H(full frame)`:** Any unprivileged attacker can mutate `auth_ref` into thousands of distinct 16 KiB envelopes at zero CPU cost, each passing §4.7's `π` check and forcing every committee node to run `π` verification, Diffie-Hellman share decryption, and threshold-PRF header opening (`Y_{i,hdr}`).
- **Fix:** Define `eid = H(hd ‖ auth_ref)` (covering `π` via board check) and bind `H(hd ‖ auth_ref)` as the context of `π` instead of `hd`. There is no circularity because the wallet computes `hd` and `auth = H(ic ‖ hd ‖ tkc ‖ nf ‖ rh)` before computing `π` (§5.3).

---

### F3 — Missing `ic` and `r_tkc` in `header` makes the §4.7 / §5.4 check that `auth` opens to `hd` and `tkc` impossible to execute
- **Severity:** blocking
- **Location:** `DESIGN.md` §4.6, §4.7 item 5, §5.3, §5.4 item 2
- **Claim affected:** C6 (Authorization enforcement) and implementability of Admission (§5.4)
- **Failure scenario:**
  1. By §5.3, Midnight `authorize` publishes `auth = H(ic ‖ hd ‖ tkc ‖ nf ‖ rh)`, `nf`, `rh`, and the proof, *"and nothing else"*, where `ic = Commit(intent; r_ic)` and `tkc = Commit(tickets_padded_32; r_tkc)` are hiding commitments.
  2. At Admission (§4.7 item 5, §5.4 item 2), each node must verify that `auth_ref` on Midnight equals `auth` and *"opens to `hd` and to the `tkc` of the header"*.
  3. Inspecting `header` in §4.6: in non-TEE mode `header` omits both `ic` and `r_tkc`; in TEE mode v1 `header` includes `intent` and `r_ic` (allowing recomputation of `ic`) and still omits `r_tkc`.
  4. Without `r_tkc` (both modes) and `ic` (non-TEE mode), no node can recompute `tkc` from the header's tickets or verify `H(ic ‖ hd ‖ tkc ‖ nf ‖ rh) == auth_ref`. If an implementation skips the hash check and only checks that `auth_ref` exists on Midnight, an initiator attaches a finalized `auth_ref` from a 1-satoshi decoy spend to an envelope carrying arbitrary unauthorized tickets, breaking C6.
- **Fix:** Include the 32-byte hiding commitment `ic` (in non-TEE mode) and the 32-byte commitment randomness `r_tkc` (in both modes) inside `header` (`+64` bytes). `ic` is hiding so non-TEE nodes learn nothing about `intent`, and `r_tkc` opens only the tickets that nodes already read upon opening `header`.

---

### F4 — ECDSA tickets `(ℓ, h)` do not bind slot `ℓ` to the authorized address `cm_addr`, enabling P2 hold/blacklist/covenant bypass on Ethereum and cross-account slot burning
- **Severity:** blocking
- **Location:** `DESIGN.md` §3.4, §3.6, §4.1, §4.4, §4.7 items 3 & 7, §5.3 items 4–5, §5.4; `DECISIONS.md` #8, #27, #30
- **Claim affected:** C6 (Authorization enforcement), C7 (Hold enforcement), R1/R4 (P1 covenants and P2 holds/blacklists), and C13 (ECDSA liveness)
- **Failure scenario:**
  1. In Schnorr/Ed25519, `x_f` is common to all addresses and the sighash challenge `c` hashes `x(Q)` or `X`. In ECDSA (§3.6, §4.4), committee slot `ℓ` holds shares `(w_{f,i}, μ_{f,i})` specific to one address `X` (`μ_f + μ_A = k⁻¹·x`), while an Ethereum EIP-1559 unsigned payload `0x02 ‖ rlp([chain_id, nonce, max_priority_fee, max_fee, gas, to, value, data, access_list])` and its hash `h` contain **no sender address `X`** (sender is recovered from `(h, v, r, s)` via `ecrecover`).
  2. By §4.1, *"Slot ids never appear on Midnight"*, and `tk = (ℓ, h)` carries nothing linking `ℓ` to `cm_addr` in `authorize` (§5.3 items 4–5). In non-TEE mode nodes do not know which `cm_addr` `authorize` spent; in TEE mode v1 §4.7 items 3 & 7 also omit checking `slot_record[ℓ].X == header.X`.
  3. **P2 hold / blacklist / covenant bypass (`0` corrupt nodes):** Sanctioned owner `Mal` of a held P2 Ethereum EOA `X_frozen` (holding e.g. 100M USDC) creates an unheld, covenant-free P1 decoy EOA `X_decoy` at the same Ethereum account `nonce` `ν`. `Mal` constructs `tx` (`nonce = ν, value = 0, to = USDC, data = transfer(D_blacklisted, 100M)`), proves `authorize` on Midnight against `X_decoy`'s asset record with ticket `tk = (ℓ_frozen, h)` naming an unused slot `ℓ_frozen` of `X_frozen`, and puts `Mal`'s `X_frozen` user half `s_u = h·w_{u,frozen} + r·μ_{u,frozen}` in the variant body. `authorize` passes all checks (`X_decoy` is unheld, `h` matches `tx`, and `rh` is encrypted under `X_decoy`'s dummy P1 hold key so `X_frozen`'s hold authority cannot decrypt `rh` to revoke it). Honest nodes release `s_{f,i} = h·w_{f,i,frozen} + r·μ_{f,i,frozen}`, producing `s = s_u + s_f = k_{ℓ_frozen}⁻¹(h + r·x_frozen)`, which `ecrecover`s to `X_frozen` on Ethereum and drains the frozen P2 account.
  4. **Cross-account slot-burning griefing:** Any attacker who knows another user Alice's unused ECDSA slot IDs (e.g. sequential board IDs or via 1 curious non-TEE node) puts Alice's slot IDs (`6` per P2WPKH request) in `X_decoy` envelopes. Honest nodes admit each envelope and permanently burn Alice's slots (§4.5 rule 4) when combine fails, exhausting all `N_slot = 32` slots in 6 requests.
- **Fix:** Commit a Merkle root `slots_root` of `(ℓ, R_ℓ)` inside the Midnight asset record at birth and at each slot refill (backed by a `q`-signed committee slot certificate so individual slot IDs remain hidden on Midnight), prove inside `authorize` that every ticket's `ℓ` opens in `cm_addr`'s `slots_root`, and in TEE mode v1 check `slot_record[ℓ].X == header.X` at §4.7 item 3.

---

### F5 — P2 owner can burn all `G_g = 4` guardian-reserved ECDSA slots in ordinary spends, making P2 ECDSA addresses permanently unseizable (and `G_g = 4 < K·L = 6` on P2WPKH)
- **Severity:** blocking
- **Location:** `DESIGN.md` §2.3, §3.8, §4.4, §4.7, §5.3, §5.8; `DECISIONS.md` #5, #8
- **Claim affected:** R4 and §5.8 (P2 Seizure on ECDSA chains)
- **Failure scenario:**
  1. At birth of a P2 ECDSA address, guardians `G` receive escrow shares of `(w_u, μ_u)` only for `G_g = 4` reserved slots (§2.3, §3.8); an escrow of `x_u` alone cannot sign unreserved ECDSA slots (§3.8). The P2 owner generated those 4 slots and holds `(w_u, μ_u)` for them as well.
  2. Midnight `authorize` uses a private source tag (`DECISIONS.md` #8; `DESIGN.md` §5.3) and sees no slot IDs, while committee nodes see `ℓ` and do not see whether `authorize` used the `owner` source or the `seizure` source (and §4.7 / §5.4 contain no reserved-slot rule in either mode).
  3. Immediately after birth, the P2 owner executes 4 tiny legal owner spends on Ethereum naming the `G_g = 4` guardian-reserved slots. Honest nodes admit them and permanently burn all 4 reserved slots (§4.5 rule 4). The owner still has `28` unescrowed slots for normal use, while any future settled Midnight seizure order fails permanently because `G` has `0` usable slots and cannot run §3.6 refill without the user.
  4. Independently, on Bitcoin P2WPKH (`K = 3`, `L = 2`, §2.3), a single 2-input spend consumes `K·L = 6` ECDSA slots, so `G_g = 4` cannot execute even one 2-input P2WPKH seizure.
- **Fix:** Split `slots_root` (from F4) in the P2 asset record into `owner_slots_root` and `guardian_slots_root`, enforce in the `authorize` circuit that `owner` / `recovery` sources open slots only in `owner_slots_root` while `seizure` opens slots only in `guardian_slots_root`, and set `G_g` to a multiple of `K·L_max` (at least `12` on P2WPKH).

---

### F6 — Reusing `k_hdr` in `Enc_{k_hdr}(txid)` at `FINAL` either leaks `txid` and `header` to TEE operators and board observers or prevents `FINAL` quorum formation
- **Severity:** blocking
- **Location:** `DESIGN.md` §4.6, §5.1, §5.6, §6.1; `bundle/vectors/sizes.py` line 8
- **Claim affected:** C10 (TEE Blindness), B1, B5, and C13 (`FINAL` settlement)
- **Failure scenario:**
  1. `k_hdr = KDF(Z_hdr)` has no subkey labels (§4.6), and envelope AEAD ciphertexts omit an explicit nonce (`sizes.py` line 8 budgets `hdr = 150 + 16`, i.e., a 16-byte tag with implicit fixed nonce `0`).
  2. At `FINAL`, `q` nodes post `(eid, FINAL, digest)` carrying `Enc_{k_hdr}(txid)` on the public board (§5.1, §6.1).
  3. **If each node chooses a random IV:** the `q` honest nodes produce `q` distinct ciphertexts, so their `FINAL` vote digests do not match and no `q`-vote `FINAL` quorum forms.
  4. **If nodes use deterministic nonce `0`:** `body_0 = AEAD(k_hdr, 0, header)` and `C_tx = Enc_{k_hdr}(0, txid)` reuse the identical stream-cipher keystream (`ChaCha20-Poly1305` or `AES-GCM`). Any passive board observer or TEE operator computes `body_0[0..32] ⊕ C_tx = header[0..32] ⊕ txid`. Because `header[0..4]` holds low-entropy fields (`request_type = 0x00`, `K = 8`, `L = 2`, `G = 2`), XORing `(0x00, 8, 2, 2)` reveals `txid[0..4]`, uniquely pinpointing the confirmed host-chain transaction; XORing that full 32-byte `txid` back in decrypts `header[0..32]` (including the committee slot IDs `ℓ(g, j)`) and compromises the AEAD authentication key.
- **Fix:** Derive a separate subkey `k_fin = KDF(Z_hdr ‖ "final")` and compute `Enc_{k_fin}(0, txid)` deterministically with fixed nonce `0`.

---

### F7 — Network-created shards for offline holders (`X_u = U + Hq_st(e_c·U)·G`) cannot satisfy the mandatory `BIRTH` proof of possession `pop_u`
- **Severity:** blocking
- **Location:** `DESIGN.md` §3.1 steps 1 & 3, §3.3, §10 R3
- **Claim affected:** R3 (Network-created user element for offline holders) and §3.1 Birth check
- **Failure scenario:**
  1. Holder registers shielded receive key `U = u·G` once per charter on Midnight and goes offline (§3.1 step 1).
  2. A payer or issuer picks `e_c`, computes `E_c = e_c·G` and `X_u = U + Hq_st(e_c·U)·G` (*"Only the holder computes `x_u = u + Hq_st(u·E_c)`. The creator and the committee know `X_u` and never `x_u`"*), and sends a `BIRTH` envelope so the new address obtains a birth certificate and becomes fundable (§3.1 steps 3–4).
  3. In §3.1 step 3, every committee node requires `pop_a = Schnorr_{x_a}(Hq_pop(SL1/pop ‖ X_f ‖ X_a ‖ slot_a ‖ charter_id ‖ chain_id))` on every top-level shard and refuses `BIRTH_OK` without it; `FenrirAssets` rejects any P1/P2 asset record lacking a birth certificate.
  4. Because the holder is offline and nobody else knows `x_u`, `pop_u` cannot be computed and no network-created address can ever pass birth check.
- **Fix:** Check a Schnorr PoP of `u` when `U` is registered in the charter on Midnight, and for network-created shards replace `pop_a` in `BIRTH` with a zero-knowledge proof of `(U, e_c)` showing that `U` belongs to `charter_id` and `X_a = U + Hq_st(e_c·U)·G` (keeping `U` private so multiple addresses of one offline holder remain unlinkable to non-TEE nodes).

---

### F8 — Non-TEE optimistic-combine failure (`f + 1` combiners vs `f + 1` `VOID` posts) cannot reach `VOID`, and ECDSA blame checks lack OR-escrow and nested-gate commitments
- **Severity:** major
- **Location:** `DESIGN.md` §3.6, §3.8, §4.6, §4.7 item 8, §5.1, §5.6 steps 5–6; `DECISIONS.md` #37; `bundle/vectors/sizes.py` line 13
- **Claim affected:** C13 (Liveness), C20 (Reissue after failed contribution, §5.9), and §4.7 item 8 blame identification
- **Failure scenario:**
  1. **Unreachable `VOID` in non-TEE mode:** At `n = 9, f = 2`, §5.6 step 5 sends variant PRF partials `Y_{i,(j_g,g)}` and signature partials only to `f + 1 = 3` combiners chosen by `H(eid ‖ g)`. Suppose a malicious co-signer sends a bad scalar `s_a` (or a dishonest initiator substitutes `P_{j_g,g} ≠ y_{j_g,g}·G` or malformed `var_{j_g,g}` AEAD) and `f = 2` of the `3` combiners are Byzantine and stay silent. Only **1** honest combiner opens the variant body and sees the failure, emitting **1** `VOID` post — strictly fewer than the **`f + 1 = 3` `VOID` posts** required for `VOID` (§5.1). Non-combiner nodes cannot verify the failure because the variant body and capsule stay sealed to them (contradicting §5.1's statement that `VOID` posts are *"individually signed, because they void a request and any party verifies them"*). The request cannot `VOID` or reissue; it triggers an unnecessary Generation 2 and stalls until `exp`.
  2. **Missing ECDSA escrow/nested blame commitments:** When an ECDSA combined signature fails on a P2 guardian seizure (`S = T ⊂ G`), §4.7 item 8 checks `s_a·R_ℓ = λ_a·(h·W_a + r·M_a)` using *"session party index"* (§4.6) and *"`W_a, M_a` from the slot record"*, while capsules carry only one 33-byte base-`G` point `λ_a·X_a` (§4.6, `sizes.py` line 13). However, OR-gate escrow holders (`G`) are explicitly **not** session parties of §3.6 (line 212) and have no session party index in the §3.6 slot record, and `λ_a·X_a` in base `G` cannot verify an equation in base `R_ℓ`. Likewise, for nested threshold gates (a `k_1`-of-`m_1` group whose member `3` is a `k_2`-of-`m_2` subgroup — omitted from `ECASES` in `check.py` line 341), §3.6 step 7 specifies only downward dealing inside each group; if signing set `{1, 2}` omits subgroup `3`, `{1, 2}` lack shares of subgroup `3`'s session-party additive halves `Σ_{p∈sub} (w_p, μ_p)` so `s` does not reconstruct `k⁻¹(h + r·x)`.
- **Fix:** (1) On combine failure after verifying `t` DLEQ-valid variant PRF partials, have the honest combiner broadcast `(Z_{j_g,g}, t proved partials)` to all committee nodes so all `t ≥ f + 1` honest nodes verify the bad contribution/`P_{v,g}` and post `VOID`. (2) Record §3.8 ECDSA escrow Feldman commitments `(Com_{R_ℓ}(w), Com_{R_ℓ}(μ))` in the nodes' slot record keyed by canonical leaf path, and in §3.6 step 7 require nested subgroup leaves to deal their additive `(w_p, μ_p)` into the top-level group's polynomial before sub-sharing the subgroup's evaluated share downward.

---

### F9 — Top-level `slot_a` in `CL`/`ρ_a` gives group co-signers identical FROST binding factors, and `cm_addr` omits `chain_id` and Taproot `root`
- **Severity:** major
- **Location:** `DESIGN.md` §2.4, §3.1, §3.2, §4.2
- **Claim affected:** C1 (Address binding), C17/C19 and O20 (FROST unforgeability for threshold/escrow group actors)
- **Failure scenario:**
  1. §3.1 defines `slot_a` only for **top-level shards** (*"with the top-level shard points in charter slot order... bound to the actor's own point, its charter slot `slot_a`"*). §4.2 then defines `CL = R_0 ‖ (slot_a ‖ pool_id_a ‖ ν ‖ D_{a,ν} ‖ E_{a,ν})_{a∈S'} ‖ ℓ ‖ D_ℓ ‖ E_ℓ` *"with the actors in charter slot order"* and `ρ_a = Hq_bind(SL1/bind-act ‖ suite ‖ epoch ‖ slot_a ‖ CL ‖ pm)`.
  2. When `k_γ ≥ 2` members of one threshold group (or `t_g = 3` guardians of `G`) co-sign, they belong to the same top-level shard slot. Using top-level `slot_a` leaves their order in `CL` undefined and gives two members `a_1, a_2 ∈ S'` the **same binding factor `ρ_{a_1} = ρ_{a_2}`**. Because actor pool posts carry no proof of possession (§3.10: *"the committee neither checks nor claims them"*), corrupt member `a_2` posts `(D_2, E_2) = (r_d·G − D_1, r_e·G − E_1)`, yielding `(D_1 + ρ·E_1) + (D_2 + ρ·E_2) = (r_d + ρ·r_e)·G` — canceling honest member `a_1`'s AOMDL challenge pair `(D_1, E_1)` out of `R_A` and breaking the FROST AOMDL simulation/extraction of O20.
  3. In §3.1 step 3 and §3.2, nodes compute `Q = P + H_TapTweak(x(P) ‖ root)·G` and check the chain address, yet `cm_addr = Commit(X ‖ charter_id ‖ profile ‖ H(Γ); r)` omits both `chain_id` and `root` (or `Q`). Thus `BIRTH_OK(eid, cm_addr)` neither binds the checked chain nor gives `authorize` (§5.3 item 5) a committed `root` from which to compute `x(Q)` when a charter enables the §3.7 exit leaf.
- **Fix:** Define `slot_a` everywhere as a canonical fixed-width tree-path leaf ID `(top_slot, gate_path, member_index)` sorted lexicographically, and commit `chain_id` and `root` (or `Q`) inside `cm_addr`.

---

### F10 — Envelope size calculation (`sizes.py` / §11.1) omits ECDSA per-actor header weight and session-party index
- **Severity:** minor
- **Location:** `DESIGN.md` §4.6, §11.1; `bundle/vectors/sizes.py` lines 10–15
- **Claim affected:** §4.6 / §11.1 ECDSA signing-set capacity estimates per 16 KiB frame
- **Failure scenario:**
  1. §4.6 specifies that `header` carries, per actor `a ∈ S'`, *"its position `1..|S'|` in this request, the commitment `H(τ_a)` of its contribution token, and on ECDSA its session party index and weight"* (`λ_a` is a 32-byte scalar mod `N_s`, plus position and party index = at least `66` bytes per ECDSA actor).
  2. `vectors/sizes.py` (line 12) sets `tbl = 32` for both Schnorr and ECDSA, undercounting each ECDSA actor by ~34–36 bytes and slightly overstating §11.1's `|S|` table (`42 / 38` on P2WPKH and `> 60` on Ethereum).
- **Fix:** Add `36` bytes to `tbl` when `ecdsa=True` in `sizes.py` (or have nodes recompute `λ_a` from the leaf IDs of `S` as they already do in §2.4 rule 3, removing `λ_a` from the header) and regenerate the §11.1 table.

---

## 2. Nonce and Slot Rules

### F11 — `coldStart` (§7.11) and `recover` (§5.8) reshare ECDSA slots used after the last 60s Midnight checkpoint, leaking both user key `x` and the global committee root key `x_f`
- **Severity:** blocking
- **Location:** `DESIGN.md` §2.2, §3.9, §5.8, §7.4, §7.11 steps 1 & 2, §7.13
- **Claim affected:** C5 (No spend without the committee), C6, C7, C12 (One nonce use), C15 (Recovery), and C16 (Cold start)
- **Failure scenario:**
  1. Midnight checkpoints occur every `60 s` (§7.13), whereas ECDSA spends release in `1.15 s` (`board_first`) or `F_M + 0.6 s` (`Midnight-first`), and Midnight `authorize` records never contain slot IDs (§4.1).
  2. Under §7.11 step 2 (`coldStart`, triggered on Midnight by `q = 6` operator signatures with **intact enclaves**, or by a fleet storage outage) and §5.8 (`recover`), recovery group `E` reshares `x_f` and every ECDSA slot not claimed on the board *up to the latest Midnight checkpoint `H_cp`*.
  3. **Key-extraction scenario (`q = 6` malicious TEE operators with `0` broken enclaves, or a real crash within 60 s):**
     - `t = 0 s`: Midnight records checkpoint `H_cp`.
     - `t = 5 s`: An operator (holding its own P1 ECDSA address `X = (x_u + tw + x_f)·G`) completes a spend on ECDSA slot `ℓ_5` for hash `h_1`, obtaining `s_1 = k⁻¹(h_1 + r·x) mod N_s`.
     - `t = 10 s` (before the `60 s` checkpoint): `q = 6` operators wipe their VM disks and sign `coldStart(committee_id)`. Fresh enclaves boot at replay floor `H_cp`. Because `ℓ_5` was unclaimed at `H_cp`, `E` reshares `(w_{f,i}, μ_{f,i})` of `ℓ_5` to the fresh enclaves.
     - `t = 20 s`: The operator submits a second spend on **the same slot `ℓ_5`** with `h_2 ≠ h_1`, obtaining `s_2 = k⁻¹(h_2 + r·x) mod N_s`.
     - The operator solves:
       `k = (h_1 − h_2)·(s_1 − s_2)⁻¹ mod N_s`,  `x = (s_1·k − h_1)·r⁻¹ mod N_s`,  `x_f = (x − x_u − tw) mod N_s`.
     - Because `x_f` is the single secp256k1 root key shared across Suite 1 (ECDSA) and Suite 2 (Bitcoin P2TR, §2.2), **every secp256k1 address in Fenrir permanently loses committee co-custody, covenants, and holds**. (Under a benign outage in that 60 s window, any honest user whose slot is reused broadcasts `(r, s_1)` and `(r, s_2)` on chain, exposing `x` to the public.)
  4. Additionally, in §7.11 step 1 (all `n` nodes reboot with Tier 0 intact), ECDSA slot shares live only in RAM (§7.4) and are lost on all `n` nodes simultaneously, yet step 1 specifies no restoration or refill step for ECDSA slots.
- **Fix:** Do not back up or reshare ECDSA slot shares through `E` (§3.6 step 8, §3.9, §5.8, §7.11): whenever RAM state is lost on `> n − t` nodes (`coldStart`, `recover`, or fleet reboot), burn all existing ECDSA presignature slots and require a fresh §3.6 slot session before the next ECDSA spend.

---

### F12 — Opening `body_0` before `auth_ref` is in force lets 1 corrupt non-TEE node censor any Midnight-first request by sniping its slots via `board_first`
- **Severity:** blocking
- **Location:** `DESIGN.md` §4.1, §5.2, §5.3, §6.1, §6.2, §9.1 C13, §9.3; `DECISIONS.md` #29, #35
- **Claim affected:** C13 (Liveness), §6.2 (Censorship resistance), and §9.3 (*"C6: the header opens before the authorization is in force → Proof obligation: none"*)
- **Failure scenario:**
  1. When a Midnight-first request `Env_victim` (e.g. any P2 spend, P2 seizure, or stateful P1 spend, all forbidden from `board_first` by §5.3) is posted, the board orders and opens `body_0` in `C + h ≈ 1 s` while `authorize` waits `F_M` (multiple 6 s Midnight blocks) for finality (§5.3). By §4.1, its committee slots `ℓ(g, j)` remain **unreserved** until `auth_ref` is in force and `q` nodes vote `OPENED`/`ADMIT`.
  2. At `t = 1 s`, **1 corrupt non-TEE node** (`|C| = 1 ≤ f`) reads `Env_victim`'s opened header, learning its unreserved slot `ℓ(1, 1)` (plus fee rate, request type, and on ECDSA the account, §6.1).
  3. The corrupt node immediately posts a `K = 1, L = 1` `board_first` stateless-P1 envelope `Env_snipe` naming `ℓ(1, 1)` (with an intentionally invalid `s_0` so no host transaction confirms). `Env_snipe`'s authorization is verified on the board without waiting for `F_M`, so within `2C ≈ 1–2 s < F_M` all `q` honest nodes vote `ADMIT` on `Env_snipe`, claiming and permanently burning `ℓ(1, 1)` (§4.5 rule 4).
  4. When `Env_victim`'s `authorize` finalizes at `t = F_M`, every honest node sees `ℓ(1, 1)` already claimed/burned, rejects `Env_victim`, and posts `VOID` — refuting §6.2 (*"In non-TEE mode Byzantine nodes see the header after OPENED... They cannot stop the release"*) and C13.
  5. Even without an attacker, at §11.3's 160–400 req/s (`640–1,600` slots/s) over ~37 s of proving (`25 s`, §11.4) plus `F_M` finality, uncoordinated sampling from a public unclaimed pool (§4.1) causes heavy birthday slot collisions unless the RAM pool holds `> 10⁵` pre-dealt slots.
- **Fix:** Hold header PRF partials `Y_{i,hdr}` until `auth_ref` is in force (ordering still runs in parallel with `F_M`, adding just one peer hop `h ≈ 50 ms` to total latency: `max(F_M, C) + C + 3h`), so `body_0` never exposes unreserved slot IDs before the block that reserves them; and size or shard the unclaimed slot pool explicitly for the `proving + F_M` concurrency window.

---

### F13 — TEE peer witness `slot` key `(node, ℓ)` omits `(epoch, suite)` and ECDSA address scope, causing false witness refusals
- **Severity:** major
- **Location:** `DESIGN.md` §4.2, §4.6, §7.7, §12 O15
- **Claim affected:** C13 (TEE-mode liveness across suites, epochs, and ECDSA addresses)
- **Failure scenario:**
  1. Slot IDs `ℓ` are 4-byte integers (§4.6) scoped per `(suite, epoch)` for Schnorr (§4.2 hashes `suite ‖ epoch ‖ ℓ`) and per address (`0..N_slot−1`) for ECDSA (§3.6).
  2. In §7.7, the TEE peer witness log keys `slot` entries solely by `(node, ℓ) → H(tk)`, and witness entries above the latest checkpoint (or prior to O15 log compaction) persist across requests and across the `ROTATE` grace period.
  3. Node `i` signs Suite 2 (secp256k1) slot `ℓ = 0` with `slot(i, 0) → H(tk_btc)`. When node `i` next signs Suite 3 (Ed25519) slot `ℓ = 0` (or slot `0` in `epoch + 1` before compaction, or slot `0` of another ECDSA address) with `H(tk_2) ≠ H(tk_btc)`, all `w` peers see an existing entry for `(i, 0)` with a different digest and refuse to ack (§7.7), stalling release.
- **Fix:** Key `slot` witness entries by `(node, suite, epoch, ℓ)` for Schnorr suites and `(node, cm_addr, ℓ)` for ECDSA.

---

## 3. Merged State Machine and Board-First Authorization

### F14 — Returning Midnight records to `UNSPENT` on post-release `EXPIRED` and on post-`ADMIT` share-complaint `VOID` leaves live host-chain signatures alongside `UNSPENT` Midnight state
- **Severity:** blocking
- **Location:** `DESIGN.md` §4.7, §5.1, §5.2, §5.4, §5.6, §9.1 C6/C7/C11, §9.2; `DECISIONS.md` #29
- **Claim affected:** C6 (Authorization enforcement / cumulative covenants), C7 (P2 Hold enforcement — broken even with `0` corrupt nodes and intact TEEs), C11 (One spend per record state), and §9.2 (*"Fewer than `t` broken enclaves keeps C6, C7"*)
- **Failure scenario:**
  1. **Scenario A — Post-release `EXPIRED` (`0` corrupt nodes, all 9 TEE enclaves intact):**
     - On Day 1, unheld P2 owner `Mal` posts a valid spend `Env_1` sending 100 BTC to `D_clean` (an unblacklisted address `Mal` controls) with a `1 sat/vB` fee grid (`authorize` checks only a fee *ceiling*, §5.3 item 2) and short board expiry `exp = height + 20` (~20 s, chosen by initiator in `pub.exp`, §4.6).
     - All 9 intact enclaves admit `Env_1`, release `(R_1, s_1)`, and broadcast `tx_1`; `Mal` records the signed `tx_1`.
     - 20 s later (before the next Bitcoin block), `exp` passes, `Env_1` enters `EXPIRED`, and `q` honest enclaves submit `settle(auth_1, EXPIRED)` on Midnight, **returning the asset record to `UNSPENT` with a fresh nullifier** (§5.6).
     - On Day 30, law enforcement places a P2 hold (`SetHold(tag)`) and settles a seizure order on Midnight. `Mal` attaches a high-fee CPFP child transaction to the saved `tx_1` and mines it on Bitcoin, bypassing the hold and front-running the guardians' seizure. The same loop lets a P1 user collect arbitrarily many signed transactions on multi-input/cumulative-limit charters while each `EXPIRED` resets the Midnight spend state.
  2. **Scenario B — Merged ACK/ADMIT share-complaint race (`f = 2` corrupt nodes `{8, 9}` at `n = 9, q = 6, t = 7`):**
     - `Mal` (colluding with `{8, 9}`) posts `Env_1` (at a high fee rate, or on a non-expiring Solana durable nonce) whose outer dealing gives valid `κ_0` shares to 5 honest nodes `{1..5}` and `{8, 9}` (`7 = t` shares) and garbage shares to 2 honest nodes `{6, 7}` (`π` still verifies, as §5.2 line 516 notes).
     - Because §5.2 sends `Y_{i,hdr}` without waiting for ACKs or a complaint window, `{1..5, 8, 9}` immediately open `body_0`, and `{1..5, 8}` (`6 = q` votes) commit `ADMIT` in Block `B_2` before `{6, 7}`'s complaint is ordered.
     - `{1..5}` send signature partials `s_{f,1..5}` to the combiners; `Mal` grinds `salt` so `8` is a combiner, and `8` combines `{1..5, 8, 9}` (`7 = t` partials) to obtain `(R_1, s_1)` **privately without broadcasting**, while honest combiners receive at most `5 < 7` partials and cannot broadcast.
     - In Block `B_3`, `{6}`'s valid share complaint orders, all honest nodes post `VOID` (§4.7, §5.1), and the committee settles `settle(auth_1, VOID)`, resetting Midnight to `UNSPENT` while `Mal` holds a secret, high-fee host signature `(R_1, s_1)`.
- **Fix:** (1) Require a 1-block complaint window between `ORDERED` and `ADMIT` (or forbid share-complaint `VOID` once `q` `ADMIT` votes commit, with combiners forwarding `Z_{j_g,g}` on release). (2) Once any honest node enters `RELEASED`, never return the Midnight asset record cleanly to `UNSPENT` on `EXPIRED`/`VOID`: transition it to a `RELEASED_UNCONFIRMED` state on Midnight where covenants remain debited, P2 holds trigger immediate guardian CPFP/RBF seizure, and any subsequent owner `authorize` must spend the exact same pinned input/nonce to supersede `tx_1` on chain.

---

### F15 — `board_first` releases host signatures before Midnight inclusion; root-age expiry during relay rejects `authorize` on Midnight and permanently strands change outputs
- **Severity:** blocking
- **Location:** `DESIGN.md` §5.3, §5.6, §9.1 C6/C11, §12 O29; `DECISIONS.md` #29
- **Claim affected:** C11 (One spend per record state), C6, R5 (Spendability of change), and completeness of O29
- **Failure scenario:**
  1. For a `board_first` P1 charter (§5.3), nodes verify `authorize` against finalized Midnight root `Root_M` within the charter's root-age bound `Δ_root`, order the call in Block `B_1`, release and broadcast the signed host transaction `tx_1` in `1.15 s` (§11.2), and relay `(authorize, QC(B_1))` to `FenrirAssets` on Midnight (`~6 s` block time + finality).
  2. Suppose `Root_M` has age `Δ_root` when `B_1` commits at `t = 1 s`. `tx_1` is broadcast at `t = 1.15 s` and confirms on Bitcoin, creating change output `U_chg`. When the relay transaction reaches Midnight at `t ≥ 6 s` (or later under Midnight congestion), Midnight has advanced past `Δ_root` (or rotated `Root_M` out of its ledger Merkle-root history) and **rejects the relayed `authorize`**.
  3. Because `authorize` never entered `PENDING` on Midnight, `settle(auth, FINAL)` (§5.6) cannot execute: the successor Midnight asset record for `U_chg` is **never created**, permanently stranding `U_chg` inside Fenrir (`U_chg` has no asset record to satisfy §5.3 item 1). Moreover, `nf` stays unspent on Midnight, so a `coldStart` or `ROTATE` that resets the board's pending `nf` set allows a second `authorize` on `nf`.
  4. Additionally, §5.3 step 3 states *"The board orders the call and records `nf` in its pending set. A second call with the same `nf` is refused in board order"* while §2.1 says the board *"interprets nothing"*. If `nf` is recorded before proof verification (step 2), a mempool observer copies `nf` from the cleartext `board_first` post into an invalid proof ordered ahead of the real call, blocking `nf`. O29 (§12) omits both directions.
- **Fix:** (1) Record `nf` in the pending set only after proof verification succeeds. (2) Enforce a strict relay safety margin on the board (`age(Root_M) ≤ Δ_root − Δ_relay_margin` where `FenrirAssets` and Midnight's root ring buffer retain roots up to `Δ_root`), persist the board's pending `nf` set in Midnight checkpoints and rotation handover, and expand O29 accordingly.

---

### F16 — Node-local `STALLED` predicate lets a corrupt actor + `f` corrupt nodes deadlock collecting requests at both `n = 9` and `n = 17`
- **Severity:** major
- **Location:** `DESIGN.md` §4.7 item 6, §5.1, §5.7, §5.9 step 6; `DECISIONS.md` #35
- **Claim affected:** C13 (Liveness), C20 (Reissue after `Δ_c`), and O28
- **Failure scenario:**
  1. At launch (`n = 9, f = 2, q = 6, t = 7`), corrupt actor `a ∈ S'` (colluding with corrupt nodes `{8, 9}`) posts contribution frame `CF_a` whose outer dealing `κ_c` gives valid shares to 5 honest nodes `{1..5}` and `{8, 9}` (`7 = t`), and bad shares to 2 honest nodes `{6, 7}`.
  2. `{8, 9}` send `Y_{8,hdr}, Y_{9,hdr}` for `CF_a` **only to `{1..5}`** and remain silent thereafter.
  3. `{1..5}` combine `7 = t` partials, decrypt `CF_a`, attach `a`'s contribution to their local actor slot table, and vote `ADMIT` (`5 < q = 6` votes — not `ADMITTED`). `{6, 7}` hold only `5 < 7` partials and cannot open `CF_a` (and §5.7 states `CF_a` *"has no state of its own after it is attached or ignored"*, so `{6, 7}`'s share complaint does not detach `CF_a` at `{1..5}`).
  4. When `exp_c` passes, §5.1 / §5.9 step 6 triggers `VOID (STALLED)` at a node only when *"a slot of the actor slot table [is] empty"*. Nodes `{1..5}` have no empty slot and emit `0` `VOID` posts; `{6, 7}` emit **`2 < f + 1 = 3` `VOID` posts** (at `n = 17, f = 5`, `{13..17}` send partials to `{1..8}`, leaving `{9..12}` to emit **`4 < f + 1 = 6` `VOID` posts**). Neither `ADMITTED` nor `VOID` is reached, blocking §5.9 reissue until `exp`.
- **Fix:** Define `STALLED` as a board-global predicate: every honest node posts `VOID (STALLED)` if board height `exp_c` commits without `q` `ADMIT` votes on the board, and detach any `CONTRIB` frame against which a valid share complaint is ordered.

---

### F17 — P2 hold check compares a Midnight block height to a host-chain `OBS` height, and Generation 1 release (`F_M + 0.6 s`) always outruns `rh` revocation
- **Severity:** major
- **Location:** `DESIGN.md` §5.4, §5.5, §11.2
- **Claim affected:** C7 (Hold enforcement on pending P2 spends via `rh` and `revoke`)
- **Failure scenario:**
  1. §5.5 specifies: *"Before each release, a node checks on Midnight that `auth_ref` is not revoked, at a Midnight height at least as new as the anchor of the generation."* However, the generation's anchor (§5.4) is entry `f + 1` of the nodes' `OBS` reports of **host-chain block heights** (e.g. Bitcoin height `880,000` vs Midnight height `50,000`), which cannot be compared across chains.
  2. Furthermore, `rh` is included in `authorize` specifically so the hold authority can trial-decrypt new `rh` handles and submit `revoke(auth_id)` to stop a pending spend before release (§2.2, §5.5: *"moves the request to VOID if nothing was released"*). Yet the board opens `Env` while `authorize` finalizes and releases Generation 1 in `C + 2h ≈ 0.6–1.1 s` after `authorize` finalizes (§11.2). Because Midnight produces a block every `~6 s` plus `F_M` finality, any `revoke(auth_id)` submitted in response to `authorize` appearing on Midnight finalizes at least `≥ 6 s` **after** `authorize` finalizes — after Generation 1 has already been signed and broadcast.
- **Fix:** Specify the §5.5 check purely in Midnight heights: for a P2 charter, Generation 1 checks `auth_ref` at a finalized Midnight height `≥ inclusion_height(authorize) + Δ_hold` (where charter parameter `Δ_hold ≥ 1–2` Midnight blocks gives the hold authority a nonzero window to decrypt `rh` and finalize `revoke`), and Generation 2 checks at the latest finalized Midnight height reported alongside the Generation 2 `OBS` votes.

---

## 4. Blindness Claims and Stated Limits

### F18 — Plaintext `pub.auth_ref = 0` and public board votes (`BIRTH_OK`, `OPENED`, `ACK`-only) break TEE operator blindness and `CONTRIB` indistinguishability
- **Severity:** major
- **Location:** `DESIGN.md` §3.1, §4.6, §5.1, §5.7, §6.1, §9.1 C21, §9.3, §10 B5; `DECISIONS.md` #34
- **Claim affected:** C21 (Actor identity / contribution hiding), C10 (TEE blindness), §6.1 table, and B5
- **Failure scenario:**
  1. §6.1 (line 733), C21, and `DECISIONS.md` #34 claim that `CONTRIB` frames share every envelope's public shape *"so the [TEE] operator cannot tell a contribution from a request"*, §10 B5 claims *"an observer cannot tell an institution-initiated request from a customer-initiated one by its frames"*, and §6.1 (line 708) claims that at `Birth` a board observer sees *"nothing"* and a TEE operator sees *"ciphertext and time"*.
  2. Three plaintext board fields refute these claims in TEE mode:
     - **Before ordering:** Bytes `46..78` of the plaintext 96-byte `pub` header (`auth_ref`, §4.6) are `0x00…00` for `CONTRIB`, `BIRTH`, slot refill, and P0, and non-zero for every P1/P2 spend and exit.
     - **At Birth:** `q` nodes emit plaintext `BIRTH_OK(eid, cm_addr)` posts on the board (§3.1), identifying `eid` as a `BIRTH` envelope and publishing `cm_addr` — which also appears in `FenrirAssets` on Midnight (§3.1 step 4), **directly linking the board `BIRTH` envelope `eid` to the Midnight asset record** for every observer.
     - **At Collection:** Board votes (§5.1) are public plaintext: a collecting multi-actor request emits `q` `OPENED` posts prior to `ADMIT` (single-actor customer requests emit no `OPENED` post), and each `CONTRIB` frame emits `(eid, ACK, …)` followed by **zero further posts forever** (§5.7), revealing exact `|S'|` frame counts even on a busy board.
- **Fix:** Populate `pub.auth_ref` with 32 random bytes when unused (indicating unused status inside encrypted `body_0`), blind `cm_addr` in `BIRTH_OK` (or adopt O8 ZK birth), and update §6.1, §6.4, C21, and B5 to state plainly that post-ordering board vote types distinguish `BIRTH`, collecting requests, and `CONTRIB` frames in TEE mode.

---

### F19 — Unencrypted board dealings for ECDSA slot sessions (§3.6), P2 guardian escrows (§3.8), and `E` slot backups (§3.9) leak `R_ℓ`, `X`, and P2 status in TEE mode
- **Severity:** major
- **Location:** `DESIGN.md` §3.6, §3.8, §3.9, §5.7, §6.1, §6.3, §6.4 item 3, §10 B1
- **Claim affected:** C10 (TEE Blindness), B1 (`MET` in TEE mode across all profiles), and §6.1 / §6.4 stated limits
- **Failure scenario:**
  1. §6.1 (line 710) asserts that during the `ECDSA slot session`, a TEE operator sees only *"ciphertext"* and a board observer sees only *"session sizes and the number of session parties"*, and §6.4 item 3 states that ECDSA account linkage occurs *"in non-TEE mode"* only.
  2. In §5.7, however, after an envelope announces a refill, *"The session of §3.6 runs on the board between every session party and the nodes"*: §3.6 steps 1, 2, and 6 publish `R_f, Φ, Ψ, R^{(p)}, R_ℓ, Com_{R_ℓ}(P_{w,p}), Com_{R_ℓ}(P_{μ,p})`, and `x'_p·G` on the board, and §3.9 posts `t` backup dealings to `E` with public commitments **in base `R_ℓ`**. Similarly, §3.8 posts P2 guardian escrows on the board in *"the open mode of line dealing"* with public commitments to `X_u` (Schnorr) or in base `R_ℓ` (ECDSA) and `q_g` ACKs signed by the standing public keys of `G`.
  3. Any TEE operator or passive board observer records `R_ℓ` and `X = X_f + Σ_p x'_p·G` from §3.6 / §3.8 / §3.9 (and identifies P2 births from `G`'s standing ACK keys). When the ECDSA address later spends on Ethereum or Bitcoin, the on-chain signature publicly reveals `r = x(R_ℓ) mod N_s`, linking the transaction and account `X` back to the exact birth/refill/escrow session in TEE mode.
- **Fix:** Encapsulate §3.6 ECDSA session messages and §3.8 guardian escrow dealings inside fixed-size encrypted envelopes (to enclaves and session/guardian `AK` keys), remove ECDSA slot backups to `E` (per F11), or downgrade §6.1, §6.4 item 3, and §10 B1 in TEE mode for ECDSA and P2.

---

## 5. Honesty of Claim Status and Proof Obligations

### F20 — TEE Tier-0 disk rollback (`c = 5` on ECDSA, `c = 6` on Schnorr, `0` broken enclaves) extracts the shared root key `x_f`, refuting C6/C7's "all operators malicious" TEE claim and breaking `anchor_before_release` charters
- **Severity:** blocking
- **Location:** `DESIGN.md` §1, §4.1, §7.4, §7.7, §9.1 C6 & C7, §10 R1 & R4
- **Claim affected:** C5, C6, C7, C12, R1, R2, R4, and §7.7 `anchor_before_release` safety
- **Failure scenario:**
  1. §1 (*"The enclave enforces authorizations and holds even when every operator is malicious, while the TEE holds"*), §9.1 C6 & C7 (`Adversary: TEE: all operators, enclaves intact`; `Status: TEE assumed TEE`), and §10 R1 (`MET`) claim security against **all `n = 9` malicious operators** with intact enclaves.
  2. Yet §7.4 step 3 opens Tier 0 (holding the node's witness log) with static `K_vol = HKDF(K_tpm ‖ "VT1/vol")` and **no version ratchet**, noting that Tier-0 rollback relies on §7.7's peer witness bound — which holds only for **`c ≤ n − 1 − 2f = 4` colluding operators** at `n = 9` (`6` at `n = 17`).
  3. **Full `x_f` extraction at `c = 6` malicious operators `{1..6}` and `3` honest operators `{7, 8, 9}` with all 9 enclaves intact (within one 60 s checkpoint window):**
     - `{1..6}` create their own default-profile P1 Schnorr address and three valid spends `Env_1, Env_2, Env_3` with distinct challenges `c̃_1, c̃_2, c̃_3` naming the **same** Schnorr slot `ℓ_1`.
     - **Fork 1** on `{1,2,3,4,5,6,7}` (`7 = t ≥ q` enclaves; each has `6 = w` peers inside this set): orders, admits, witnesses, and releases 7 partials on `Env_1`, yielding `s_f^{(1)} = σ_1(d_{ℓ_1} + ρ_1 e_{ℓ_1}) + c̃_1 x_f`.
     - `{1..6}` reboot cleanly (`admitBoot` increments `boot_ctr`, fencing clones while allowing rolled-back Tier 0, §7.4 step 3), restore pre-Fork-1 `/mnt/persist` Tier 0, and replay the board's `SL1/slot` dealing message so their intact enclaves re-decrypt `(d_{ℓ_1,i}, e_{ℓ_1,i})` under `PK_i` (from Tier 1 keyring) into RAM.
     - **Fork 2** on `{1,2,3,4,5,6,8}` (`{1..6}` forgot Fork 1 and `8` never saw Fork 1, so all `w = 6` peer witness acks succeed) yields `s_f^{(2)}`; **Fork 3** on `{1,2,3,4,5,6,9}` yields `s_f^{(3)}`.
     - Solving the `3 × 3` linear system over `(s_f^{(1)}, s_f^{(2)}, s_f^{(3)})` recovers `(d_{ℓ_1}, e_{ℓ_1}, x_f)` in plaintext. (On ECDSA, just **`c = 5`** malicious operators `{1..5}` across two forks `{1..5,6,7}` and `{1..5,8,9}` yield 2 equations on one slot and extract `(w_f, μ_f)` and `x_f`.)
  4. Because `x_f` is shared across **all** charters — including charters with `anchor_before_release` (§7.7) — extracting `x_f` on the operators' own default charter breaks every `anchor_before_release` charter as well.
- **Fix:** Restrict the TEE adversary of §1, C6, C7, and §10 to `c ≤ n − 1 − 2f` colluding operators (`4` at `n = 9`, `6` at `n = 17`) on the default profile, and isolate `anchor_before_release` charters under an independent DKG root key `x_{f,anchored}` whose enclaves refuse to release any partial without a finalized Midnight `anchorLock` (or ratchet `K_vol` via peer-witnessed `keyring` state).

---

### F21 — §9.2 ("What fails when TEEs are broken") falsely claims C1, C2, C8, and C12 survive `≥ t` and `all n` broken enclaves
- **Severity:** major
- **Location:** `DESIGN.md` §9.2
- **Claim affected:** C1, C2, C8 (Sealed until order), and C12 (One nonce use) in §9.2
- **Failure scenario:**
  1. §9.2 (line 966) states: *"The claims C1 to C4, C8, C11, C12 and C17 to C19 do not use the TEE and hold in every row"*, and its table lists `C8: nothing before order` and `C12` under **Kept** when `t or more` or `All n` enclaves are broken.
  2. When `t` enclaves (`7` of `9`) are broken, the attacker extracts `t` dealing keys `sk_i`, `t` board keys `post_i`, `t` slot shares `(d_{ℓ,i}, e_{ℓ,i})` / `(w_{f,i}, μ_{f,i})`, and `t` shares of `x_f`:
     - **C8 fails immediately:** Upon seeing an unordered envelope in the mempool, the `t` broken enclaves decrypt `t` shares of `κ_0`, reconstruct `κ_0`, and read `body_0`, every variant body, every capsule, and every contribution before any board ordering.
     - **C12 fails immediately:** Holding `t` slot shares, they sign arbitrarily many distinct messages on one Schnorr or ECDSA slot.
     - **C1 and C2 fail immediately:** Because `t = 7 > q = 6`, `q` broken enclaves sign `BIRTH_OK` for an unproved rogue key `X`, and with corrupt actors holding `x_A` they know the full key `x = x_A + x_f`.
- **Fix:** Remove `C1, C2, C8, C12` from §9.2 line 966 and from the **Kept** column of the `t or more` and `All n` rows (retaining `C3`, `C4`, `C11` on Midnight state, `C17`, `C18` confinement only, and `C19`).

---

### F22 — §8.1's `n' − f'` `READY` handover count cannot ensure liveness at `t' = n' − f'` under §9's partial synchrony model
- **Severity:** major
- **Location:** `DESIGN.md` §8, §8.1 steps 3–6, §9, §9.1 C14, §12 O5
- **Claim affected:** C14 (Rotation) and feasibility of O5 without PVSS
- **Failure scenario:**
  1. §9 sets the network model to **partial synchrony**, and O5 asks for *"a proof of §8 (secrecy of `x_f`, preservation of `X_f`, liveness of `HANDOVER`) under a stated network model, or a PVSS reshare with a proof"*, while §8.1 step 6 argues that `n' − f'` `READY` posts *"confirm that the new committee as a whole is live"*.
  2. At `n' = 9, f' = 2, t' = 7`, suppose a corrupt old dealer in `Q` encrypts valid shares to `5` honest new nodes `{1..5}` and `2` corrupt new nodes `{8, 9}`, and encrypts garbage shares to `2` honest new nodes `{6, 7}` whose complaints arrive after the fixed complaint window of step 3 due to pre-GST network delay.
  3. Honest `{1..5}` plus corrupt `{8, 9}` post **`5 + 2 = 7 = n' − f'` `READY` messages**, triggering `HANDOVER` (step 6). After the grace period, the old committee zeroizes `x_f` (step 7), and corrupt `{8, 9}` go silent.
  4. Only `n' − 2f' = 5 < t' = 7` honest new nodes hold valid shares of `x_f`, permanently halting signing until `E` recovers. In general, because `f'` corrupt nodes can always supply `f'` `READY` posts and withhold `f'` `READY` posts, the maximum non-blocking `READY` threshold `n' − f'` guarantees at most `n' − 2f' < t'` honest share holders whenever share validity is not publicly verifiable.
- **Fix:** State in §8 and O5 that §8.1's fixed complaint window requires **synchrony** (bounded message delay), and that under §9's **partial synchrony** model PVSS (publicly verifiable share ciphertexts eliminating the complaint window) is required rather than optional.

---

### F23 — Missing proof obligations and unblocked `MET` grades across §9.1, §9.3, and §10
- **Severity:** major
- **Location:** `DESIGN.md` §9.1, §9.3, §10; `DECISIONS.md` #10, #41
- **Claim affected:** Honesty of status for C2, C4, C5, C6, C7, C8, C17, C19, R1, R2, and B3
- **Failure scenario:**
  1. *(Note: no claim in §9.1 is marked `proved`; all are marked `sketched`, `open`, or `assumed`.)* However, several claims omit required open obligations or receive `MET` grades in §10 despite `open` obligations:
  2. **Open items that must block `MET` in §10:** In §9.1, **C5** (Schnorr committee unforgeability) is explicitly **`open (O6)`**, and **C17 / C19** (multi-actor Schnorr unforgeability with pool actors — on which **C4** rests) are explicitly **`open (O20)`**; **C8** has no written proof (**O26**); and multi-shard `authorize` lacks circuit **O22** and gadget integration **O25**. Yet §10 grades **R2** as `Schnorr MET`, multi-actor **R1** as `MET / MET`, and **B3** as `MET / MET`, whereas ECDSA is graded `PARTIAL` for its open items O1/O2/O19. Under `DECISIONS.md` #10 (*"Grade honestly per mode"*), unproved core unforgeability/sealing reductions (`O6`, `O20`, `O22`, `O26`) must cap those grades at `PARTIAL` until closed.
  3. **Missing obligations in §9.1:**
     - **C5 (ECDSA):** Marked `sketched, conditional on O19`, omitting **O1** (`F_presig` at `t = n − f`) and **O2** (`F_mul`), which are needed even at `n_A = 1` (compare C3, which conditions on O1 and O2).
     - **C6 and C7 (non-TEE / P2):** Marked `sketched` without conditioning C6 (non-TEE) on **O4** (ticket circuit), **O22** (`Γ` circuit), and **O25** (Compact hash gadgets / STARK fallback), or C7 on **O3** (hold contract).
     - **C2 (Adversary column):** Lists `any coalition of actors, up to all of A` without `|C| < q` (unlike C1); if `|C| ≥ q` (and `≥ t`), corrupt nodes forge `BIRTH_OK` without PoPs and know `x_f` alongside `A`, hence know `x`.
  4. **Inaccurate `none` entries in §9.3:** §9.3 lists `Proof obligation: none` for opening headers before authorization is in force (missing slot-sniping censorship of C13, see F12) and for `CONTRIB` frames keeping their outer dealing under C21 (missing plaintext `auth_ref = 0` and board-vote distinguishability, see F18).
- **Fix:** Add `O1, O2` to C5 (ECDSA), `O3, O4, O22, O25` to C6/C7, and `|C| < q` to C2; replace the two false `none` entries in §9.3; and change §10 R2 (Schnorr), multi-actor R1 (Schnorr), and B3 from `MET` to `PARTIAL` until O6, O20, O22, and O26 are discharged.

---

## Checked and Found Sound

1. **BIP340 parity and Taproot tweak algebra across all 8 `(g_P, g_Q, σ)` sign combinations and nested Lagrange weights (§2.4, §3.2, §4.2, `vectors/check.py`):** Placing `c̃·tw + c·g_Q·t_tap` (with `c̃ = g_P·g_Q·c`) once in `s_0`, weighting every leaf secret `x_a` by path-product Lagrange coefficients `λ_a`, and multiplying every nonce term `(k_0, d_{a,ν} + ρ_a·e_{a,ν}, d_ℓ + ρ·e_ℓ)` by `σ` yields `s·G − c·lift_x(x(Q)) = σ·R` with even `y(σ·R)` and x-coordinate `x(R)`. Placing the tweak term zero times or twice fails verification as claimed.
2. **Ed25519 multi-shard linearity, uniform unclamped scalars mod `ℓ`, and decode-time torsion check (§3.5, §4.3, §5.10 rule 3, `vectors/ed.py`):** Checking prime-order subgroup membership (`[ℓ]P = O`) once when decoding wire points eliminates cofactor-8 malleability between strict and cofactor-multiplied Ed25519 verifiers and makes 128-bit random linear combination batch verification sound (`≤ 2⁻¹²⁸` error over prime `ℓ`).
3. **ECDSA presignature slot base-change check `(a·φ_i)·R_ℓ = φ_i·R_f` (§3.6 steps 2–6, `vectors/check.py`):** For `R_f = k_f·G`, `R_ℓ = (Π_p k_p)·R_f`, and `a = Π_p k_p⁻¹`, commitments `Φ, Ψ` in base `R_f` with `Φ_0 = G, Ψ_0 = X_f` satisfy `Eval(Φ, i) = (a·φ_i)·R_ℓ` and `Eval(Φ' + Ψ, i) = (a·(x_A·φ_i + ψ_i))·R_ℓ`, enabling each node to verify `(w_{f,i}, μ_{f,i})` publicly in base `R_ℓ` using only batched DLEQ on `x'_p·Φ_k`.
4. **Sharing one Schnorr committee slot `ℓ(g, j)` across `K` candidate variants per `(generation, input)` with fresh per-half actor nonces (§4.1, §4.2, §5.11, `vectors/check.py`, `vectors/ed.py`):** Releasing at most one committee partial per slot (for the deterministic anchor-selected variant `j_g`) while burning a distinct `k_0` and distinct actor pool pair `(d_{a,ν}, e_{a,ν})` on each of the `N_h = L·Σ_{v=1..K} min(v, G_max)` halves avoids two-challenge linear extraction on both actor shards and committee slot nonces; unselected candidate `(R_A, pm, ρ, c̃)` tuples are publicly computable without committee secrets.
5. **Single-user Schnorr sealed-half reduction sketch against all `n` corrupt committee nodes (C3, §9.1):** Because each half uses a fresh `k_u` and distinct variant sighash `m_v`, simulating dealt halves by sampling `(s_u, c, salt)`, computing `R_u = σ·(s_u·G − c·(g·Y_A + g_Q·t_tap·G))`, retrying privately if `y(R_u + D_ℓ + ρ·E_ℓ)` mismatches `σ` (exact probability `1/2`), and programming `H_BIP0340/challenge(x(R) ‖ x(Q) ‖ m_v) := c` is statistically faithful up to RO collision bound and extracts `x_U'` via forking on any off-grid message `m*`.
6. **Threshold-PRF envelope keying `Z_lab = κ_0·H_c(dd ‖ lab)` with reactive Chaum-Pedersen DLEQ fallback (§4.6, §9.3 Theorem D restated, `vectors/check.py`):** For `|C| ≤ t − 1` corrupt nodes in the ROM (`H_c, KDF, Hq`), unopened label outputs reduce cleanly to CDH/DDH while answering opened labels (`hdr`, selected `(j_g, g)`) and their Chaum-Pedersen proofs by programming `H_c(dd ‖ lab') = r_{lab'}·G`; checking `y_{v,g}·G = P_{v,g}` at combine catches a dishonest initiator that substituted `P_{v,g}` (§6.4 item 10).
7. **Curve-free Schnorr/Ed25519 ticket proof via committed `x(R)` paired with node-side `x(R)` recomputation (§4.7 item 7, §5.3 item 5):** Proving both `pm = H_pm(x(Q) ‖ m ‖ salt)` and `c̃ = g·H_challenge(x(R) ‖ x(Q) ‖ m)` in `midnight-zk` while each node recomputes `ρ` from `pm` and verifies `x(R_A + D_ℓ + ρ·E_ℓ) == x(R)` before releasing a partial eliminates curve arithmetic from the circuit without reopening fixed-`R` message-search / ROS attacks.
8. **Small-index Horner commitment evaluation and 128-bit RLC batching with per-item fallback (§4.1, §5.10, `vectors/check.py`):** Horner evaluation at small node indices `i ≤ n` matches power-basis Feldman evaluation, and privately sampled 128-bit batch weights drawn after message receipt give `≤ 2⁻¹²⁸` soundness error while per-polynomial fallback preserves named complaints.
