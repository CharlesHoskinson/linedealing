# Split-line dealing: speed

Lane: Fable. Date: 2026-11-14. Status words follow DESIGN.md: **proved**, **sketched**, **open**, **estimate**.

## 1. Summary

Split-line dealing as specified costs each node about 146 ms of one core and 138 KB of board space for a Taproot request with a full fee grid, and takes `F_M` + 5.1 s from post to broadcast. Twelve of the 146 ms are on the request path. The rest is the committee's nonce pool, which DESIGN.md §11.3 mentions in one sentence. The five changes below bring a request to 2.5–6.3 ms and 46 KB per node, and to `F_M` + 1.1 s, or about 2 s with no Midnight wait for P0 and for P1 charters with stateless predicates. Figures are calibrated from measurements on the prototype's machine (§2.1) unless marked as estimates.

| # | Change | Before → after | Factor | New proof needed |
|---|---|---|---:|---|
| 1 | **Slot economy** (§3.1): a committee slot serves a (generation, input) pair, so a request claims `G_max·L = 4` slots in place of `K·L = 16`; commitments are evaluated with the node index as a small integer; a dealer's batch is checked with one equation | slot CPU per request 134 ms → 3.6 ms (1.2 ms with batch checks, estimate); slot bytes 117 KB → 29 KB (18 KB with derived shares, which need a proof) | 37–110× CPU, 4× bytes | C12's counting rewritten with the anchor; O6 states "one query per slot" |
| 2 | **One polynomial per envelope** (§3.2): the header key and every variant key are outputs of the threshold PRF `κ_0·H_c(dd ‖ label)` over the outer dealing's digest `dd`; all 16 inner dealings go away | request path −4.7 ms (40% of it); frame content 14.5 KB → 11.2 KB; `n = 17` holds the full `K = 8`, `L = 2` grid; an outside actor deals nothing (5.6 ms → 0.06 ms per actor, §3.7) | 16 dealings → 0 | C8 and C9 become DDH-based: Theorem D restated for a PRF output |
| 3 | **Latency** (§3.3): post the envelope while `authorize` finalizes; merge ACK with share release and OPENED with ADMIT; take the anchor from the ADMIT block; for P0 and stateless P1 charters let the nodes verify the authorization proof and the board order the nullifier | `F_M` + 5.1 s → `F_M` + 1.1 s (5 board commits → 2); board-first: 2.15 s, or 1.15 s at 0.5-second commits, with no `F_M` | 4.6× on the board part; `F_M` removed where board-first applies | C13 for the merged ADMIT and OBS step; C6 and C11 restated for board-first |
| 4 | **Ticket proof without a STARK** (§3.4): commit `x(R)` in the ticket so no curve arithmetic is proved; prove the hashes with Midnight's own SHA-256, SHA-512 and Keccak gadgets; share sighash prefixes across variants | 240 compressions in a 2^18-row STARK plus a 2^20 wrap → 100–132 compressions in one `k = 18` circuit; proving about 100 s → 25 s on a server CPU (estimate) | 4× or more | none |
| 5 | **Request-path arithmetic and post signatures** (§3.5, §3.6): lazy per-variant checks, optimistic combine, cached per-node commitments, one multi-scalar check for `π`, the generator table; one signed vote per node and block in place of a signature per post | request path 11.2–12.6 ms → 1.8–2.7 ms | 5–6× | none |

Together: one core serves 160–400 requests per second in place of 7 at `n = 9`, and 95–260 in place of 3.6 at `n = 17` (§5). The low end uses measured unit costs only; the high end adds batch checks and is an estimate.

Three further positions. Multi-shard cost does not grow with the actor count when actors encrypt their scalars to PRF-derived variant keys and one binding factor covers all nonces (§3.7). ECDSA birth pools `F_presig`, uses two multiplications per node and slot, prepares 8 slots at birth, and takes the OT-based multiplication over Paillier for a 110-fold CPU difference; all of it conditional on O1 and O2 (§3.8). The user side never shares a nonce across variants, ECDSA slots are never shared, and no share moves before the QC (§4).

## 2. Profile

Three kinds of figure appear below. **measured** is a timing from `impl/BENCHMARKS.md` or from the micro-benchmark of §2.1. **calibrated** is an operation count from DESIGN.md multiplied by a measured unit cost. **estimate** is a derived figure with no measurement behind it.

### 2.1 Unit costs on the benchmark machine (measured)

`impl/BENCHMARKS.md` machine: aarch64, Cortex-X925, k256 0.13.4, curve25519-dalek 4.1.3. I ran a scratch micro-benchmark on the same machine with the same crate versions (one thread, release build, under `heavy-slot`, not `--exclusive`; source in the scratchpad, not in the repository). It reproduces the prototype's share check and times the replacements of §3. The appendix holds the raw output and the routine. The machine was shared with other jobs, so each figure carries about ±15%; the three rows that use the generator table come from a second, noisier run.

The absolute figures are for an aarch64 laptop core. Committee nodes run on AMD EPYC under SEV-SNP. Ratios between code paths carry over; absolutes must be measured again on the node hardware. On x86-64 curve25519-dalek selects an AVX2 or AVX-512 IFMA backend for its variable-time paths, which widens the gap between suite 3 and secp256k1; no SIMD backend exists for secp256k1 in either library, so SIMD is a compile flag here and not a design item.

| Operation | secp256k1 (k256) | edwards25519 (dalek) |
|---|---:|---:|
| Variable-base scalar multiplication | 55.7 µs | 30.8 µs |
| Generator multiplication as the prototype writes it (`G * s`, the generic routine) | 54.1 µs | — |
| Generator multiplication with the library's table (`mul_by_generator`; basepoint table) | 26.1 µs | 10.2 µs |
| Feldman share check as the prototype does it (`Commitment::verify`: Horner with `t − 1` full-width multiplications by the node index), `t = 7` | 291.5 µs | — |
| The same, `t = 12` | 496.7 µs | — |
| Share check with the node index as a small integer (double-and-add over at most 5 bits), `t = 7` / `t = 12` | 51.6 / 50.6 µs | — |
| The same with the table-driven generator multiplication, `t = 7` | 35.7 µs | — |
| Small-index evaluation alone, `t = 7` | 9.4 µs | — |
| Partial check with cached per-node commitments (one generator multiplication and one 3-term combination) | 122.4 µs | — |
| Signature check of one board post (ECDSA in the prototype) | 68.9 µs (bench9: 54 µs) | 33.8 µs (Ed25519), 52.6 µs (`verify_strict`) |
| `is_torsion_free` on one point | — | 49.3 µs |
| Variable-time multi-scalar multiplication, 112 points, per point, 253-bit / 128-bit scalars | — | 9.4 / 3.1 µs |

Four facts follow, and each drives an optimization.

1. The DESIGN.md planning figure of 50 µs per multiplication is right for k256 on this machine and 1.6 times too high for edwards25519.
2. k256 has a precomputed generator table behind `mul_by_generator` (26.1 µs), and the prototype never calls it: it writes `G * s`, which runs the generic routine at 54.1 µs. k256 has no variable-time multi-scalar routine: `lincomb` over 112 terms is slower than 16 separate small-index share checks (2.7 ms against 0.7 ms). curve25519-dalek has a table and a variable-time routine, which costs 0.3 multiplications per point at full width and 0.1 at 128 bits.
3. The prototype's share check spends 5.6 times (`t = 7`) to 9.8 times (`t = 12`) more than it needs, because it multiplies by the node index as a 256-bit scalar.
4. On edwards25519 a torsion check costs 1.6 variable-base multiplications. The prototype runs one per commitment point, which is why sealed Ed25519 Step A measures 7.6 ms against 2.2 ms for BIP340.

### 2.2 Request path, per node, per request

Launch parameters, P2TR, `K = 8`, `L = 2`: 16 inner dealings, 16 tickets, 16 committee slots. The left column repeats DESIGN.md §11.3. The right column prices the same steps with the prototype's code paths at the unit costs of §2.1 (secp256k1).

| Phase | Step | DESIGN.md §11.3 (estimate) | Prototype code path at measured unit cost (calibrated) |
|---|---|---:|---:|
| Before ordering | `π` check: 6 multiplications and one hash to curve | not counted | 0.40 ms |
| Order | board vote and QC check | not counted | 0.4 ms (`q` signatures) |
| ACK | DH, key check, outer share check | 8 mult, 0.4 ms | 0.40 ms |
| Open | check `t − 1` signed `κ_0` shares, reconstruct, `κ_0·G`, AEAD of 16 KiB | not counted | 0.50 ms |
| Open | 16 inner share checks | 128 mult (70 batched), 3.5–6.4 ms | 16 × 291.5 µs = 4.66 ms |
| Open | 16 tickets: recompute `ρ`, `R`, `σ` | 32 mult, 1.6 ms | 16 × 55.7 µs = 0.89 ms |
| Admit (TEE) | implied constant term, §4.7 item 4 | 48 mult, 2.4 ms | 16 × 2 mult = 1.78 ms |
| Admit (TEE) | recompute 16 sighashes and challenges | not counted | 0.05 ms |
| Admit (non-TEE) | read the settled authorization; Midnight verified the proof | not counted | 0 |
| Release | 2 partials with the prototype's self-check | not counted | 2 × 227 µs = 0.45 ms |
| All phases | signature checks on board posts: ACK, OPENED, ADMIT, RELEASE, FINAL, between `4q + t = 31` and `5n = 45` posts | not counted | 31–45 × 54–69 µs = 1.7–3.1 ms |
| **Total, TEE mode** | | **160–220 mult, 8–11 ms** | **11.2–12.6 ms** |
| Combiner, per request | verify `2t` partials and `2t` inner shares, combine, verify the signature | 42 mult, 2.1 ms | 14 × 226 µs + 14 × 292 µs + 0.15 ms = 7.4 ms |

The DESIGN.md estimate holds: the items it omits (post signatures, `π`, the partial self-check) add about as much as its batch-verification assumption removes. The request path has two large items, the 16 inner dealings (40%) and the post signatures (15–25%).

### 2.3 Off the request path, per node, amortized per request

This is where the time goes. DESIGN.md §11.3 states it in one sentence and it is ten times the request path.

| Item | Count per `K = 8`, `L = 2` request | DESIGN.md (estimate) | Calibrated |
|---|---|---:|---:|
| Schnorr nonce slots: 16 slots, each the sum of `t = 7` dealers × 2 polynomials | 224 polynomials to check, 32 aggregated polynomials to evaluate at `n` nodes | 137 mult per slot, 110 ms | 16 × (14 × 291.5 µs + 18 × 240 µs) = 134 ms |
| Board bytes for those slots | 16 × 7.3 KB | 117 KB | 117 KB |
| Board bytes for the request itself | one 16,384-byte frame and 31–45 posts of 120 B | 16.4 KB + 4–5 KB | 21 KB |

**Per request and node today: 12 ms on the path and 134 ms in the slot pool, 146 ms of one core in total, and 138 KB of board space.** One core serves 7 P2TR requests per second. A 16-core node at 80% use serves 88. The base protocol's figure of 288 requests per second per core (BENCHMARKS.md, `t = 7`) does not carry over, because the base protocol has no committee nonce pool: the owner deals the nonces.

At `n = 17`, `t = 12`: a slot is 22.6 KB and 24 polynomials per node, a prototype share check is 497 µs, and the frame holds only `K·L ≤ 10`. A 10-slot request costs 10 × (24 × 497 µs + 34 × 420 µs) = 262 ms per node and 226 KB of board space for slots.

### 2.4 Latency

From DESIGN.md §11.2, with one-second board blocks (assumed there):

| Phase | Wait |
|---|---:|
| `authorize` final on Midnight | `F_M`. Midnight produces a block about every 6 s (AURA) and finalizes with GRANDPA; its documentation publishes no finality time, so `F_M` stays a symbol here |
| Order | 1 block |
| ACK, then `κ_0` exchange | 1 block + 1 peer hop |
| OPENED | 1 block |
| ADMIT | 1 block |
| Open witness (TEE) | 20 ms |
| Anchor | 1 block |
| Release witness and release | 40 ms |
| Combine and broadcast | 10 ms |
| **Total** | **`F_M` + 5 blocks + 70 ms = `F_M` + 5.1 s** |

CPU is 12 ms of that. Latency is set by `F_M` and by the count and length of board commits, so a latency optimization has to remove a commit, shorten a commit or move `F_M` off the path. Nothing else matters.

### 2.5 Wallet and prover

| Item | Cost | Kind |
|---|---:|---|
| Envelope: 17 polynomials of degree 6, 17 × 9 pads, `π` | 17 × 7 + 9 + 5 = 133 mult, 7.4 ms on the benchmark machine; a phone core is 3–5 times slower | calibrated |
| 16 half-signatures and 16 sighashes | 16 mult, 1 ms | calibrated |
| Ticket STARK, non-TEE mode | DESIGN.md: 2^18 rows, then a BLS12-381 wrap budgeted at 2^20 constraints | estimate, open item O4 |
| ECDSA birth: 32 slots × 9 nodes × 3 `F_mul` = 864 two-party multiplications, plus 32 `F_presig` runs in the committee | depends on O1 and O2 | open |

## 3. Optimizations

Ranked by effect on throughput and latency. Each entry gives the mechanism, the gain with its derivation, the security argument against DESIGN.md §9, the implementation cost and the sources. Unit costs are those of §2.1. "Holds" means the claim's existing argument still applies word for word. "Needs a proof" means the claim's argument changes and the new one is not written.

### 3.1 Slot economy: one committee slot per generation and input, and a pool that is checked in bulk

**Rank 1 for throughput.** The slot pool is 92% of per-request CPU and 85% of per-request board bytes (§2.3).

**Mechanism.** Four changes, independent of each other.

(a) *A committee slot belongs to a (generation, input) pair, not to a (variant, input) pair.* The header fixes `G_max`, the number of generations the request may run (launch: 2). The request names `G_max·L` committee slots. Variant `v` may be selected in generation `g ≤ min(v, G_max)`, because each generation selects a higher variant. For every such pair the wallet deals one user half-signature `s_u^{(v,g,j)}` with its own fresh `k_u` and `R_u`, bound to slot `ℓ(g, j)`:

`ρ = Hq_bind(SL1/bind ‖ suite ‖ epoch ‖ ℓ(g,j) ‖ R_u^{(v,g,j)} ‖ pm_v)`, `R = R_u^{(v,g,j)} + D_ℓ + ρ·E_ℓ`.

The committee uses slot `ℓ(g, j)` once, for the variant that the anchor of generation `g` selects. The halves of the other variants on that slot are never completed. `K = 8`, `L = 2`, `G_max = 2` needs 4 committee slots and 2 × (8 + 7) = 30 user halves, in place of 16 slots and 16 halves. `G_max` is a protocol constant, 2 at launch: one fee bump per request, and a wallet that needs a second bump posts a new request. The constant fixes the ticket list of `authorize` at 32 padded entries (today 16) and keeps one circuit for every request.

(b) *Evaluate commitments with the node index as a small integer.* `Eval(C, i) = Σ i^k·C_k` with `i ≤ 17`. Horner's rule with double-and-add over the 5 bits of `i` costs about 30 group operations for `t = 7`, against 6 full multiplications. Measured: 291.5 µs → 51.6 µs at `t = 7` and 496.7 µs → 50.6 µs at `t = 12`; what remains is the generator multiplication, and calling `mul_by_generator` brings the check to 35.7 µs.

(c) *Check a dealer's whole batch with one equation.* A dealer posts `B` slots in one message (one `E`, one `π`, `2B` polynomials). Node `i` draws local 128-bit coefficients `r_m` after it has the message and checks

`(Σ_m r_m·share_m)·G = Σ_m r_m·Eval(C_m, i)`.

The left side is one generator multiplication. The right side is `2B` small-index evaluations and one variable-time multi-scalar multiplication over `2B` points with 128-bit scalars (3.1 µs per point measured on edwards25519; 6–8 µs per point is the estimate for secp256k1 with a Straus or Pippenger routine). A failed batch falls back to per-polynomial checks to find the bad one, and the complaint is the existing one. The per-node public points `D_{ℓ,i}`, `E_{ℓ,i}` are computed once per slot from the summed commitments of the `t` qualified dealers, again with small-index evaluation, and cached.

(d) *Derive `t − 1` shares from the Diffie-Hellman key (optional, last).* For nodes `1..t−1` the share is a hash output, `p(i) := Hq_der(hd_0, i, PK_i, K_i, slot)`, and the dealer interpolates the polynomial through the random constant term and those `t − 1` values. Only nodes `t..n` get a 32-byte ciphertext. `hd_0` is a digest of the header and `E` alone. It cannot be `hd`, because `hd` covers the commitments and the commitments depend on these shares. A polynomial costs `33t + 32(n − t + 1)` bytes: 327 at `n = 9` (was 519), 588 at `n = 17` (was 940).

**Gain.**

| Per `K = 8`, `L = 2` request, `n = 9` | Today (calibrated) | After (a)+(b) (calibrated from measured units) | After (a)–(c) (estimate) |
|---|---:|---:|---:|
| Slots | 16 | 4 | 4 |
| Node CPU for slots | 134 ms | 4 × (14 × 51.6 µs + 18 × 9.4 µs) = 3.6 ms; 2.7 ms with `mul_by_generator` | 4 × 0.3 ms = 1.2 ms |
| Board bytes for slots | 117 KB | 4 × 7.3 KB = 29 KB | 29 KB; 4 × 14 × 327 B = 18.3 KB with (d) |

CPU falls 37 times with (a) and (b) alone and about 110 times with (c). Board bytes fall 4 times, and 6.4 times with (d). At `n = 17` the slot cost of a request falls from 262 ms and 226 KB (10 slots, the most the frame allows today) to 7.2 ms, or about 2 ms with (c), and to 90 KB for 4 slots, or 56 KB with (d).

**Security.**

- C12 (one nonce use) keeps its counting argument, with one step replaced. An honest node computes a partial on slot `ℓ(g, j)` for one ticket only: the ticket of the variant selected by the anchor of generation `g`. The rule "a node never releases two different variants for one generation and one input" is already in §5.6 step 3, and the witness kinds `release` and `slot` of §7.7 already record `(node, ℓ) → H(tk)`. Today all honest nodes agree on a slot's one ticket because they read the claim order from the board. After the change they agree because they read the anchor from the board. Both are facts about one consistent board record, but the step is a new one, so C12's status after the change is **sketched** until the counting is rewritten with the anchor in it.
- C5 and O6 (no spend without the committee; ROS) hold in kind. The committee still answers one signing query per slot, with a binding factor that fixes `R_u`, the slot and `pm`. The `K` candidate tickets on one slot give the wallet nothing it lacks today: it can already evaluate `Hq_bind` and the challenge hash for as many `(R_u, pm)` as it likes before it posts. The O6 reduction must state "one query per slot, chosen by the board anchor among the dealt tickets".
- C3 (sealed user half) holds because every user half has its own `k_u`. This is the reason the user side does **not** share a nonce (§4, item 1).
- (b) and (c) change no message. (c) is sound with error 2^-128 because the node draws `r_m` after the dealer is committed and never reveals them. Variable-time code touches public commitments only; the left side multiplies a secret sum and stays constant-time.
- (d) **needs a proof**, and it is the reason (d) comes last. Today every pad depends on `hd`, which covers the whole dealing, and SCHEME.md §10 and Theorem E use that against related dealings. A derived share depends on `hd_0` only. The uniformity of a hash output under an unknown `K_i` still gives Theorem C, and `π` still binds `E` to `hd` and the ciphertexts, but the related-dealing argument and Theorem D must be redone for shares that do not depend on the commitments. The complaint is unchanged: a node reveals `K_i` with its DLEQ proof, and anyone recomputes the derived share and checks it against the commitment.
- Suite 3: the batch equation is checked in ristretto255 or multiplied by the cofactor (§3.9).

**Cost.** (a) is a header field, a slot-naming rule and a wallet loop: about 300 lines, plus test vectors for O18. (b) is 20 lines. (c) needs a variable-time multi-scalar routine for secp256k1 (libsecp256k1 has the building blocks, k256 does not): about 400 lines. (d) is 150 lines in the dealer and the decryptor.

**Sources.** `impl/src/algebra.rs` (`Commitment::evaluate`), the micro-benchmark of §2.1, BIP340 (the batch equation and coefficients drawn from a generator seeded by a hash of all inputs), BIP327 (nonce reuse reveals the key; nonces may be published before the message is known).

### 3.2 One polynomial per envelope: threshold-PRF keys for the header and for every variant

**Rank 2 for throughput, rank 1 for bytes and for the multi-shard form.**

**Mechanism.** The envelope keeps the outer dealing of `κ_0` and drops every inner dealing. Nobody reconstructs `κ_0`. Keys are outputs of the threshold Diffie-Hellman PRF that §7.4 already uses for `K_grp`:

`key(label) = KDF(κ_0 · H_c(dd ‖ label))`, with `H_c` a hash to the curve and `dd = H(pub* ‖ commitments ‖ ciphertexts ‖ E)` the digest of the outer dealing.

`dd` is used, not `hd`, because `hd` covers the bodies and the bodies are encrypted under these keys. Node `i` releases the partial `Y_i = κ_{0,i} · H_c(dd ‖ label)`. Any `t` partials combine with Lagrange weights to `κ_0 · H_c(dd ‖ label)`. The labels are `hdr` for `body_0` and `(v, g)` for the body of variant `v` in generation `g`. That body holds the scalars `s_u^{(v,g,j)}` for `j = 1..L` and a 32-byte capsule key for capsule `v`, so the capsule opens in whichever generation selects `v`. The header carries the explicit point `S_u^{(v,g,j)} = s_u·G` (33 bytes) for every half, so every later check keeps its form.

A partial is checked only when something fails. The receiver combines `t` partials and tries the AEAD. If the tag fails, it asks for the Chaum-Pedersen proofs `DLEQ(G, Eval(C, i); H_c(dd ‖ label), Y_i)`, verifies them against the outer commitments, and drops the bad partial.

**Gain.**

- Request path: the 16 inner share checks disappear (4.66 ms of 12 ms). In their place a node computes two partials (0.11 ms) and combines `t` partials twice. The combination is constant-time in TEE mode, `2t` multiplications = 0.78 ms at `t = 7`, and variable-time in non-TEE mode, about 0.3 ms.
- Envelope: 16 inner dealings (8.3 KB at `n = 9`, 15 KB at `n = 17`) become 30 points and 30 scalars (1.95 KB at any `n`). With 30 tickets of 149 bytes (117 plus `x(R)`), 15 capsule keys, 8 capsules and the outer dealing, the frame holds 11.2 KB at `n = 9` and 11.6 KB at `n = 17`. The limit `K·L ≤ 10` at `n = 17` goes away.
- Wallet: 17 polynomials and 16 nonce points (149 multiplications, 8.3 ms) become one polynomial and 60 generator multiplications for the 30 pairs `R_u`, `S_u` (81 multiplications, 4.5 ms; a generator table makes those 60 about four times cheaper).
- Multi-shard: an actor deals nothing (§3.7).

**Security.**

- C8 (sealed until order): the outer dealing, its encryption and its proof `π` are unchanged, and a node releases a partial for label `hdr` only after the QC. The hiding argument changes from "fewer than `t` shares of a scalar are uniform" to "the PRF output on a label for which fewer than `t − |C|` honest partials exist is pseudorandom". That is the security of the Naor-Pinkas-Reingold threshold PRF under DDH in the random-oracle model on secp256k1. **Needs a proof**: restate Theorem D for a PRF output. The reduction answers complaints as Theorem C does today.
- C9 (unselected variants stay sealed): same change. Today's argument is information-theoretic. The new one is computational (DDH, ROM), status **sketched**. Honest nodes release a partial for `(v, g)` only for the selected variant.
- C3, C4: unaffected. The adversary of C3 already holds every dealt half.
- C6, C12: unaffected. The release rule is unchanged; a partial point replaces a scalar share.
- Binding across envelopes: `dd` is inside `H_c`, so a partial opens keys of one outer dealing only. A second envelope with the same outer dealing and other bodies has another `hd`, and it needs a proof `π` for that `hd`, which needs the ephemeral secret `e` (Theorem C, event `Reuse`). Honest nodes release partials only for an envelope whose `π` verified and whose QC exists. The restated Theorem D must include this step, because the key no longer depends on the bodies.
- What a dishonest wallet can do: encrypt a scalar that does not match `S_u`. Today a bad inner share shows before ADMIT. After the change the mismatch shows at release, the request ends VOID, and the check `s_u·G = S_u` names the wallet. The wallet burns its own slots, which it can do today by letting a request expire.

**Cost.** About 600 lines: the PRF partial and its lazy proof (the code of `veritee_seal` on another curve), the capsule format, the fallback path. One new proof obligation.

**Sources.** DESIGN.md §7.4 (the same PRF with Chaum-Pedersen proofs, on ristretto255), §4.6, §4.7; `impl/src/message.rs` (`decrypt`, `share_pad`, `hg`). The DiSE paper (ePrint 2018/727) is the standard reference for this construction; ePrint refused automated download during this work, so it is not cited as read.

### 3.3 Latency: overlap Midnight, two board commits, and board-first authorization for P0 and stateless P1

**Rank 1 for latency.**

**Mechanism.** Three steps, each usable without the next.

(a) *Post the envelope while `authorize` finalizes.* `auth = H(ic ‖ hd ‖ tkc ‖ nf ‖ rh)` is known to the wallet before it submits anything, so `auth_ref` goes into the envelope and both messages leave together. The board orders and opens the envelope while Midnight finalizes. Only ADMIT waits for finality.

(b) *Two commits in place of five.*

| Commit | Carries | Then |
|---|---|---|
| 1 | the envelope, in a block with a QC | each node checks its outer share and sends its `hdr` partial to its peers in the same step (the ACK post goes to the board in parallel); each node opens `body_0` and runs the checks of §4.7 |
| 2 | one ADMIT(`eid`, `H(header)`) vote per node, which also serves as OPENED, with the node's OBS report in the same vote | each node selects `j_1`, witnesses (TEE), and releases |

ACK and share release merge because C8 only forbids a share before the QC. OPENED and ADMIT merge because a node that can admit has opened. The anchor needs a rule change. SCHEME.md §3.6 opens attempt 1 of generation 1 when the request is armed, and each node then posts `OBS(rid, 1, 1, h)` with the height of its finalized host tip; the anchor height is entry `f + 1` of the first `q` reports. Here a node posts its OBS in the same vote as its ADMIT, and an OBS counts only if the request reaches ADMITTED. The anchor lemma (`anchor_between_honest_nodes_quorum`) speaks about `q` reports with at most `f` Byzantine ones and does not use the arming order, so it applies unchanged; the liveness text of C13 must be rewritten for the merged step. Without this rule change the path has three commits and every figure below grows by one `C`.

(c) *Board-first authorization, a charter option for P0 and for P1 charters whose predicates read no mutable Midnight state.* The wallet posts the `authorize` call itself (proof and public inputs `auth`, `nf`, `rh`, and the Midnight state root it was proved against) to the board next to the envelope. Each node verifies the proof, checks that the root is a finalized Midnight root not older than a charter bound, and checks that `nf` is unused in finalized Midnight state. The board orders the call and records `nf` in its pending set; a second call with the same `nf` is refused in board order. The committee relays the call to Midnight with the block's QC, and the `FenrirAssets` contract accepts an `authorize` for a record of such a charter only with that certificate. `settle` is unchanged.

Also set the board's commit time to 0.5 s or less. Mysticeti reports 0.5 s WAN commit latency with three message rounds, and 400 ms median on Sui's 106 validators; a 9-node committee has no reason to run 1-second blocks.

**Gain.** `C` is one board commit, `h` one peer hop (50 ms).

| Path | Latency | `C = 1 s` | `C = 0.5 s` |
|---|---|---:|---:|
| Today | `F_M + 5C + 0.07 s` | `F_M` + 5.1 s | `F_M` + 2.6 s |
| (a)+(b), every profile | `max(F_M, C + h) + C + 2h` | `F_M` + 1.1 s | `F_M` + 0.6 s |
| (a)+(b)+(c), P0 and stateless P1 | `2C + 3h` | 2.15 s | 1.15 s |

The three hops are the partial exchange, the witness and the release. (a) and (b) remove three commits and let the two that remain overlap `F_M`. (c) removes `F_M`, which is at least one 6-second Midnight block plus GRANDPA's lag: it turns a wait of ten seconds or more into about one second.

**Security.**

- C8 holds: no partial leaves a node before the QC that orders its envelope.
- C6 under (a) and (b) holds word for word: release still requires the settled, unrevoked authorization that opens to `hd` and `tkc`. What changes is that an envelope can be opened and never admitted. That is already true today, because the checks before ordering (§4.7) do not look at `auth_ref`; a non-TEE node sees the header of such an envelope, as it does today. No slot is claimed before ADMITTED.
- Merging ACK with share release: a node that sends its partial before `q` ACKs may help open an envelope that a valid complaint later voids. The header of a void envelope is then known to the nodes. Only the dealer of a malformed envelope is exposed.
- C6 under (c) is restated: "no node releases without an authorization whose proof it verified against a finalized Midnight root and whose nullifier the board ordered first". **Needs a proof.** In TEE mode the enclave runs the verifier, so the claim binds every operator while the TEE holds. In non-TEE mode it stays a guarantee for `|C| < t`.
- C11 under (c): Midnight still rejects a second `authorize` on one `nf`, and the certificate requirement removes the race between a board-first call and a direct call. The pinned input or nonce still limits the host chain to one spend. Status **sketched**.
- (c) is not offered to P2. A P2 authorization can be revoked on Midnight by the hold authority (§5.5), and an authorization that is not on Midnight cannot be revoked there.
- (c) is not offered to a P1 charter with a predicate over state that other requests change: a cumulative spend limit, an approver veto, any counter. Two requests proved against one finalized root would both pass such a predicate. The eligible charters are P0 and P1 with the owner source and stateless predicates only (fixed destination allow-lists, time locks, approver signatures inside the proof). For those nothing can change between the proof and the release except the nullifier, which the board orders. A later version can admit stateful predicates by having the board order the state keys they read, as it orders nullifiers.

**Cost.** (a) is a wallet change. (b) is a change to the state machine of §5.1: about 400 lines and new liveness text for C13. (c) is a PLONK verifier in the node (about 1.4 ms per proof), a Midnight finality client the node already needs, one contract rule and one proof.

**Sources.** DESIGN.md §4.7, §5.2–5.5, §11.2; Midnight consensus documentation (AURA and GRANDPA, no finality time published); GetBlock's Midnight page (block time about 6 s); Mysticeti (0.5 s WAN commit, 400 ms median on Sui); the Aptos Keyless write-up (pairing-based verification: TurboPLONK 1.36 ms, Groth16 on BLS12-381 1.31 ms).

### 3.4 The ticket proof: no STARK and no wrap; prove the hashes in Midnight's own circuit

**Rank 1 for the wallet's proving time in non-TEE mode.** This reverses the proof system of DECISIONS.md item 9 (a hash-only STARK with one BLS12-381 wrap) and keeps its statement and its interface.

**Mechanism.** Two changes.

(a) *Keep elliptic-curve arithmetic out of the proof.* §5.3 item 5 says `R` "is recomputed from `R_u`, the slot points and `ρ`", which is a secp256k1 scalar multiplication for every ticket. §11.4 counts only SHA-256 compressions. The two reconcile as follows. The committed ticket gains one field, `x(R)` (suite 3: the encoding of `R`). The proof shows, for every half, two hash relations over committed values:

`pm_v = H_pm(x(Q) ‖ m_v ‖ salt)` and `c̃ = g · H_challenge(x(R) ‖ x(Q) ‖ m_v)`,

with `m_v` the sighash of variant `v` under the committed intent. The node, which opens `tkc` at ADMIT, recomputes `ρ` and `R = R_u + D_ℓ + ρ·E_ℓ` natively, as §4.2 already requires, and refuses a ticket whose `x(R)` differs. `ρ` never enters the circuit. Both relations are needed: without the `pm` relation the wallet could hold `R` fixed and search over messages, which reopens the ROS attack that `ρ` closes.

(b) *Use the SHA-256, SHA-512 and Keccak gadgets of Midnight's proof library, and count compressions per request, not per variant.* midnight-zk ships `hash/sha256`, `hash/sha512`, a Keccak gadget, foreign-field arithmetic and an in-circuit verifier for its own KZG proofs. It ships no STARK verifier. Its SHA-256 preimage example (one compression) is 1,911 rows. For BIP341 with SIGHASH_DEFAULT, two inputs and two outputs:

| Hash | Compressions | Shared by |
|---|---:|---|
| `sha_prevouts` (72 B), `sha_amounts` (16 B), `sha_scriptpubkeys` (70 B), `sha_sequences` (8 B) | 6 | the request |
| first two blocks of the tagged `SigMsg` (175 B; `sha_outputs` and `input_index` fall in the third block) | 2 | the request |
| `sha_outputs` (86 B) | 2 | each variant |
| third block of `SigMsg` | 1 | each (variant, input) |
| challenge, tag midstate fixed (96 B) | 2 | each half |
| `pm`, as a SHA-256 tagged hash (96 B) | 2 | each (variant, input); zero if `H_pm` is Poseidon |

For `K = 8`, `L = 2`, `G_max = 2`: 8 + 16 + 16 + 60 = 100 compressions with a Poseidon `H_pm`, 132 with SHA-256. That is 190,000 to 250,000 rows, inside `k = 18`, with the rest of `authorize` in the remaining rows or at `k = 19`. The ticket commitment `tkc` is padded to 32 entries. DESIGN.md's count is 16 × 15 = 240 compressions in a STARK of 2^18 rows followed by a wrap of 2^20 constraints.

**Gain.** One proof at `k = 18` replaces a STARK and a `k = 20` wrap. A community benchmark of Midnight's prover reports 12.3 s at `k = 17` and 24.6 s at `k = 18` on a server CPU, and 4.4 s and 8.8 s on an RTX 5090. Proving time doubles per unit of `k`, so the wrap alone is about 100 s on that CPU. The gain is 4 times in proving time at the least, one proof system fewer, and no new verifier contract. O4 changes from "write an AIR for three suites and measure a wrap" to "compose three existing gadgets and measure `k`".

On a phone a `k = 18` KZG proof takes minutes (estimate). Measured hash-based provers are far faster there: WHIR at 2^20 BabyBear coefficients runs in 240 ms on an iPhone CPU, and Binius proves a 2 KiB SHA-256 in 103 ms on an M1 and about 5 s on a phone. The position is: the companion device or a desktop proves the native circuit at launch. A phone-only path is a second phase with a zero-knowledge hash-based proof on the phone and an untrusted wrapping service, and it is built only if phone proving of the native circuit measures above the product's target.

**Security.** C10 (blindness) holds: the node learns `x(R)` from the ticket opening at ADMIT, and it computes `R` itself at that moment today. C6 holds: the statement proved is the statement of §5.3 item 5 with `R` moved from a recomputation in the proof to a committed value that the node checks. C5 and O6 depend on the node's check `x(R)` = recomputed, which is a rule of §5.4. Choosing Poseidon for `H_pm` puts the hiding of `pm` on Poseidon as a random oracle, which Midnight's commitments already assume. TEE mode v1 has no ticket proof and is unaffected.

**Cost.** A circuit of about 1,500 lines over existing gadgets. Whether Compact can call these gadgets, or the circuit must be written against the library directly, is to be confirmed with Midnight.

**Sources.** midnight-zk repository (tree, `zk_stdlib/goldenfiles/examples/ShaPreImageCircuit`: `k = 13`, 1,911 rows; `BitcoinThresholdECDSA`: 56,139 rows); Midnight forum post on the GPU proof server; Aptos Keyless write-up (client proof under 5 s with server-side wrapping as a stated plan; a 2^22-gate TurboPLONK proof takes 104 s); client-side proving report Q1 2026; the ethresear.ch WHIR benchmark; the Delving Bitcoin prover comparison (a statement with ECDSA verification inside takes 8 s to 4.5 min on an M2 Max and 6 min on an iPhone 14 Pro, which is the cost of arithmetic the proof should not contain).

### 3.5 Request-path arithmetic

**Mechanism and gain**, per node and request, secp256k1, launch parameters, after §3.1 and §3.2:

| Step | Today (calibrated) | After | How |
|---|---:|---:|---|
| `π` check before ordering | 0.40 ms | 0.20 ms | the three equations as one variable-time multi-scalar check with random coefficients (9 points); all inputs are public |
| Outer share: DH and check | 0.40 ms | 0.11 ms | small-index evaluation; drop the `G·sk_i = PK_i` recheck that `decrypt` runs on every call |
| Inner dealings | 4.66 ms | 0 | §3.2 |
| Header key | 0.50 ms | 0.45 ms | one partial; combine `t` partials in constant time |
| Tickets: `ρ`, `R`, `σ` | 0.89 ms | 0.11 ms | lazy: only the `L` tickets of the selected variant, at release |
| TEE check of §4.7 item 4 | 1.78 ms | 0.25 ms | lazy, and each check is `s_u·G = S_u` plus one 3-term variable-time combination |
| Own partials | 0.45 ms | 0.01 ms | a partial is two field multiplications; the self-check goes away because the combiner's signature check covers it |
| Variant key | — | 0.45 ms | as the header key |
| Combine (TEE: every node) | 7.4 ms on the combiner | 0.15 ms | optimistic: interpolate, verify the signature, check partials only on failure (the prototype's `combine` already works this way); cache `D_{ℓ,i}`, `E_{ℓ,i}`, `X_{f,i}` |
| Post signatures | 1.7–3.1 ms | 0.1–1.0 ms | §3.6 |
| **Total, TEE mode** | **11.2–12.6 ms** | **1.8–2.7 ms** | |

"Lazy" means a check that concerns one variant runs when that variant is released. A wrong ticket on an unselected variant harms nobody. A wrong ticket on the selected variant makes every honest node refuse, and the request ends VOID at release where today it ends VOID at ADMIT.

Library choice. First, call `mul_by_generator` wherever the base is `G`: 54.1 µs → 26.1 µs, measured, with no new dependency. Second, move the verification paths (share checks, `π`, partial checks, batch equations) to libsecp256k1, whose verification uses wNAF, the curve endomorphism and Shamir's trick in variable time, and whose signing path uses a precomputed table of multiples of `G`. k256 offers only constant-time arithmetic and no multi-scalar routine, which is the wrong tool for checks on public data. The size of that second step is not measured here; it must be benchmarked on the node hardware before the dependency is taken. curve25519-dalek already has a basepoint table (10.2 µs) and a variable-time multi-scalar routine. No GPU belongs on a node: after these changes a request costs under 3 ms of single-core arithmetic in pieces of 50 µs.

**Security.** Every variable-time routine here runs on public data: commitments, tickets, partials already released, signatures. The Diffie-Hellman with `sk_i`, the PRF partials and the combination of partials stay constant-time, because in TEE mode the operator watches timing and those values open the header. C6 holds: the lazy checks still precede the release they guard. C13 (liveness) is unaffected for honest wallets.

**Cost.** About 500 lines. The libsecp256k1 step adds a C dependency and a benchmark.

**Sources.** Micro-benchmark of §2.1; `impl/src/message.rs` (`decrypt`, `AuthProof::verify`), `impl/src/signing.rs` (`partial`, `verify_partial`, `combine`); libsecp256k1 README; BIP340 batch verification.

### 3.6 Board posts: one signature per node and block

**Mechanism.** A node signs once per board block. The signed vote covers the block and a list of the node's posts for that block: (`eid`, kind, digest) triples for ACK, ADMIT, RELEASE and FINAL across all requests. The QC of the block certifies all of them. Posts are no longer signed one by one, and a node checks `q` signatures per block, in one Ed25519 batch. Shares, partials and PRF partials travel on the attested or authenticated peer channel with its MAC and carry no signature: each is checked against a public commitment or by the final signature, and no step needs a transferable proof of who sent a bad one.

**Gain.** The prototype verifies each post alone: 54–69 µs each, 31–45 posts per request, 1.7–3.1 ms, and BENCHMARKS.md finds post checks to be half of the base protocol's CPU. With one vote per node and block, a request costs `5 × q` signature checks divided by the number of requests in the block: at 34 µs per Ed25519 check and 16 requests per block that is 0.06 ms. Board bytes per request for posts fall from 4–5 KB to under 1 KB.

**Security.** A post is authenticated exactly as before, by the node's `post_i` key, through the vote that contains it. Complaints stay individually signed and public, because they void a request. C13 holds. BLS aggregation is not used (§4, item 9).

**Cost.** A board format change, about 300 lines.

**Sources.** `impl/BENCHMARKS.md` ("board-post checks are about half of the per-node CPU"; "the sequencer verifies each signed post and each partial individually"); micro-benchmark of §2.1.

### 3.7 Multi-shard: cost that does not grow with the actor count

DECISIONS.md items 21–25 make the user half a sum over a set `A` of actors. Done by copying the user's part of the envelope per actor, a request with `|A|` actors costs `|A|` envelopes and `|A| × 16` inner dealings.

**Mechanism.**

(a) *Actors deal nothing.* The initiator's header carries, for each variant body, a public key `P_{v,g} = y_{v,g}·G` with `y_{v,g} = KDF'(κ_0·H_c(dd ‖ v ‖ g))`. The initiator knows `κ_0` and computes it. Each actor encrypts its scalars `s_a^{(v,g,j)}` to `P_{v,g}` and posts one contribution: per half a nonce reference and 32 bytes, plus one ephemeral point per body. The committee derives `y_{v,g}` when it releases that variant, by the same partials as §3.2, and decrypts every actor's scalar for it.

(b) *One binding factor per half.* With per-signer factors, as FROST has, a node computes `|A|` scalar multiplications for every ticket. MuSig2 uses a single coefficient over the aggregated second nonce: `R = R_1 + b·R_2` with `b` a hash of the aggregate nonce, the key and the message. Here `ρ` hashes the slot ids, all actor commitments of the half and `pm`, and `R = Σ_a D_a + D_ℓ + ρ·(Σ_a E_a + E_ℓ)`: point additions and one multiplication for any `|A|`.

(c) *Check the sum first.* The combiner adds the actors' scalars and the committee half and verifies the final signature. It checks each actor's `s_a·G = σ·(D_a + ρ·E_a) + c̃·λ_a·X_a` only when that fails.

(d) *Actors use fresh nonce pairs per half.* An actor's pool entry is two points (66 bytes) with no dealing. An actor never shares a pair across variants, for the reason given in §4, item 1.

**Gain.** Per actor and request: about 2.4 KB on the board for 30 halves, one Diffie-Hellman and one field addition per released input at each node (about 60 µs), and nothing in the ticket proof beyond the hash inputs. The copy-per-actor form costs each node 16 inner share checks and 16 nonce multiplications per actor (5.6 ms at prototype cost) and 8–15 KB per actor.

**Security.** C3 and C4 generalize per actor: each actor's halves use fresh nonces, so the committee with every dealt half still cannot produce a half for another message. C9 holds as in §3.2: an actor's scalar for an unselected variant is encrypted to a key that the committee never derives. The single binding factor moves the Schnorr argument for C5 from the FROST form to the MuSig2 form. **Needs a proof**: O6 must cover actors as co-signers with a single coefficient. A `k`-of-`m` group shard uses Lagrange weights `λ_a` for the subset named in the header, fixed before the challenge as item 23 requires. Blindness toward operators (item 25) holds: contributions are ciphertexts until release.

**Cost.** About 800 lines on top of §3.2, and the proof.

**Sources.** DECISIONS.md items 21–25; BIP327 (single nonce coefficient, untrusted aggregation, optional partial-signature verification, the nonce-reuse warning).

### 3.8 ECDSA birth and refill

Every figure here is an **estimate** conditional on O1 and O2.

**Mechanism.**

(a) *Pool `F_presig` outputs.* `(R_f, Φ, Ψ)` and the shares of `φ`, `ψ` depend on `x_f` only. The committee produces them ahead of time, as it does Schnorr nonce slots, and a birth consumes 32 from the pool. The committee-internal rounds leave the birth session.

(b) *Two multiplications per node and slot in place of three.* The products `a·φ_i` and `(a·x_U')·φ_i` share the node's input `φ_i`. With an OT-based multiplication the node is the receiver and its choice bits encode `φ_i` once; the user sends two correlations per transfer. One vector multiplication of length 2 and one scalar multiplication on `ψ_i` replace three scalar multiplications.

(c) *Eight slots at birth, the rest in the background.* O11 already refills below 8. Birth with `N_slot = 8` is four times shorter, and the wallet refills while it is online.

(d) *Choose the OT-based multiplication of the DKLs23 family for both functionalities.* A vendor benchmark of September 2026 measures, for 2-of-3 presigning, 0.05 core-seconds and about 120 KiB per presignature with DKLs23 against 5.9 core-seconds and about 88 KiB with CGGMP21. CPU differs by a factor of 110 and bytes by 1.4. Bytes are the cheaper resource for a committee of 9 to 17 nodes.

(e) *Batch the public check of step 5.* The `2 × N_slot` equations in bases `R_ℓ` fold into one multi-scalar check with local coefficients, as in §3.1(c).

**Gain.** At `n = 9`: 864 two-party multiplications per birth become 576 with (b) and 144 at birth time with (c). Scaling the benchmark's 120 KiB for three pairs, a pair costs about 40 KiB, so the user's traffic at birth falls from about 13 MB to about 2 MB. The committee's `t = 7` presigning (21 pairs, about 0.35 core-seconds and 840 KiB per slot) moves off the path.

**Many actors (DECISIONS.md item 24).** With a set `A` of outside shard holders the user's values `a = k_u⁻¹` and `a·x_A` are themselves shared among the actors. Each (actor, node) pair then runs the two multiplications of (b), and the actors run pairwise multiplications among themselves to share `a` from `k_u` and to share `a·x_A`. The count per slot is about `2·|A|·n + 2·|A|·(|A| − 1)`: 18 for one actor at `n = 9`, 66 for three, 130 for five. The instantiation is **open**, as O1 and O2 are, and the estimate assumes the pooled `F_presig` of (a).

**Security.** (a) holds if `F_presig` outputs are independent of the user, which the definition of §3.6 states; an unused pool entry is burned on rotation as Schnorr slots are. (b) changes the instantiation of `F_mul`, which is O2. (c) and (e) change no claim. C3 for ECDSA stays conditional on O1 and O2.

**Cost.** Set by O1 and O2.

**Sources.** DESIGN.md §3.6; the Silence Laboratories presignature benchmark page. The DKLs23 paper (ePrint 2023/765) could not be downloaded and is not cited as read.

### 3.9 Suite 3: ristretto255 for every point that is not part of a signature

`is_torsion_free` costs 49.3 µs, more than a variable-base multiplication (30.8 µs), and the prototype runs it on every commitment point. Sealed Ed25519 Step A measures 7.55 ms against 2.19 ms for BIP340 for that reason. A slot pool on edwards25519 would spend 14 × 7 × 49 µs = 4.8 ms per slot on torsion checks against 0.4 ms on share checks.

**Mechanism.** Encode Feldman commitments, slot points, `R_u`, `S_u` and `E` as ristretto255 elements, as the seal group already does. Decoding costs one field inversion and guarantees a prime-order element. Only `X` (once, at birth) and the final `R` of a released signature are Edwards points, and the combiner's `verify_strict` checks them.

**Gain.** About 3.5 times on Step A for suite 3 (7.55 ms → about 2 ms), and 10 times on suite-3 slot verification.

**Security.** Every check holds in the prime-order group, so small-order components cannot enter a commitment. The signature that leaves the system is still verified in full.

**Cost.** An encoding change in suite 3, about 200 lines.

**Sources.** Micro-benchmark of §2.1; `impl/BENCHMARKS.md` (Ed25519 rows); `impl/src/ed25519.rs`.

### 3.10 More slots per dealing round

**Mechanism.** When all `n` dealers of a round are qualified, apply a fixed `(n − t + 1) × n` Vandermonde matrix to their `n` dealt sharings. Any `t − 1` nodes know at most `t − 1` of the inputs, so the `n − t + 1` outputs are jointly uniform to them. A round of `n` dealings yields `n − t + 1` slots: 3 at launch, 6 at `n = 17`. Today `t` dealings yield one. When a dealer is disqualified the round falls back to today's rule.

**Gain.** Polynomials per slot fall from `2t` to `2n/(n − t + 1)`: 14 → 6 at launch (2.3 times), 24 → 5.7 at `n = 17` (4.2 times), in CPU and in bytes, in the fault-free case.

**Security.** The outputs are public linear combinations of the dealers' commitments, so every node still computes `D_ℓ`, `E_ℓ`, `D_{ℓ,i}`, `E_{ℓ,i}`. C12 is unaffected. C5 and O6 **need a proof** that jointly uniform, linearly related slots are as good as independent ones in the reduction. This is randomness extraction as used in honest-majority MPC; no source was opened for it, so it ranks last among the cryptographic changes and waits for O6.

**Cost.** About 200 lines.

### 3.11 TEE mode

- A SEV-SNP confidential VM has no enclave boundary inside the node process, so there is no per-call crossing to remove. Attestation evidence is produced per boot (classes 0x02, 0x04) and per epoch (0x03), never per request.
- *Witness entries are batched per board height for every kind*, as §7.7 already does for `open`: one signed WITNESS message per peer and height carrying all entries, one signed ack back. Signature work per request falls with the batch size.
- *The witness log is appended with group commit.* dm-integrity in its default journal mode writes data and tags to the journal and then to their place, which halves write throughput, and a FLUSH forces the journal out. One `fsync` per board height covers all acks of that height.
- *The witness does not move onto board votes.* A board vote arrives once per commit (0.5–1 s). The peer round takes 20 ms. Piggybacking would slow the path by a commit to save 60 ms of a path that is seconds long.
- *The open witness and the first release witness merge.* At ADMIT a node witnesses `(node, eid) → H(header)`. The release digest `(j_g, ℓ, H(tk))` is a function of that header and the board anchor, so a second, conflicting release needs a forged anchor, which the prevote witness prevents within the same collusion bound. **Needs a proof** against §7.7's bound; the gain is one peer round (20–40 ms), so this is optional.

**Sources.** DESIGN.md §7.2–7.7; the dm-integrity kernel documentation (journal mode, `commit_time`).

### 3.12 Smaller items

- **Complaints.** One complaint per dealer message voids the whole batch of that dealer; it already carries one DLEQ proof for all polynomials of the message. With §3.1(c) a node pays the per-polynomial search only when a batch fails.
- **Cross-request batching.** A node folds all `π` checks, all outer share checks and all signature checks of one board block into one multi-scalar check per curve. At 16 requests per block the per-request share of those checks falls by a further factor of about 2 (estimate, from the 0.1 against 0.3 multiplication-per-point figures of §2.1).
- **Fee grid.** After §3.1, §3.2 and §3.4 a further variant costs about 210 bytes per half, 400 bytes of capsule and 3 to 5 compressions. `K = 8` stays.
- **Authorization batching (O12).** midnight-zk has an aggregation crate (IVC and multi-circuit aggregation). Aggregating many `authorize` proofs into one Midnight transaction lowers Midnight fees and hides timing inside a block. It adds a proving step and does not shorten the request path, so it serves O12 and is not a speed item.

## 4. What not to do

1. **One user nonce for all variants of an input.** Hashing the whole variant set into `pm` and using one `R_u` gives one `R` per input, one slot and one nonce for all `K` variants, and it satisfies the binding rule. It breaks C3. The adversary of C3 is the whole committee with every dealt half. Two halves `s_u = σ·k_u + c·(…)` and `s'_u = σ·k_u + c'·(…)` with one `k_u` give the user's key by subtraction. The same holds for an actor's nonce pair across variants: `K ≥ 3` halves on one pair `(d_a, e_a)` are three equations in three unknowns. Committee slots can be shared across variants (§3.1) only because the committee's halves are never dealt in advance.
2. **One ECDSA slot for all variants.** Two user halves `h·w_u + r·μ_u` on one slot reveal `(w_u, μ_u)` to a committee that holds them, and with its own halves reveal `k` and `x` (§4.4). ECDSA keeps `K·L` slots per spend. `K = 3` on P2WPKH and `K = 1` on Ethereum already keep that small.
3. **Returning unused or voided slots to the pool.** It would cut slot consumption again. A slot named in an opened envelope has had user halves computed against it, and the wallet that named it knows `ρ`-bound points on it. §4.5 item 4 burns it, and C12's counting needs that.
4. **One committee nonce per slot.** It halves the pool. It removes the binding factor and opens the ROS attack that §4.2 closes.
5. **Sending a share or a partial before the QC,** for example with the mempool gossip to save a round. C8 is exactly the statement that this does not happen.
6. **Releasing at Midnight inclusion, before finality,** in the Midnight-first path. C6 requires a settled authorization, and a signature released to a host chain cannot be recalled. The legal ways to stop waiting for `F_M` are the overlap and the board-first option of §3.3.
7. **Board-first authorization for P2, or for a P1 charter with stateful predicates.** A hold authority revokes on Midnight, and it cannot revoke what is not there; C7 would fail in TEE mode, where it holds today. A spend limit checked against one finalized root admits two requests that together exceed it (§3.3).
8. **Skipping the witness round on an optimistic path.** It saves 20–60 ms out of seconds and removes rollback protection for up to `n − 1 − 2f` colluding operators.
9. **A BLS aggregate signature for the quorum certificate at `n = 9` or `n = 17`.** A pairing-based verification costs about 1.3 ms. Twelve Ed25519 signatures cost 0.4 ms singly and less in a batch. Aggregation pays at hundreds of validators.
10. **Elliptic-curve arithmetic inside the ticket proof.** midnight-zk's threshold-ECDSA example is 56,139 rows; a recomputation of `R` for 30 halves would add that order of rows per half and pass 2^20. §3.4(a) removes the need.
11. **A STARK wrapped in a SNARK when the SNARK's own library already has the hash gadgets.** The wrap costs more rows than the statement it wraps (2^20 against 2^18) and needs a STARK verifier gadget that Midnight's library does not have.
12. **Batch verification with short coefficients or without a fallback.** 32-bit coefficients give 2^-32 soundness against a dealer who can retry. Without the per-polynomial fallback a node cannot name the bad dealing, and the public complaint of line dealing needs a named dealing.
13. **Variable-time arithmetic on `sk_i`, on share values or on PRF partials.** In TEE mode the operator measures time, and those values open the header.
14. **Replicated pseudorandom secret sharing for nonces.** It gives shares with no interaction, and it gives no commitments `D_{ℓ,i}`, `E_{ℓ,i}`, which partial verification needs. Its key count is `C(n, t−1)`: 84 at launch, 12,376 at `n = 17`. The verifiable variants known to this lane need an honest majority among `2t − 1` nodes, which `t = n − f` does not give (not source-checked).
15. **An anchor output for fee bumping, to reach `K = 1` on Bitcoin.** It adds a distinguishable output (B5) and a funded fee wallet. After §3.1–3.4 a variant is cheap enough to keep.
16. **A smaller or second frame class for speed.** The frame is the anonymity set (O7). §3.2 makes room inside 16 KiB at `n = 17`; it does not shrink the frame.
17. **A GPU on the node.** Per-request arithmetic is under 3 ms of short operations. A GPU helps the prover (2.8 times on Midnight's prover per the forum post), and that is the wallet's side.

## 5. Revised cost table

Calibrated from the unit costs of §2.1 unless marked. P2TR, `K = 8`, `L = 2`. "Before" at `n = 17` uses `K·L = 10`, the most today's frame holds. "After" uses `G_max = 2` and §3.1(a), (b), §3.2, §3.3(a), (b), §3.4, §3.5, §3.6. The column "with batching" adds §3.1(c) and a table-driven generator multiplication and is an estimate.

### 5.1 Node CPU per request (one core)

| | `n = 9`, before | `n = 9`, after | with batching | `n = 17`, before | `n = 17`, after | with batching |
|---|---:|---:|---:|---:|---:|---:|
| Request path, TEE mode | 11.2–12.6 ms | 1.8–2.7 ms | 1.3–2.0 ms | 11.5–14.2 ms | 2.4–3.3 ms | 1.8–2.6 ms |
| Slot pool | 134 ms (16 slots) | 3.6 ms (4 slots) | 1.2 ms | 262 ms (10 slots) | 7.2 ms (4 slots) | 2.0 ms |
| **Total** | **146 ms** | **5.4–6.3 ms** | **2.5–3.2 ms** | **274–276 ms** | **9.6–10.5 ms** | **3.8–4.6 ms** |
| Requests per second and core | 7 | 160–185 | 310–400 | 3.6 | 95–105 | 220–260 |
| Combiner, per request | 7.4 ms | 0.15 ms | 0.15 ms | 20.5 ms | 0.2 ms | 0.2 ms |

Non-TEE mode has no constant-term check and combines partials in variable time: subtract about 0.7 ms at `n = 9` and 1.2 ms at `n = 17` from the request path, and add the proof check if the node verifies the authorization itself (1.4 ms, §3.3(c)).

### 5.2 Bytes on the board per request

| | `n = 9`, before | `n = 9`, after | `n = 17`, before | `n = 17`, after |
|---|---:|---:|---:|---:|
| Frame | 16.4 KB | 16.4 KB | 16.4 KB | 16.4 KB |
| Used inside the frame | 14.5 KB | 11.2 KB | 13.9 KB (`K·L = 10`) | 11.6 KB (`K·L = 16`) |
| Slots | 117 KB | 29 KB | 226 KB | 90 KB |
| Posts | 4–5 KB | under 1 KB | 7–10 KB | under 2 KB |
| **Total** | **138 KB** | **46 KB** | **250 KB** | **108 KB** |
| Total with derived shares, §3.1(d) (needs a proof) | — | 36 KB | — | 75 KB |
| Total with (d) and §3.10, no dealer disqualified (estimate) | — | 25 KB | — | 32 KB |

### 5.3 Latency, post to broadcast

| | Before | After, every profile | After, board-first (P0, stateless P1) |
|---|---:|---:|---:|
| Formula | `F_M + 5C + 0.07 s` | `max(F_M, C + h) + C + 2h` | `2C + 3h` |
| `C = 1 s` | `F_M` + 5.1 s | `F_M` + 1.1 s | 2.15 s |
| `C = 0.5 s` | `F_M` + 2.6 s | `F_M` + 0.6 s | 1.15 s |
| Board commits on the path | 5 | 2 | 2 |
| Peer rounds on the path | 4 | 3 | 3 |

### 5.4 Wallet and prover

| | Before | After |
|---|---:|---:|
| Envelope arithmetic, `n = 9` | 149 mult, 8.3 ms | 7 + 9 + 5 + 60 = 81 mult, 4.5 ms |
| Envelope arithmetic, `n = 17` (before: `K·L = 10`) | 11 × 12 + 17 + 5 + 10 = 164 mult, 9.1 ms | 12 + 17 + 5 + 60 = 94 mult, 5.2 ms |
| Ticket proof, non-TEE | STARK of 2^18 rows and a wrap of 2^20 constraints (about 100 s on a server CPU for the wrap, extrapolated) | one circuit at `k = 18` (25 s on that CPU, 9 s on an RTX 5090; both from the forum post, circuit not named, so an estimate) |
| SHA-256 compressions in the proof | 240 | 100–132 |
| ECDSA birth, user traffic, `n = 9` (estimate, conditional on O2) | 864 multiplications, about 13 MB | 144 at birth, about 2 MB; 432 more in background refills |

### 5.5 Multi-shard, per actor and request

| | Copy of the user part per actor | §3.7 |
|---|---:|---:|
| Board bytes | 8–15 KB | 2.4 KB |
| Node CPU | 5.6 ms | 0.06 ms per released input |
| Dealings by the actor | 16 | 0 |
| Growth of the ticket proof | 16 tickets | none beyond `ρ`'s hash inputs, which are outside the proof |

## 6. Sources

Local files read:

- `design/enhancement/DESIGN.md`, `DECISIONS.md` (items 21–25): the protocol, its claims C1–C16 and the cost estimates of §11.
- `design/SCHEME.md` §3.2–3.4, §7 and the theorem statements of `design/PROOFS.md` (Theorems A–E): the dealing, the proof `π`, Step A, the base cost model.
- `impl/BENCHMARKS.md`, `impl/bench9-output.txt`, `impl/src/algebra.rs`, `message.rs`, `signing.rs`, `ed25519.rs`: measured figures and the code paths priced in §2.
- Scratch micro-benchmark, `/tmp/claude-1000/-home-hoskinson/bee643b4-08f5-4340-b29d-1a5130e7b1e5/scratchpad/speedbench/src/main.rs`: the unit costs of §2.1. The scratchpad is temporary, so the appendix keeps the raw output and the routine. The figures should be re-measured under `heavy-slot --exclusive` inside `impl/benches`, and on the node hardware, before anyone relies on them.
- `~/.cargo/registry/.../k256-0.13.4/Cargo.toml` and `src/arithmetic/mul.rs`: `precomputed-tables` is a default feature and backs `mul_by_generator`.

Web sources opened:

- https://github.com/midnightntwrk/midnight-zk (README, file tree, and `zk_stdlib/goldenfiles/examples/ShaPreImageCircuit`, `BitcoinThresholdECDSA`, `SchnorrExample` through raw.githubusercontent.com): Midnight's library is PLONK with KZG on BLS12-381; it has SHA-256, SHA-512, RIPEMD-160, Keccak, Poseidon, foreign-field ECC, a KZG verifier gadget and an aggregation crate; the row counts used in §3.4.
- https://docs.midnight.network/concepts/network-architecture/consensus : AURA block production and GRANDPA finality; no block or finality time is given.
- https://getblock.io/nodes/midnight/ : average block time about 6 seconds.
- https://forum.midnight.network/t/open-source-drop-cuda-accelerated-midnight-proof-server-nocy-gpu-proof-server/972 (20 January 2026): proving 12.3 s at `k = 17` and 24.6 s at `k = 18` on an EPYC 7642, 4.4 s and 8.8 s on an RTX 5090.
- https://alinush.github.io/keyless-zkp (29 October 2025): pairing-based verification times (TurboPLONK 1.36 ms, Groth16 on BLS12-381 1.31 ms), a 2^22-gate TurboPLONK proof at 104 s, and the plan of client-side hash-based proving with a server-side wrap.
- https://hackmd.io/@clientsideproving/report-q1 (Q1 2026): Binius proves SHA-256 of 2,048 bytes in 103 ms on an Apple M1 and in about 5 s on phones.
- https://ethresear.ch/t/gpu-accelerated-whir-proving-on-apple-silicon/24762 (30 April 2026): WHIR over BabyBear with Poseidon2 at 2^20 coefficients in 240 ms on an iPhone CPU and 133 ms with its GPU.
- https://delvingbitcoin.org/t/pq-provers-for-p2pkh-outputs/2287 (February 2026): proofs of a statement with SHA-256 and a full ECDSA verification take 8 s (STWO-Cairo) to 4.5 min on an M2 Max and about 6 min on an iPhone 14 Pro.
- https://github.com/Plonky3/Plonky3 : a SHA-256 AIR, a Keccak AIR and a WHIR-based commitment scheme exist for the second-phase phone path; the README gives no timings.
- https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki : the batch verification equation and the rule that coefficients come from a generator seeded by a hash of all inputs.
- https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki : one nonce coefficient `b` over the aggregated second nonce; untrusted nonce aggregation; nonces may be sent before the message is known; a nonce used twice reveals the key; partial-signature verification is needed only to identify a disruptive signer.
- https://github.com/bitcoin-core/secp256k1 : precomputed table for generator multiplication, wNAF, the endomorphism and Shamir's trick in verification, constant-time signing.
- https://arxiv.org/pdf/2310.14821 (Mysticeti, v6; read: the abstract, the caption of Figure 1, and the evaluation's setup and ideal-conditions paragraphs; the protocol and proof sections were not read): three message rounds to commit, 0.5 s WAN commit latency, sub-second latency with 10 and 50 validators across 13 AWS regions, Sui's median falling from 1.9 s to 400 ms on 106 validators.
- https://presign-calculator.demo.silencelaboratories.com/ (runs of September 2026, vendor-run): DKLs23 against CGGMP21 for 2-of-3 presigning: 0.05 against 5.9 core-seconds and about 120 against 88 KiB per presignature.
- https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html : journal mode writes data twice; `commit_time` and FLUSH.

Not opened, and therefore not cited as evidence: ePrint 2023/765 (DKLs23), 2018/727 (DiSE), 2024/1586 (WHIR) and 2024/253 (2PC-MPC). eprint.iacr.org answered automated requests with HTTP 403. §3.2, §3.8 and §3.10 say where a claim rests on these papers' content from memory; the proofs those sections ask for must start by reading them.

## Appendix: micro-benchmark

Crates as pinned by `impl/Cargo.lock` (k256 0.13.4, curve25519-dalek 4.1.3, ed25519-dalek 2.2.0), release build, one thread, timed loops after one warm-up call, run under `heavy-slot` without `--exclusive` on 2026-11-14.

The small-index evaluation:

```rust
fn mul_small(p: ProjectivePoint, k: u64) -> ProjectivePoint {
    let mut acc = ProjectivePoint::IDENTITY;
    for b in (0..64 - k.leading_zeros()).rev() {
        acc = acc.double();
        if (k >> b) & 1 == 1 { acc += p; }
    }
    acc
}
// c[0] is the constant term; node is the evaluation index (1..=n)
fn horner_small(c: &[ProjectivePoint], node: u64) -> ProjectivePoint {
    let mut acc = ProjectivePoint::IDENTITY;
    for p in c[1..].iter().rev() { acc = mul_small(acc + p, node); }
    acc + c[0]
}
```

`horner_small` is checked against `G * share` for random polynomials before it is timed. It is variable-time and is used on public commitments only.

First run (the figures of §2.1 except the three table rows):

```
== secp256k1 (k256 0.13.4)
variable-base mul                                               55.7 us
generator mul                                                   54.1 us
lincomb 2 terms (aG + bQ)                                       86.4 us
-- n=9 t=7
share check, prototype (full-width Horner)                     291.5 us
share check, small-scalar Horner                                51.6 us
16 share checks, small-scalar Horner                           714.9 us
16 share checks, one RLC batch (lincomb, 128-bit r)           2691.2 us
verify partial, cached evals (g*s == lincomb3)                 122.4 us
verify t partials, one RLC lincomb                             566.4 us
-- n=17 t=12
share check, prototype (full-width Horner)                     496.7 us
share check, small-scalar Horner                                50.6 us
16 share checks, small-scalar Horner                           825.2 us
16 share checks, one RLC batch (lincomb, 128-bit r)           4527.2 us
verify partial, cached evals (g*s == lincomb3)                 121.1 us
verify t partials, one RLC lincomb                             859.1 us
k256 ECDSA verify (one board post)                              68.9 us
k256 BIP340 verify                                              65.8 us
== edwards25519 (curve25519-dalek 4.1.3)
variable-base mul                                               30.8 us
basepoint mul (table)                                           10.2 us
is_torsion_free                                                 49.3 us
vartime double-base (aA + bB)                                   30.8 us
vartime MSM, 112 points, full scalars                         1048.8 us
vartime MSM, 112 points, 128-bit scalars                       348.4 us
ed25519-dalek verify (one board post)                           33.8 us
ed25519-dalek verify_strict                                     52.6 us
```

Second run, for the generator table. The machine was busier and several unrelated lines moved by a factor of two (the prototype share check at `t = 7` read 721 µs, the edwards25519 variable-base multiplication 119 µs), so only these lines are used:

```
variable-base mul                                               53.6 us
generator mul (g * s, generic)                                  55.0 us
generator mul (mul_by_generator, table)                         26.1 us
share check t=7, small Horner + table generator mul             35.7 us
small-index Horner alone, t=7, i=9                               9.4 us
```
