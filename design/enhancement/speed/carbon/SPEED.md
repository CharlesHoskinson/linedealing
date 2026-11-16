# Split-Line Dealing: Cryptographic and Systems Speed Engineering

This report profiles the split-line dealing architecture specified in `design/enhancement/DESIGN.md` and `design/enhancement/DECISIONS.md` against the Rust prototype in `impl/`, identifies why latency, sustained node throughput, client proving, and `n = 17` envelope sizes cost what they do today, and specifies ten ranked optimizations that make the protocol fast without weakening any security claim in `DESIGN.md` §9 (`C1`–`C16`), the TEE rollback bound (`§7.7`), or the multi-shard charter invariants (`DECISIONS.md` 21–25).

---

## 1. Summary: The Five Biggest Wins

Baseline numbers below are for a two-input Taproot spend (`K = 8` fee steps, `L = 2` inputs, `16` inner dealings) at launch (`n = 9, f = 2, q = 6, t = 7`) and `n = 17` (`f = 5, q = 12, t = 12`).

| Rank | Optimization | Target Metric | Before (`DESIGN.md` §11 / `impl/`) | After | Speedup |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Two-block board pipeline + overlapped Midnight finality `F_M` + piggybacked group-committed TEE peer witnessing** (§3.1) | Post-to-broadcast latency; BFT commits/req; TEE `dm-integrity` flushes | `F_M + 5.07 s` (`5` serial 1 s blocks after `F_M`); `2n` `fdatasync`s/req | `max(1 blk + 20 ms, F_M) + 1 blk + 30 ms` (`2.05 s` at 1 s blocks when `F_M <= 1 s`; **`0.85 s`** at 400 ms blocks); `1` `fdatasync`/block | **2.5×–6× lower latency**; **2.5× higher board cap**; **~300× fewer disk flushes** |
| **2** | **Lazy per-node slot commitments + batched epoch Schnorr slot pool verification (`B_pool = 1,024`)** (§3.2) | Sustained committee throughput (off-path slot burn per 16-slot spend) | `2,192` muls (`109.6 ms` unbatched, `~55 ms` batched) at `n = 9`; `6,240` muls (`312 ms`) at `n = 17` (*estimate*) | **`40.8` mul-eq (`0.69 ms`)** at `n = 9`; **`104.2` mul-eq (`1.77 ms`)** at `n = 17` | **54×–60× fewer mul-eq**; **80×–176× faster wall-clock** (removes #1 sustained throughput wall) |
| **3** | **Single-circuit `midnight-zk` `Table16` PLONK (`k = 18`) + Poseidon2 internal hashes + BIP341 midstate hoisting + `tkc` nonce binding** (§3.3) | Non-TEE client proving time, RAM, and Midnight `authorize` verification | `2^18` SHA-256 STARK + `2^20..2^21` BLS12-381 wrap (`8–16 s` CPU, `~3 GB` RAM, *estimate*) | Single native `k = 18` (`~251.6k` rows) BLS12-381 Halo2-KZG proof (**`1.5–2.5 s` CPU**, **`~0.5 s` WebGPU**, `~400 MB` RAM); block-aggregated verify | **4×–8× smaller outer circuit**; **5×–6× faster CPU prove** (**16×–30× with client GPU**) |
| **4** | **Addition-chain Horner + 128-bit RLC + Strauss/Pippenger MSM + Montgomery batch inversion + optimistic combiner** (§3.4, §3.7) | Per-node on-path group operations (`K = 8, L = 2`, incl. combiner) | `204–264` muls at `n = 9`; `330–403` muls at `n = 17` (*estimate*, incl. `44` / `74` combiner muls) | **`30.7` mul-eq** at `n = 9`; **`31.8` mul-eq** at `n = 17` (core + combiner) | **6.6×–12.7× fewer scalar-mul equivalents**; makes `n = 17` cost within **4%** of `n = 9` |
| **5** | **Curve & wire stack: `libsecp256k1` (GLV + static tables), AVX2 `dalek`, single-pass `PrimeOrderPoint`, `blst` QCs, and `f + 1` seeded shares** (§3.5, §3.6, §3.8) | Wall-clock node CPU; Suite-3 decode; `n = 17` padded envelope frame | `14.9 ms` (`n = 9`) / `~23 ms` (`n = 17`) TEE node CPU (*estimate*); `7.55 ms` Ed25519 `Step A` (*measured*); `64 KiB` frame at `n = 17` | **`0.68 ms` (`n = 9`)** / **`0.75 ms` (`n = 17`)** total on-path TEE CPU; **`0.80 ms`** Ed25519 `Step A`; **`16 KiB` frame at `n = 17`** (`15,890 B`) | **22×–31× faster total on-path node CPU**; **9.4× faster Suite-3 `Step A`**; **4× smaller `n = 17` frame** |

Combined across on-path verification and background slot-pool replenishment, a single AMD EPYC Zen 4 SEV-SNP vCPU sustains **`~730 req/s` at `n = 9`** (`1.37 ms/req` total CPU) and **`~395 req/s` at `n = 17`** (`2.52 ms/req`), up from `~8–14 req/s/core` (`n = 9`) and `~3 req/s/core` (`n = 17`) in the unoptimized design — a **50×–130× increase in sustained single-core throughput**.

---

## 2. Profile: Where Time Goes Today

All numbers are strictly separated into **measured** benchmarks from `impl/BENCHMARKS.md` and `impl/bench9-output.txt` (single core, Arm Cortex-X925/A725 `aarch64`, Rust `1.94.0 --release`, `k256 = 0.13.4`, `curve25519-dalek = 4.1.3`, `ed25519-dalek = 2.2.0` without `batch`) and **estimates** derived from `DESIGN.md` §11 (`50 µs`/mul planning budget vs `32.5 µs`/mul measured in `k256`).

### 2.1 Measured Base Prototype (`impl/`) and Four Code-Level Root Causes

In the measured `n = 9, q = 6` prototype (`impl/BENCHMARKS.md`, `impl/bench9-output.txt`):
* **Open ECDSA signing (`1` slot)**: Node CPU is **`2,331 µs` (`410 req/s/core`)** at `t = 3` and **`3,320 µs` (`288 req/s/core`)** at `t = 7`; combiner CPU is `151 µs` (*measured*). Individual ECDSA board-post signature checks (`21 × 54 µs = 1,134 µs` at `t = 3`; `25 × 54 µs = 1,350 µs` at `t = 7`) consume **41%–49% of total node CPU** (*measured*).
* **Sealed `K = 8` multi-dealing (`sealed-k8`, `n = 9, t = 7`)** (*measured*, `impl/bench9-output.txt`):

| Suite | Owner Seal (`8` pts) | Node `Step A` (Envelope/Proof) | Node Decrypt + Check (`8` shares) | Partial (`1` pt) | Verify Partial (`1` pt) | Combine (`t = 7`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `bip340` (`k256`) | `4,897.9 µs` | `2,193.2 µs` | `2,071.6 µs` (`259 µs/pt`) | `227.2 µs` | `225.8 µs` | `143.7 µs` |
| `ecdsa` (`k256`) | `5,587.3 µs` | `2,035.0 µs` | `2,009.9 µs` (`251 µs/pt`) | `223.3 µs` | `223.8 µs` | `145.8 µs` |
| `ed25519` (`dalek`) | `9,708.5 µs` | **`7,554.3 µs`** | `3,364.7 µs` (`421 µs/pt`) | `184.6 µs` | `185.2 µs` | `164.9 µs` |

Auditing `impl/src/` exposes four concrete implementation bugs driving these numbers:
1. **256-bit constant-time scalar multiplications by `node ∈ 1..9` (`impl/src/algebra.rs:147`, `impl/src/ed25519.rs:430`)**: `Commitment::evaluate` computes Horner steps via `(acc + c) * x` with `x = Scalar::from(node as u64)`. Both `k256` and `curve25519-dalek` treat `Scalar` as secret and execute a full 256-bit constant-time variable-base scalar multiplication (`~32.5 µs` in `k256`, `~26.4 µs` in `dalek`) on every coefficient just to multiply a public point by a small public integer `1..9`. At `t = 7`, `6` Horner muls + `1` generator mul = `7 × 32.5 µs = 227.5 µs`, matching `Partial = 227.2 µs` and `Decrypt = 8 × 259 µs = 2,072 µs` to the microsecond.
2. **Triple subgroup multiplication and re-compression on Suite 3 (`impl/src/ed25519.rs:37-53, 512, 589`)**: Both `decode_compressed` and `encode_point` run `point.is_torsion_free()` (a full 253-bit variable-base scalar multiplication `[ℓ]P`) plus `point.compress()` (a `2^255 - 19` field inversion). Because `SealedDeal::step_a` (`ed25519.rs:589`) and `public_polynomials` (`ed25519.rs:512`) re-serialize decoded structs to hash transcripts instead of hashing input wire slices, every commitment point `C_{m,u}` (`8 × 7 = 56` points) undergoes **three** `[ℓ]P` multiplications and **two** field inversions (`168` scalar muls ≈ `4.5 ms` + inversions ≈ `1.0 ms`), inflating `ed25519` `Step A` by **3.4×** (`7,554.3 µs` vs `2,193.2 µs`).
3. **Byte-serial 64-iteration scalar reduction (`impl/src/algebra.rs:10`)**: `reduce(&[u8; 64])` folds 512-bit SHA-512 outputs into secp256k1 scalars via a 64-step loop `acc = acc * 256 + byte`, executing 64 full Montgomery scalar multiplications per hash instead of one 512-bit Barrett/Montgomery wide reduction.
4. **Unbatched Jacobian-to-affine inversions (`impl/src/signing.rs:78-81`)**: Point coordinates are converted to affine individually (`to_encoded_point`), paying a `~10–15 µs` field inversion per ticket instead of one shared Montgomery batch inversion.

### 2.2 Split-Line Dealing End-to-End Latency Profile (`DESIGN.md` §11.2 — Estimates)

For a single `K = 8, L = 2` spend today, latency is dominated by sequential consensus barriers, not node algebra:

| Phase | Non-TEE Path (*estimate*) | TEE v1 Path (*estimate*) | Bottleneck Cause |
| :--- | ---: | ---: | :--- |
| 1. Client `authorize` proof | `8,000–16,000 ms` | `~1,000 ms` (`ic`/`tkc` proof) | `2^18` SHA-256 STARK + `2^20..2^21` BLS12-381 FRI-verifier wrap |
| 2. Midnight finality (`F_M`) | `F_M` (serial before post) | `F_M` (serial before post) | Wallet waits for `auth_ref` before posting envelope to Fenrir board |
| 3. `ORDERED` + `ACK` + `OPENED` | `3,000 ms` (`3` blocks @ 1 s) | `3,020 ms` (`3` blocks + `20 ms` witness) | Separate BFT blocks for `ORDERED`, `κ_0` `ACK`, and `body_0` `OPENED` |
| 4. `ADMIT` + `ANCHOR` | `2,000 ms` (`2` blocks @ 1 s) | `2,040 ms` (`2` blocks + `40 ms` witness) | Separate BFT block to fix host-chain fee `OBS` after `ADMIT` |
| 5. Node algebra + Combine | `~15 ms` | `~15 ms` | On-path dealing/ticket checks + eager `t`-partial combiner check |
| **Post-to-broadcast total** | **`F_M + 5.02 s`** | **`F_M + 5.08 s`** | **5 sequential BFT board blocks stacked in series with `F_M`** |
| **Click-to-broadcast total** | **`F_M + 13–21 s`** | **`F_M + 6.1 s`** | Client proof + serial `F_M` + 5 board blocks |

### 2.3 Per-Node CPU Profile (`K = 8, L = 2`, `n = 9, t = 7` — Estimates + Omitted Costs)

`DESIGN.md` §11.3 budgets `160–220` scalar multiplications (`8–11 ms` at `50 µs`/mul) on the critical path, but **omits two mandatory on-path costs** (`§5.6(5)` combiner partial checks, which *every* TEE node executes, and board/witness Ed25519 signature checks) while deferring the largest sustained CPU cost of all (epoch slot replenishment):

| Component (`n = 9, t = 7`, `K = 8, L = 2`) | Unbatched Muls | `DESIGN.md` §11.3 Batched | Time @ `50 µs` (*est.*) | Time @ `32.5 µs` (`k256` *rate*) | Share of Sustained CPU |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **On-path 1**: Outer `κ_0` (`DH` + degree-6 eval + `π`) | `17` | `17` (*§11.3 counts 8, omits π*) | `0.85 ms` | `0.55 ms` | `0.7%` |
| **On-path 2**: `16` inner dealings (`OPENED`) | `128` | `~70` | `3.50–6.40 ms` | `2.28–4.16 ms` | `4.5%` |
| **On-path 3**: `16` ticket `R_m = R_{u,m} + D_ℓ + ρ_m E_ℓ` | `16` (*§11.3 budgets 32*) | `16` + `16` affine invs (`~24` eq) | `1.20–1.60 ms` | `0.78–1.04 ms` | `1.1%` |
| **On-path 4**: `16` TEE §4.7(4) `S_u` algebra checks | `48` (`0` non-TEE) | `48` (`0` non-TEE) | `2.40 ms` | `1.56 ms` | `2.0%` |
| **On-path 5 (omitted in §11.3)**: Combiner §5.6(5) (`L·t·3 + 2`) | `44` | `44` (run on **every TEE node**) | `2.20 ms` | `1.43 ms` | `1.8%` |
| **On-path 6 (omitted in §11.3)**: `~49` board/QC/witness Ed25519 sigs | `~53` eq | `~53` eq (`verify_batch` off) | `2.65 ms` | `2.65 ms` (`54 µs/sig`) | `2.2%` |
| **On-path TEE node subtotal** | **`~314` eq** | **`~256` eq** | **`12.8–15.7 ms`** | **`9.25–11.4 ms`** | **`~12%–19%`** |
| **Off-path (sustained wall)**: `16` burned Schnorr pool slots (`16 × 137`) | **`2,192`** | **`~1,100`** | **`55.0–109.6 ms`** | **`35.8–71.2 ms`** | **`81%–88%`** |
| **Total sustained TEE node CPU per spend** | **`~2,506` eq** | **`~1,356` eq** | **`67.8–125.3 ms`** | **`45.0–82.6 ms`** | **`100%`** |

**Position**: Speeding up on-path dealing verification alone leaves sustained throughput capped at **`~12–22 req/s/core`**, because every `K = 8, L = 2` spend permanently burns `16` Schnorr committee slots (§4.5) costing `55–110 ms` (`n = 9`) or `312 ms` (`n = 17`) to replenish. Both the `5`-block latency pipeline and the `2,192`-mul slot-pool wall must be eliminated together.

---

## 3. Ranked Optimizations

Optimizations are ordered by combined impact on end-to-end latency and sustained committee throughput.

---

### 3.1 Optimization 1: Two-Block Board Pipeline, Overlapped Midnight Finality `F_M`, Sub-Second Event-Driven BFT, and Piggybacked Group-Committed TEE Peer Witnessing

* **Mechanism**:
  1. **Overlap `F_M` with Fenrir Block 1**: Because `auth_ref = H(authorize_tx)` is deterministic before Midnight confirms it and the MEGa header `hd` already excludes `auth_ref` (`DESIGN.md` §4.6: `hd = ("SL1", B, X_id, eid, H(capsule_1..K))`), the wallet submits `authorize` to Midnight and posts the padded envelope `(eid, auth_ref, κ_0, capsules)` to the Fenrir board **simultaneously**. Nodes sequence the envelope in **Block 1 (`ORDERED`)**, release `κ_0` shares, open `body_0`, and run all §4.7 algebraic checks **concurrently with `F_M`**. Nodes gate *only* their `ADMIT` vote (and any inner-share / partial release) on observing `auth_ref` finalized and unrevoked on Midnight.
  2. **Eliminate the `ACK` block (off-board happy-path `κ_0` reconstruction)**: Block 1's BFT quorum certificate (`ORDERED` QC) already fixes the slot and satisfies `C8`. Immediately upon verifying Block 1's QC and its own `κ_0` share, node `i` multicasts `(eid, i, κ_{0,i})` directly over attested peer links (`~20 ms`). Every node interpolates `κ_0` from the first `t` valid peer shares (`s·G == Y_{0,i}`) with zero board block. Only if a node detects a bad `κ_0` share does it post `COMPLAINT(eid, 0, i, K_i, π_DLEQ)` to the board.
  3. **Fuse `OPENED + ADMIT + ANCHOR` into Block 2**: Because `κ_0` is pinned by `Com(κ_0)` in the ordered envelope and `body_0` is authenticated AEAD under `κ_0` with AD `hd` (`§5.2` step 4), all honest nodes open the identical `body_0`. Validators attach their latest signed host-chain fee observations (`OBS`) as BFT vote extensions on *every* block header. Once `body_0` passes §4.7 and `auth_ref` is final on Midnight, each node casts one vote `ADMIT(eid, H(header))` into **Block 2**. Block 2's QC simultaneously commits `OPENED`, `ADMIT` (`>= q` matching `H(header)`), and `Anchor(H_block2)` from the block's embedded `OBS` median — fixing `j_1` with zero extra `ANCHOR` block.
  4. **Piggyback and group-commit TEE peer witnesses (`§7.7`)**: Nodes attach `open(node, eid)` witness records to their Block 1 `κ_{0,i}` peer messages and attach deterministic `release(node, eid, g=1) -> (j_1, ℓ, H(tk))` witness proposals to Block 2 `ADMIT` votes. Each peer batches all witness entries for all `B` envelopes in the block into **one sequential `dm-integrity` Tier 0 log append + one `fdatasync` per block** (`~1–2 ms` NVMe), returning a batch-signed `WITNESS_ACK`. Crucially, a node still waits for **`w = n - 1 - f` distinct peer `WITNESS_ACK`s** (never conflating `q` QC voters with `w` peers; see §4.3) before emitting `(s_{u,j_1,i}, s_{f,i})` over peer channels (`~10 ms`).
  5. **Event-driven sub-second BFT cadence**: Replace fixed 1 s empty/sleep block timers with demand-driven HotStuff/Simplex block production (`350–400 ms` target under load, instant trigger when mempool `>= 1` envelope).

* **Estimated gain and derivation**:
  * Board commits per spend drop from **`5` (`ORDERED`, `ACK`, `OPENED`, `ADMIT`, `ANCHOR`) to `2` (`Block 1: ORDERED`, `Block 2: ADMIT+ANCHOR`)** — a **2.5× increase in BFT board request capacity** and **60% reduction in consensus state churn**.
  * Post-to-broadcast latency drops from `F_M + 5.07 s` to `max(T_blk + 20 ms, F_M) + T_blk + 30 ms`:
    * At `T_blk = 1.0 s` and `F_M <= 1.0 s`: **`2.05 s` total** (vs `6.07 s`, **3.0× faster**).
    * At `T_blk = 400 ms` and `F_M <= 400 ms` (or TEE v1 without external `F_M` bottleneck): **`0.85 s` post-to-broadcast** (**6.0× faster**).
    * Even when `F_M = 6 s` (slow external settlement), `1.02 s` of Fenrir Block 1 + `κ_0` open + algebra is hidden under `F_M`, cutting post-`F_M` wait from `5.07 s` to **`1.03 s` (4.9× faster after Midnight finality)**.
  * TEE Tier 0 `fdatasync` calls per node drop from `2n = 18` (`n = 9`) or `34` (`n = 17`) per request to **`1` per block**: at `B = 16` requests/block, `18 × 16 = 288` disk flushes collapse to `1` (**288× reduction**, removing NVMe IOPS saturation).

* **Security argument**:
  * **`C8` (pre-ordering confidentiality & adaptive MEGa security)**: No node sends `κ_{0,i}` until Block 1's BFT QC (`ORDERED`) is verified. Pre-ordering adversaries see the exact same ciphertext distribution as in `DESIGN.md` §5.2.
  * **`C6`, `C7` (policy gating & revocation)**: Opening `κ_0` during `F_M` reveals `body_0` only to the committee (which already occurs before `ADMIT` in `DESIGN.md` §5.2 step 4), while inner dealings `(s_{u,v,j}, s_f)` remain sealed at threshold `t = n - f` until Block 2 `ADMIT` confirms `auth_ref` is finalized and unrevoked on Midnight (`H_M` embedded in Block 2). If `auth_ref` fails or expires, inner shares are never released (`C9`, `C10` intact: `t - f = 5 > f = 2` honest non-TEE nodes, or TEE enclaves gated on `ADMIT`, refuse release).
  * **`C13` (monotone fee selection)**: Embedding `OBS` in Block 2 fixes `Anchor(H_admit)` deterministically at the `ADMIT` height; honest `OBS` monotonicity across blocks is unchanged.
  * **`§7.7` (TEE rollback safety)**: Requiring `w = n - 1 - f` *distinct* peer `WITNESS_ACK`s (`w = 6` at `n = 9`, `w = 11` at `n = 17`) on the group-committed batch before emitting any secret preserves `2w - (n - 1) = n - 1 - 2f` (`4` at `n = 9`, `6` at `n = 17`) rollback tolerance identically. Group-committing adds monotonicity across the batch without weakening durability.

* **Implementation cost**: Medium (`~650` LoC in consensus state machine + peer witness batcher: split `Ordered` -> peer `KappaShare` handler, add `OBS` vote extension to BFT proposal/vote, add group-commit `fdatasync` ring buffer in enclave Tier 0 store).
* **Sources**: `DESIGN.md` §4.6, §5.2, §5.5, §7.7, §11.2; `VERITEE-MODEL.md` §3, §5.

---

### 3.2 Optimization 2: Lazy Per-Node Slot Commitments (`D_{ℓ,j}, E_{ℓ,j}`) + Batched Epoch Schnorr Slot Pool Verification

* **Mechanism**:
  1. **Delete eager `D_{ℓ,j}, E_{ℓ,j}` computation**: At epoch start, nodes currently compute per-signer verification shares `(D_{ℓ,j}, E_{ℓ,j})` for all `j ∈ 1..n` on every slot (`2n` degree-`t-1` commitment evaluations per slot). Yet in a `K = 8, L = 2` spend, **`14` of `16` slots are permanently burned unselected** (§4.5), and on the `2` selected slots optimistic combining (§3.7) checks `[s]G == R + cQ` directly without touching `(D_{ℓ,j}, E_{ℓ,j})` unless a partial fails! Store only the summed polynomial commitment vectors `(Com(D_ℓ), Com(E_ℓ))` (`2t` points) and compute `(D_{ℓ,j}, E_{ℓ,j})` **lazily on blame fallback only**.
  2. **Batch epoch slot dealings in chunks of `B_pool = 1,024` slots**: Each of the `t` dealers in `Q` generates **one** fresh MEGa ephemeral key `E_d` and **one** key-reuse DLEQ proof `π_d` (`131 B`) covering all `2 · B_pool = 2,048` polynomials `(d_{d,ℓ}, e_{d,ℓ})`, using seeded shares (§3.6) for `i = 1..t-1`.
  3. **Addition-chain Horner + single Pippenger RLC + batch affine normalization**: Each node `i`:
     * Computes `K_{d,i} = sk_i · E_d` **once per dealer** (`t` muls total across `1,024` slots = `< 0.01` mul/slot).
     * Evaluates each polynomial's commitment vector at small integer `i ∈ 1..n` using public addition chains (§3.4: `3.1` group ops/step avg at `n = 9`; `3.9` at `n = 17`), then runs **one** `2 · t · B_pool`-point Pippenger MSM (`14,336` points at `n = 9`; `24,576` points at `n = 17`) with 128-bit random weights (`ecmult_multi_var` Pippenger costs `~0.10` var-base mul-eq per 128-bit scalar at `N >= 10^4`).
     * Sums `C_{ℓ,u} = sum_{d ∈ Q} C_{d,ℓ,u}` (`2t(t - 1)` point adds/slot) and normalizes all `2,048` public nonce pairs `(D_ℓ, E_ℓ) = (C_{ℓ,0}^{(d)}, C_{ℓ,0}^{(e)})` to affine via **one** Montgomery simultaneous field inversion (`6` field muls/slot).

* **Estimated gain and derivation**:
  * **At `n = 9, t = 7`** (per slot, amortized over `B_pool = 1,024`):
    * `7` DH + `7` proofs / `1,024` = `0.024` mul-eq.
    * `14` degree-6 addition-chain evaluations (`14 × 6 × 3.1 = 260` group ops @ `1/310` mul-eq) = `0.84` mul-eq.
    * Coefficient summation (`14 × 6 = 84` point adds) = `0.27` mul-eq.
    * Pippenger RLC (`14` polynomials × `0.10` mul-eq/point) = `1.40` mul-eq.
    * Batch affine normalization = `0.02` mul-eq.
    * **Total**: **`2.55` mul-eq/slot (`43.4 µs/slot` in `libsecp256k1`)** vs `137` muls/slot (`6,850 µs` @ `50 µs`). Per `16`-slot spend: **`40.8` mul-eq (`0.69 ms`)** vs `2,192` muls (`109.6 ms` unbatched, `~55 ms` batched in §11.3) — **54× fewer mul-eq and 80×–159× faster wall-clock**.
  * **At `n = 17, t = 12`** (per slot, amortized over `B_pool = 1,024`):
    * `0.04` (DH/proofs) + `3.32` (`24 × 11 × 3.9 = 1,030` group ops) + `0.85` (`264` point adds) + `2.28` (`24 × 0.095` Pippenger) + `0.02` (affine) = **`6.51` mul-eq/slot (`111 µs/slot`)**. Per `16`-slot spend: **`104.2` mul-eq (`1.77 ms`)** vs `6,240` muls (`312 ms`) — **60× fewer mul-eq and 176× faster wall-clock**.

* **Security argument**:
  * Every slot `ℓ` still sums **`t` independent dealer polynomials** (`|Q| >= t`), so against `t - 1` corrupt nodes (`C5`), at least one honest dealer contributes uniform independent `(d_{h,ℓ}, e_{h,ℓ})` unknown to the adversary. No Vandermonde/hyper-invertible extraction is used (see §4.2).
  * Sharing `E_d` across `B_pool` polynomials of a single dealer uses distinct `slot` tags `(d, epoch, batch_id, ℓ, kind)` in `Hq_enc`, matching the multi-slot MEGa proof of `PROOFS.md` Theorem C. If the Pippenger RLC fails, binary-splitting across dealers `d ∈ Q` and slots isolates the exact invalid `(d, ℓ)` in `ceil(log_2(14,336)) = 14` fast checks for `COMPLAINT`.
  * `C12` (at most one `(v, j)` bound per slot `ℓ`) is untouched.

* **Implementation cost**: Low–Medium (`~350` LoC in `impl/src/reshare.rs` / epoch pool module: chunked slot dealing struct, Pippenger RLC verifier with binary-search blame fallback, lazy `evaluate_commitment(ℓ, j)` helper).
* **Sources**: `DESIGN.md` §3.5, §4.5, §11.3; `PROOFS.md` Theorem C; `bitcoin-core/secp256k1` `src/ecmult_impl.h` (`ECMULT_PIPPENGER_THRESHOLD = 88`).

---

### 3.3 Optimization 3: Eliminate the Ticket STARK Wrap — Single-Circuit Native `midnight-zk` `Table16` PLONK (`k = 18`) + Poseidon2 Internal Hashes + BIP341 Midstate Hoisting + `tkc` Nonce Binding

* **Mechanism**:
  1. **Resolve the non-native EC mul trap via `tkc` nonce binding**: `DESIGN.md` §5.3 item 5 asks the ZK circuit to check `R_m = R_{u,m} + D_ℓ + ρ_m E_ℓ`, while §11.4 budgets "hash-and-predicate only, no curve scalar multiplications inside the proof" — an unaddressed spec contradiction (`16` non-native secp256k1/Curve25519 scalar muls in BLS12-381 `𝔽_r` would add `~400k` rows alone). Fix it cleanly: include `r_repr_m` (`x(R_m)` for BIP340, compressed `R_m` for Ed25519, `r_m = x(R_ℓ) mod n` for ECDSA) as a private field inside each ticket tuple hashed into `tkc`! The circuit hashes `r_repr_m` directly into `BIP0340/challenge` / SHA-512 with **zero non-native curve arithmetic**. At `ADMIT`, every Fenrir node already computes `R_m = R_{u,m} + D_ℓ + ρ_m E_ℓ` natively in `17 µs` (§3.4) and plugs its locally recomputed `r_repr_m` into `tkc` when checking `auth == H_auth(ic, tkc)`. Any false `r_repr_m` in the prover's witness produces a `tkc` mismatch at every honest node and is rejected at `ADMIT`.
  2. **Switch Fenrir-internal hashes (`H_pm`, `Hq_bind`, `ic`, `tkc`, `auth`, policy Merkle tree) from SHA-256/SHA-512 to Poseidon2 over BLS12-381 `𝔽_r`** (`ePrint 2023/323`): Neither Bitcoin, Ethereum, nor Solana ever evaluates `ic`, `tkc`, `auth`, or `H_pm`. Replacing SHA-256 there with width-4 Poseidon2 (`~30` PLONK rows/permutation in `midnight-zk`'s native Poseidon gadget vs `2,099` rows/block for SHA-256) cuts commitment hashing by **~70×**. Host-chain hashes (`TapSighash`, `BIP0340/challenge`, BIP143, Keccak-256, Ed25519 SHA-512) stay untouched, with 64-byte BIP340/BIP341 tagged-hash prefix midstates (`SHA256("TapSighash")||SHA256("TapSighash")`, `SHA256("BIP0340/challenge")||...`) baked in as circuit constants (saving 1 compression per tagged hash).
  3. **Hoist shared BIP341 sighash components (`K = 8, L = 2`)**: In BIP341 (`SIGHASH_DEFAULT`), `sha_prevouts` (`2` blocks), `sha_amounts` (`1` block), `sha_scriptpubkeys` (`2` blocks), and `sha_sequences` (`1` block) depend **only on the `L = 2` inputs**, not on the fee output or input index `v`! Compute them **once per spend (`6` blocks)** instead of `16 × 6 = 96` times. Compute `sha_outputs` (`1` block for 2 P2TR outputs) **once per fee variant `j` (`8` blocks, or `16` for larger output scripts)** instead of `L × K` times. Each `(v, j)` ticket then needs only `3` `TapSighash` blocks (`48` blocks) + `2` `BIP0340/challenge` blocks (`32` blocks). Total SHA-256 compressions for `K = 8, L = 2` drop from **`~240` + `32` SHA-512 down to `6 + 16 + 48 + 32 = 102` SHA-256 compressions** (`0` SHA-512)!
  4. **Prove directly in `midnight-zk`'s native BLS12-381 Halo2-KZG (`Table16` lookup, `k = 18`) — delete the external STARK and `2^20..2^21` FRI wrap**: Using Halo2's 16-bit spread lookup chip (`2,099` active rows per SHA-256 block + one shared `2^16 = 65,536`-row spread table reused across SHA-256, `K = 1` Ed25519 SHA-512, and `K = 1` EVM Keccak-256):
     * `102` SHA-256 blocks × `2,099` rows = **`214,098` rows**.
     * Universal cross-suite selector branches (`K = 1` Solana Ed25519 `5` SHA-512 blocks ≈ `18,500` rows reusing the 16-bit spread table; `K = 1` EVM RLP + `3` Keccak-256 permutations ≈ `12,000` rows; Poseidon2 `ic`/`tkc`/`auth`/Merkle + JubJub credential Schnorr + integer value/fee/recipient range checks ≈ `7,000` rows) = **`~37,500` rows**.
     * **Total universal circuit active rows**: **`~251,600 < 2^18 = 262,144` rows (`k = 18`)** (or `k = 19` if `L = 4` inputs are supported in the same universal circuit).
     * Because `midnight-zk` natively verifies `k = 18` BLS12-381 PLONK-KZG proofs, the external `2^18` hash STARK and `2^20..2^21` FRI-verifier wrapper circuit disappear completely.
  5. **Client WebGPU/Metal acceleration & Midnight block proof aggregation (`O12`)**: Run the `2^18` BLS12-381 KZG MSM + NTT on client WebGPU/Metal/CUDA when available, and aggregate per-block `authorize` proofs on Midnight via `midnight-zk`'s `aggregator` crate (amortizing pairing checks across spends). *(Note: Nova/HyperNova IVC folding loses here — folding 16 steps over a pasta/Grumpkin-like cycle requires a BLS12-381 cycle curve not native to `midnight-zk` and pays `>150k` constraints of non-native folding overhead plus a final Spartan/PLONK wrap larger than proving `251.6k` rows directly.)*

* **Estimated gain and derivation**:
  * BLS12-381 outer circuit size drops from **`2^20..2^21` (`1.05M–2.10M` rows) + `2^18` STARK** down to **one `2^18` (`262,144`-row) native circuit** — a **4×–8× reduction in KZG MSM/NTT size** plus total elimination of STARK proving.
  * Client CPU proving drops from **`8–16 s` (`~3 GB` RAM)** to **`1.5–2.5 s` (`~400 MB` RAM)** on an 8-core laptop/phone CPU (**5×–6× faster, 7.5× less memory**), and to **`~0.4–0.6 s`** with client WebGPU/Metal (**16×–30× faster**, matching TEE v1 UX without a user enclave!).

* **Security argument**:
  * **Cross-suite anonymity (`DESIGN.md` §5.3)**: All three suites (`bip340` `K <= 8, L <= 2`, `ecdsa` `K = 1..8`, `ed25519` `K = 1`) execute inside **one fixed `k = 18` universal circuit** with identical Midnight public inputs `(root, nf, auth)` and unused slots padded as dummy entries in `tkc`. Midnight observers learn zero bits about chain, `K`, `L`, or policy profile.
  * **Slot privacy on Midnight (`§4.1`)**: `(D_ℓ, E_ℓ)` and `r_repr_m` appear only inside the Poseidon2 preimage of `tkc`, which is computationally/statistically blinded by a 256-bit salt `r_tkc`; Midnight sees only `(ic, auth)` (`auth = Poseidon2(ic, tkc)`).
  * **`C3`, `C5`, `C6`, `C10`**: Soundness of `r_repr_m` binding follows directly in the ROM/Poseidon2 collision-resistance game: since `ADMIT` recomputes `r_repr_m' = repr(R_{u,m} + D_ℓ + ρ_m E_ℓ)` from the wire ticket and checks `Poseidon2(ic, Poseidon2(..., r_repr_m', ...)) == auth`, binding resistance of `Poseidon2` forces `r_repr_m' == r_repr_m` except with probability `<= Q_H^2 / 2^254`, so the proven host-chain challenge `c_m = H_sig(r_repr_m, Q, tx_j)` is identically bound to the committee's actual signing nonce `R_m`. Poseidons are used strictly for internal commitments over `𝔽_r` (`ePrint 2023/323` standard 128-bit security round numbers `R_F = 8, R_P = 56`).

* **Implementation cost**: High (`~2,200` LoC in `midnight-zk` `zk_stdlib` / Halo2: hoisted BIP341 gadget reusing `Table16` spread table across SHA-256/SHA-512/Keccak, Poseidon2 `ic`/`tkc`/`auth` gadget, node-side Poseidon2 hash crate `zkhash`/`poseidon2` in `impl/src/hash.rs`).
* **Sources**: `DESIGN.md` §4.2, §5.3, §11.4; `midnightntwrk/midnight-zk` (`proofs`, `circuits`, `aggregator`); Halo2 `Table16` SHA-256 specification (`2,099` rows/block + `2^16` table); Grassi, Khovratovich, Schofnegger, *Poseidon2* (`ePrint 2023/323`); Plonky3 & Binius SHA-256 vs Poseidon2 benchmark comparisons.

---

### 3.4 Optimization 4: Small-Integer Addition-Chain Horner + 128-bit RLC + Strauss/Pippenger MSM + Montgomery Batch Inversion Across All On-Path Node Checks

* **Mechanism**:
  1. **Public addition-chain Horner for `Com(p)` evaluation at `i ∈ 1..n`**: Replace `(acc + c) * Scalar::from(node)` (`impl/src/algebra.rs:147`, `ed25519.rs:430`) with a dedicated `mul_small_node(P: ProjectivePoint, i: u8)` using fixed public addition chains (`1`: `0` ops; `2`: `1D`; `3`: `1D+1A`; `4`: `2D`; `5`: `2D+1A`; `6`: `2D+1A`; `7`: `3D+1S` via `8P - P`; `8`: `3D`; `9`: `3D+1A`; for `10..17`, `<= 4D+1A`). Across `i = 1..9`, the average Horner step costs **`3.1` fast point doublings/additions (`~0.17 µs`)** instead of a `32.5 µs` 256-bit scalar multiplication (**190× faster per step**). Across `i = 1..17`, the average step costs **`3.9` group ops (`~0.21 µs`)**.
  2. **128-bit local-CSPRNG Random Linear Combination (RLC) of all `M = 16` inner shares**: After deriving `s_{m,i}` and evaluating `Y_{m,i} = eval(Com(m), i)` via step 1, node `i` samples independent 128-bit weights `α_2..α_16 <- {0,1}^128` from its local CSPRNG (`α_1 = 1`) and verifies a single equation:
     `(\sum_{m=1}^{16} α_m s_{m,i}) · G == Y_{1,i} + \sum_{m=2}^{16} α_m Y_{m,i}`
     using `1` fixed-base `G` mul (`0.3` mul-eq) + `1` 15-point 128-bit Strauss MSM (`~2.5` mul-eq) = **`2.8` mul-eq** (`48 µs`). Across a block of `B >= 6` envelopes (`>= 96` points), merge all inner shares into one Pippenger MSM (`~1.6` mul-eq/envelope). If the RLC fails, bisect the `16` dealings (`4` binary steps) to pinpoint the exact bad `(v, j)` for `COMPLAINT`.
  3. **128-bit RLC of all `16` TEE §4.7(4) `S_u` checks**: In TEE mode, node `i` checks `S_{u,m} - σ_m R_{u,m} == c̃_m A + c_m g_Q t_tap G` for `m = 1..16`. Draw 128-bit local weights `β_1..β_16` (`β_1 = 1`) and check:
     `(S_{u,1} - σ_1 R_{u,1}) + \sum_{m=2}^{16} β_m (S_{u,m} - σ_m R_{u,m}) == (\sum_{m=1}^{16} β_m c̃_m) A + (\sum_{m=1}^{16} β_m c_m g_Q t_tap) G`
     This collapses `48` full scalar multiplications into `16` mixed point add/subtractions (`0.05` mul-eq) + `1` 15-point 128-bit Strauss MSM (`2.5` mul-eq) + `1` variable-base mul on `A` (`1.0` mul-eq) + `1` fixed-base mul on `G` (`0.3` mul-eq) = **`3.9` mul-eq (`66 µs`)** — a **12.3× reduction**.
  4. **Exact ticket nonce computation + Montgomery simultaneous batch inversion**: Compute `R_m = (R_{u,m} + D_{\ell_m}) + ρ_m E_{\ell_m}` as `16` GLV scalar multiplications (`ρ_m E_{\ell_m}`) + `32` mixed point additions, then convert all `16` Jacobian `Z_m` coordinates to affine (`x(R_m) = X_m · Z_m^{-2}`) via **one** Montgomery simultaneous field inversion (`1` `𝔽_p` inversion + `3 × 15 = 45` `𝔽_p` muls ≈ `0.4` mul-eq total, vs `16` separate inversions).
  5. **Folded outer `κ_0` share + `π` check**: Combine `κ_{0,i} · G - Y_{0,i} = O`, `z_e G - T_1 - c_e E = O`, and `z_e g' - T_2 - c_e E' = O` with 128-bit local scalars `(1, γ_1, γ_2)` into one Strauss MSM (`~2.5` mul-eq single-request, `~1.2` mul-eq block-batched).

* **Estimated gain and derivation**:
  * **At `n = 9, t = 7` (TEE)**: `3.6` (`κ_0` DH + eval + `π`) + `4.1` (`16` inner evals `1.3` + RLC `2.8`) + `16.0` (ticket `R_m` + batch inv) + `3.9` (TEE §4.7(4) RLC) + `0.1` (`L = 2` partials) = **`27.7` mul-eq** (`23.8` non-TEE), down from `160–220` muls in `DESIGN.md` §11.3 (**5.8×–7.9× algorithmic reduction**).
  * **At `n = 17, t = 12` (TEE)**: `3.7` (`κ_0`) + `5.0` (`16` degree-11 evals `2.2` + RLC `2.8`) + `16.0` (tickets) + `3.9` (TEE §4.7(4)) + `0.1` (partials) = **`28.7` mul-eq** (`24.8` non-TEE), down from `~256–329` muls (**8.9×–11.5× algorithmic reduction**).

* **Security argument**:
  * **Soundness (`C1`–`C10`)**: Over prime-order groups (`N_s` on secp256k1, prime-order subgroup `ℓ > 2^252` on Edwards25519 after single-pass subgroup validation in §3.5), for any nonzero error vector `(Δ_1..Δ_M) != 0`, `\sum α_m Δ_m = O` defines a hyperplane in `(ℤ_q)^M` hit by uniform post-message local randomness `α_2..α_M ∈ {0,1}^128` with probability `<= 2^{-128}` (Schwartz–Zippel / Bellare–Garay–Rabin small-exponent test). Because `α_m, β_m` are drawn locally inside node `i` *after* the wire bytes are fixed and are never revealed externally, an adaptive adversary gets zero oracle feedback.
  * **Side-channel safety**: `mul_small_node` operates strictly on **public** polynomial commitment points `C_{m,u}` and **public** node ID `i ∈ 1..n`. Secret scalars (`sk_i`, `s_{m,i}`) only ever enter `sk_i · E` and `(Σ α_m s_{m,i}) · G`, both executed via constant-time scalar multiplication.

* **Implementation cost**: Medium (`~550` LoC across `impl/src/algebra.rs`, `impl/src/ed25519.rs`, `impl/src/signing.rs`, `impl/src/reshare.rs`).
* **Sources**: `impl/src/algebra.rs:147`; `impl/src/ed25519.rs:430`; `impl/src/signing.rs:78-81`; `bitcoin-core/secp256k1` `secp256k1_ecmult_multi_var`.

---

### 3.5 Optimization 5: Curve Backend Upgrade (`libsecp256k1` FFI + Static Tables, AVX2 `curve25519-dalek`), Single-Pass `PrimeOrderPoint` Decode, and Wide 512-bit Scalar Reduction

* **Mechanism**:
  1. **Replace pure-Rust `k256` with `secp256k1` (`bitcoin-core/secp256k1` C FFI)**: `libsecp256k1` provides hand-tuned 64-bit assembly field arithmetic, GLV endomorphism splitting (`secp256k1_scalar_split_lambda` into two 128-bit half-scalars using `λP = (βx, y)`), `secp256k1_ecmult_gen` constant-time precomputed Comb tables for `G`, and `secp256k1_ecmult_multi_var` (Strauss wNAF for `< 88` points, Pippenger bucket MSM for `>= 88` points). In addition, build cached wNAF/Comb lookup tables at epoch start for epoch-static public keys (`X_f`, `PK_1..PK_n`) and per-address `A`, turning `K_i = r · PK_i` (wallet side) and `c̃ · A` (node side) into `~5 µs` fixed-base lookups.
  2. **Enable AVX2 / IFMA SIMD backend on `curve25519-dalek` (`ed25519`)**: Compile node binaries with `RUSTFLAGS="-C target-cpu=x86-64-v3"` (or `znver4` on AMD EPYC Genoa/Turin SEV-SNP), activating `curve25519-dalek`'s parallel 4-way AVX2 `EdwardsPoint` backend (`22%–35%` faster single mul and Straus/Pippenger `vartime_multiscalar_mul`).
  3. **Single-pass `PrimeOrderPoint` newtype for Suite 3 (`impl/src/ed25519.rs`)**: Wrap wire-decoded Edwards25519 points in `struct PrimeOrderPoint { point: EdwardsPoint, wire_bytes: [u8; 32] }`. Perform `decompress()` + `is_torsion_free()` **exactly once** when parsing untrusted wire bytes in `Deal::read`. Hash `wire_bytes` directly into Fiat–Shamir transcripts without re-compressing or re-multiplying by `ℓ` (`ed25519.rs:512, 589`). Further replace `[ℓ]P == O` inside `is_torsion_free()` with `curve25519-dalek`'s dedicated cofactor-check / Straus batching where available, never skipping per-point validation (see §4.7).
  4. **Replace bytewise `reduce()` (`impl/src/algebra.rs:10`) with wide 512-bit reduction**: Fold 64-byte SHA-512 outputs as `L_256 + 2^256 · H_256 mod N_s` using `2^256 mod N_s = 0x14551231950b75fc4402da1732fc9bebf` (one 256×129-bit mul + add, `< 40 ns` vs `~3 µs` for 64 Montgomery muls).
  5. **Keep committee enclaves strictly CPU-only (no GPU inside SEV-SNP)**: Adding discrete GPUs (H100 Confidential Computing) to Fenrir nodes would drag PCIe/SPDM/NVIDIA driver firmware into the `VERITEE-MODEL.md` TCB for zero latency gain (`0.68 ms` CPU is already `< 0.1%` of BFT block time). Use GPUs **only on untrusted user/companion devices** for client ZK proving (§3.3).

* **Estimated gain and derivation**:
  * Variable-base secp256k1 mul drops from `50 µs` (planning estimate) / `32.5 µs` (*measured* `k256`) to **`~17 µs`**, and fixed-base `G` mul drops to **`~5 µs`** (**1.9×–2.9× raw backend speedup** on top of §3.4's `6×–8×` mul-count reduction).
  * Suite-3 (`ed25519`) `sealed-k8` `Step A` drops from `7,554.3 µs` (*measured*) to **`~800 µs` (9.4× faster)** simply by eliminating `112` redundant `[ℓ]P` scalar multiplications and `112` field inversions, plus AVX2 acceleration.

* **Security argument**:
  * `bitcoin-core/secp256k1` is the most heavily audited cryptographic C library in production (used in Bitcoin Core consensus and `libsecp256k1-zkp`), with constant-time guarantees on `ecmult_gen` and `ecdh`. Variable-time `ecmult_multi_var` is invoked exclusively on public commitments, public keys, and public random linear combination weights.
  * `PrimeOrderPoint`'s private constructor enforces `C20` (`Theorem E(d)`): no external byte slice can become a `PrimeOrderPoint` without passing canonical encoding + `is_torsion_free()`, and prime-order subgroup closure guarantees all subsequent point sums/multiples remain torsion-free.

* **Implementation cost**: Low–Medium (`~400` LoC adapter swapping `k256` primitives in `impl/src/algebra.rs` to `secp256k1` + `secp256k1-sys` `ecmult_multi_var` wrapper, plus `PrimeOrderPoint` refactor in `impl/src/ed25519.rs`).
* **Sources**: `impl/Cargo.toml`; `impl/src/algebra.rs:10`; `impl/src/ed25519.rs:37-53, 512, 589`; `bitcoin-core/secp256k1`; `curve25519-dalek` AVX2 backend documentation.

---

### 3.6 Optimization 6: Seeded Shamir Shares (`f + 1` Ciphertexts), Trimmed Outer `κ_0` MEGa Proof (`131 B`), Shared-`E` Complaint Aggregation, and Adaptive `K` Grid

* **Mechanism**:
  1. **Seeded Shamir evaluation (`f + 1` ciphertexts instead of `n`)**: Under MEGa encryption, the dealer already derives `n` pseudorandom pads `pad_i = Hq_enc(E, i, PK_i, r · PK_i, slot)` for `i = 1..n`. Instead of picking random polynomial coefficients `a_1..a_{t-1}` and transmitting `n` scalar ciphertexts `ct_i = p(i) + pad_i`, define the shares of nodes `1..t-1` **implicitly as the pads themselves**:
     `p(i) := pad_i = Hq_enc(E, i, PK_i, r · PK_i, slot)` for `i = 1..t-1`.
     Together with the target secret `p(0) = s`, the `t` points `{(0, s), (1, pad_1), ..., (t-1, pad_{t-1})}` uniquely determine the degree-`(t - 1)` polynomial `p(X)`! Using precomputed constant Lagrange basis matrices (`7 × 7` scalars at `n = 9`, `12 × 12` at `n = 17`), the dealer interpolates the monomial coefficients `(a_0..a_{t-1})` (`Com(p) = a_u · G`) and evaluates `p(t)..p(n)` in `< 3 µs` of pure scalar field arithmetic, transmitting ciphertexts `ct_i = p(i) + pad_i mod q` **only for `i = t..n` (`n - t + 1 = f + 1` scalars: `3` at `n = 9`, `6` at `n = 17`)**! Nodes `1..t-1` set `s_i = pad_i`; nodes `t..n` set `s_i = ct_i - pad_i`.
     *Crucial subtle requirement*: `Hq_enc` takes `(E, i, PK_i, K_i, slot)` — **omitting `hd`** so `pad_1..pad_{t-1}` are well-defined *before* `Com(p)` (which is inside `body_0`, whereas `hd` only covers outer capsules anyway, and in outer `κ_0` `Com(κ_0)` is hashed into `π`). Header binding `(hd, H_ct(ct), E)` stays inside `HG_eph` of the outer proof `π`!
  2. **Trim `(T_a, z_a)` (`65 B`) from the outer `κ_0` MEGa proof `π` (`196 B -> 131 B`)**: `DESIGN.md` §4.6 attaches a `196 B` combined proof `(E', T_1, T_2, T_a, z_e, z_a)` (`4 × 33 + 2 × 32 = 196 B`) to `κ_0`. In base `SCHEME.md` §3.4, `(T_a, z_a)` proves Schnorr knowledge of the owner's root half `x_U` (`A = x_U · G`). In split-line dealing, `K_0 = κ_0 · G` is an anonymous per-envelope key (`C_{0,0}`), authorization is proven by `auth_ref` + the inner dealings inside `body_0`, and `κ_0 · G == C_{0,0}` is already verified by `t` honest share checks! Dropping `(T_a, z_a)` leaves `(E', T_1, T_2, z_e)` (`3 × 33 + 32 = 131 B`), saving `65 B` and `2` scalar muls per envelope.
  3. **Shared-`E` single-DLEQ complaint**: Because outer `κ_0` and all `16` inner dealings share the same ephemeral key `E`, any inner complaint on `(v, j)` publishes **one** `(K_i, π_DLEQ)` (`97 B`) plus the 2-byte index `(v, j)`, and for `i ∈ 1..t-1` verifiers simply compute `s_i = Hq_enc(E, i, PK_i, K_i, slot)` without needing a ciphertext `ct_i`.
  4. **Adaptive fee-step count `K` (`K = 4..8`) inside the fixed 16 KiB frame**: During calm mempool regimes, wallets generate `K = 4` fee variants (`8` inner dealings instead of `16`), padding `tkc` to `16` entries with dummy self-consistent tuples and zero-padding the envelope to `16,384 B` — **cutting committee slot burn in half (`8` slots vs `16`)** with zero wire-size or Midnight leakage.

* **Estimated gain and derivation**:
  * **Inner dealing size**:
    * `n = 9, t = 7, f = 2`: `7 × 33 + 3 × 32 = 327 B` (down from `519 B`, **37.0% smaller**).
    * `n = 17, t = 12, f = 5`: `12 × 33 + 6 × 32 = 588 B` (down from `940 B`, **37.4% smaller**).
  * **Outer dealing `κ_0` size**: `491 B` at `n = 9` (was `748 B`); `752 B` at `n = 17` (was `1,169 B`).
  * **Elimination of the 64 KiB frame (`O7`) at `n = 17` for `K = 8, L = 2`**: Baseline `n = 17, K = 8, L = 2` payload is `288` (hdr) + `1,169` (`κ_0`) + `15,040` (`16 × 940` inner) + `1,282` (tickets + TEE witness) + `4,160` (`8` capsules) = `21,939 B`, overflowing `16,384 B` into the **`65,536 B` (`64 KiB`)** frame (`DESIGN.md` §11.1). With `Opt 6`, `417 + 16 × 352 = 6,049 B` are saved: **`21,939 - 6,049 = 15,890 B <= 16,384 B`**! Full 2-input, 8-step Taproot spends at `n = 17` now fit inside the **16 KiB frame** (**4.0× smaller wire & storage footprint at `n = 17`** and no `16 KiB` vs `64 KiB` anonymity split!).
  * **Schnorr slot board footprint**: Drops from `7.3 KB` to **`4.5 KB`** (`n = 9`) and from `22.6 KB` to **`13.8 KB`** (`n = 17`).

* **Security argument**:
  * **Distribution equivalence**: Over an honest dealer (`r <- ℤ_q` fresh, `Hq_enc` modeled as RO), `(pad_1..pad_{t-1})` are independent uniform scalars in `ℤ_q`. Since evaluation at `{0, 1, ..., t-1}` is a bijection onto polynomials of degree `<= t - 1`, `p(X)` is identically distributed to sampling `(a_1..a_{t-1}) <- (ℤ_q)^{t-1}` around `a_0 = s`. Any `< t` corrupt nodes (`|C| <= t - 1`) learn `|C|` values of `p(i)`, leaving `p(0) = s` information-theoretically uniform once unqueried `pad_h` (`h ∉ C`) are replaced by uniform random scalars in the Gap-CDH game.
  * **Required proof update (5-line corollary to `PROOFS.md` Theorem C)**: Removing `hd` from `Hq_enc(E, i, PK_i, K_i, slot)` changes only Game 0's pre-query collision bound in `PROOFS.md` §4 (`Theorem C`): before `E = r · G` is sampled, an RO adversary with `Q_enc` queries hits `E` in `(E, ...)` with probability `<= Q_enc / q` per dealing (`Q_enc · Q_msg / q < 2^{-190}`), rather than `Q_enc · Q_msg / 2^256`. Because `(hd, H_ct(ct), E)` remains hashed into `g' = HG_eph(hd, H_ct(ct), E)` inside `π`, `Reuse` extraction (`z_e` soundness) and adaptive complaint-oracle simulation (`K_i = r · PK_i` independent of `hd`) hold **verbatim**.
  * **Complaint verifiability (`C8`, `C11`)**: For `i ∈ 1..t-1`, `K_i` + `π_DLEQ` lets every node compute `s_i = Hq_enc(E, i, PK_i, K_i, slot)` and check `s_i · G == eval(Com(p), i)` identically to `i >= t`.

* **Implementation cost**: Low (`~220` LoC in `impl/src/reshare.rs` and `impl/src/ed25519.rs`: constant `(t × t)` Vandermonde/Lagrange inverse table at epoch setup, `f + 1` ciphertext serializer, `131 B` outer proof).
* **Sources**: `DESIGN.md` §4.6, §11.1; `SCHEME.md` §3.4; `PROOFS.md` §4 (Theorem C); Groth & Shoup `ePrint 2022/506` (`notes-2022-506.md`).

---

### 3.7 Optimization 7: Optimistic Combiner Interpolation with `S_u` Pre-Check Before Capsule Decryption

* **Mechanism**:
  1. Replace `DESIGN.md` §5.6(5)'s eager per-partial verification (`L · t` runs of `verify_partial` = `2 × 7 × 3 = 42` scalar muls at `n = 9`, `2 × 12 × 3 = 72` muls at `n = 17` on **every TEE node**!) with optimistic scalar Lagrange interpolation:
     * Cache the `t` scalar Lagrange weights `{λ_i}_{i ∈ S}` for the active responder subset `S` (`|S| = t`, `< 1 µs` via Montgomery batch scalar inversion on cache miss; `0` inversions on cache hit across consecutive spends).
     * Interpolate `s_u = sum_{i ∈ S} λ_i s_{u,j_g,i}` and `s_f = sum_{i ∈ S} λ_i s_{f,i}` (`2t` scalar muls ≈ `1 µs`).
  2. **Mandatory `S_u` pre-check before `KDF(s_u)`**: Before decrypting `capsule_{j_g}`, verify **one** fixed-base equation per input: `s_u · G == S_{u,j_g}` (`0.3` mul-eq = `5 µs` on Schnorr/Ed25519; `s_u · R_ℓ == h W_u + r M_u` = `2.2` mul-eq on ECDSA). Only after `s_u · G == S_{u,j_g}` passes does the combiner derive `KDF(s_u)` and AEAD-open `capsule_{j_g}`!
  3. Set `s = s_u + s_f` and verify the single host-chain signature `[s]G == R + cQ` (`1.2` mul-eq per input). Run individual `verify_partial` across `i ∈ S` **only on the rare Byzantine fallback** where step 2 or step 3 fails.

* **Estimated gain and derivation**:
  * For `L = 2` inputs: `2 × 0.3` (`S_u` pre-check) + `2 × 1.2` (final sig check) = **`3.0` mul-eq (`53 µs`)** at `n = 9` (`3.1` mul-eq = `55 µs` at `n = 17`), down from **`44` muls (`2.20 ms` @ `50 µs`) at `n = 9`** and **`74` muls (`3.70 ms`) at `n = 17`** — a **14.7× (`n = 9`) to 23.9× (`n = 17`) combiner speedup** on every TEE node.

* **Security argument**:
  * **Exact blame attribution (`§5.6(5)`, `C11`, `C15`)**: Without step 2's `s_u · G == S_{u,j_g}` pre-check, a single Byzantine node sending a corrupted `s_{u,j_g,i}` would produce a garbage `s_u`, causing `capsule_{j_g}` AEAD decryption to fail and falsely blaming the wallet (`ABORTED`)! Checking `s_u · G == S_{u,j_g}` first guarantees that: (a) if a node corrupted `s_{u,j_g,i}`, `s_u · G != S_{u,j_g}` triggers per-share `s_{u,j_g,i} · G == eval(Com(u), i)` fallback, convicts the exact Byzantine node `i`, and swaps in a `t + 1`-th share; (b) if `s_u · G == S_{u,j_g}` holds, `s_u` is uniquely bound to `S_{u,j_g}` (discrete-log uniqueness), so any subsequent capsule AEAD failure or `[s]G != R + cQ` failure (after `s_f` fallback check) is 100% attributable to a malformed wallet envelope.

* **Implementation cost**: Trivial (`~90` LoC in `impl/src/signing.rs` and `impl/src/ed25519.rs`; `SCHEME.md` §3.8 already uses this pattern for base signing).
* **Sources**: `DESIGN.md` §5.6(5); `SCHEME.md` §3.8; `impl/src/signing.rs:195-240`.

---

### 3.8 Optimization 8: Batch Board-Post Signature Verification (`ed25519_dalek::verify_batch`) and `blst` BLS12-381 Aggregate QCs/Checkpoints

* **Mechanism**:
  1. **BLS12-381 aggregate signatures (`supranational/blst`, MinPk: `48 B` pk, `96 B` sig + `n`-bit signer bitmap) for BFT QCs, `ADMIT` vote extensions, Midnight `Checkpoints`, and `settle(auth, FINAL)`**: Instead of verifying `q` individual Ed25519/ECDSA signatures per QC (`6` at `n = 9`, `12` at `n = 17`) on every block and inside Midnight's `settle` contract, aggregate all voter signatures on the block digest into one `96 B` G2 point verified with `blst` `fast_aggregate_verify` (`2` pairings ≈ `1.3 ms` per block, amortized across all `B` envelopes in the block). Register each node's BLS key in the Epoch Key Registry / TEE boot attestation with a Proof-of-Possession (PoP) signature on G2.
  2. **Enable `ed25519-dalek = { version = "2.2", features = ["batch"] }`** for individual peer messages (`w` `WITNESS_ACK`s, `OBS` reports, complaints), verifying all signatures received in a block window in a single `ed25519_dalek::verify_batch` call (`~11.5 µs/sig` on AVX2 vs `54 µs/sig` individual).

* **Estimated gain and derivation**:
  * Per-request signature verification drops from `~49 × 54 µs = 2,646 µs` (`n = 9`) and `~89 × 54 µs = 4,806 µs` (`n = 17`) down to **`1,300 µs / B` (QC) + `w × 11.5 µs` (`WITNESS_ACK`s)**: at `B = 16` reqs/block, **`81 + 69 = 150 µs/req` at `n = 9` (17.6× faster)** and **`81 + 127 = 208 µs/req` at `n = 17` (23.1× faster)**.
  * Midnight `settle(auth, FINAL)` and `Checkpoint` verification drop from `q` individual curve verifications to **1 aggregate pairing check (`96 B` witness)** regardless of `n = 9` or `n = 17`.

* **Security argument**:
  * **Rogue-key resistance**: Key-Registry / TEE boot PoPs bind every validator `PK_i^{BLS}` in the standard PoP model (`blst` `AggregatePublicKey::from_public_keys` over PoP-verified keys).
  * **No Ed25519 consensus-split risk (`ePrint 2020/1244`)**: `ed25519_dalek::verify_batch` checks the cofactored equation `[8]([z_i s_i]B - [z_i]R_i - [z_i k_i]A_i) = O` and is used **strictly on internal committee peer messages** signed by epoch-registered prime-order node keys `post_i` / `bk_sig`. It is **never** used on host-chain Solana output signatures (which use strict individual check in §3.7).

* **Implementation cost**: Low (`~250` LoC: enable `batch` feature in `impl/Cargo.toml`, add `blst` crate for QC + Checkpoint aggregation).
* **Sources**: `impl/BENCHMARKS.md` (`54 µs` post check); `ed25519-dalek` `verify_batch` docs; Chalkias, Garillot, Nikolaenko, *Taming the many EdDSAs* (`ePrint 2020/1244`); `supranational/blst`.

---

### 3.9 Optimization 9: `O(1)` Multi-Shard Coordinator Aggregation, Homomorphic On-Board Fallback, and Constant-3-Round Additive Bar-Ilan–Beaver Multi-Shard ECDSA (`DECISIONS.md` 21–25)

* **Mechanism**:
  1. **Schnorr / Ed25519 Coordinator Mode (`O(1)` committee & Midnight cost for arbitrary `|A| = m`)**: Under `DECISIONS.md` 21–22, every satisfying actor set `S ⊆ A` of the charter's monotone access structure (`AND`, `k`-of-`m` Shamir with public Lagrange weights `λ_{a,S}`, escrow `OR` branches) reconstructs the **same** user-side key `x_U = sum_{a ∈ S} w_{a,S} x_a` (`A = x_U · G = X - X_f`). Run FROST-style pre-aggregation off-board among `S`:
     * Each actor `a ∈ S` sends fresh commitments `{(D_{a,v,j}, E_{a,v,j})}` to the coordinator.
     * Coordinator distributes the full tuple `M_S = {(b, D_{b,v,j}, E_{b,v,j})}_{b ∈ S}` alongside `(m, D_ℓ, E_ℓ)`.
     * Each actor `a ∈ S` independently verifies host-chain policy on `tx_j`, computes **per-actor FROST binding** `ρ_{a,v,j} = Hq_act("SL1/act-bind", a, v, j, tx_j, M_S, D_ℓ, E_ℓ)`, sets `R_{u,v,j} = sum_{b ∈ S} (D_{b,v,j} + ρ_{b,v,j} E_{b,v,j})`, computes `ρ_{v,j} = Hq_bind(R_{u,v,j}, j, tx_j, D_ℓ, E_ℓ)` and `R_{v,j} = R_{u,v,j} + D_ℓ + ρ_{v,j} E_ℓ`, and returns `s_{a,v,j} = d_{a,v,j} + ρ_{a,v,j} e_{a,v,j} + c_{v,j} · w_{a,S} · x_a` (applying `±1` BIP340 `y`-parity negation consistently across all `a ∈ S`).
     * Coordinator checks `s_{a,v,j} · G == D_{a,v,j} + ρ_{a,v,j} E_{a,v,j} + c_{v,j} A_{a,S}` (blaming any lying actor locally before posting), sums `s_{u,v,j} = sum_{a ∈ S} s_{a,v,j} + tweak`, seals **one standard 16 KiB envelope**, and proves **one standard `k = 18` Midnight `authorize`** (using aggregated JubJub/Schnorr charter quorum signature inside the circuit).
  2. **Asynchronous On-Board Multi-Shard Fallback (`DECISIONS.md` 23 — zero online coordination)**: When actors cannot meet online and post `m` separate sealed inner dealings under one `(eid, auth_ref)`, each Fenrir node:
     * Verifies all `m · K · L` inner dealings in **one** 128-bit Pippenger RLC (`~0.10` mul-eq per dealing instead of `8` muls!).
     * **Homomorphically aggregates shares locally before release**: `s_{U,v,j_g,i} = sum_{a ∈ S} s_{a,v,j_g,i} mod q` and `S_{U,v,j_g} = sum_{a ∈ S} S_{a,v,j_g}`. Each node sends **one 32-byte scalar `s_{U,v,j_g,i}`** (not `m` scalars!) to combiners, keeping release bandwidth, TEE witness size, and combiner interpolation **strictly `O(1)` in `m`**! Capsule encryption under `S_{U,v,j_g} = s_{U,v,j_g} · G` requires each actor `a ∈ S` to attach `S_{a,v,j}` in `body_0` and encrypt `capsule_j` to an ECDH ephemeral key whose secret is Shamir-split across `S` (`DECISIONS.md` 23).
  3. **Constant-3-Round Multi-Shard ECDSA Birth via Additive Bar-Ilan–Beaver Inversion (`DECISIONS.md` 24)**: Multiplicative nonce cascades (`k = k_f · prod_{a ∈ S} k_a`) either leak pairwise products or take `O(log m)` sequential rounds, while all-pairs MtA takes `O((m + n)^2)` work. Instead, define the joint ECDSA slot nonce **additively**:
     `k = k_f + sum_{a ∈ S} k_a`, with independent additive blinding mask `β = β_f + sum_{a ∈ S} β_a`
     (where `k_f, β_f` are `t`-of-`n` Shamir-shared on Fenrir and `k_a, β_a` are held by actor `a ∈ S`).
     * **Round 1**: Commit-and-open `R_f = k_f · G` and `R_a = k_a · G`, setting `R_slot = R_f + sum_{a ∈ S} R_a` (`r = x(R_slot) mod n`); run **one parallel round** of vectorized SoftSpokenOT/DKLs23 MtA (§3.10) between each actor `a ∈ S` and the `t` Fenrir nodes (plus actor-to-actor or star-via-committee blinded shares) to obtain additive shares of `δ = k · β` and `γ = x · β`.
     * **Round 2**: Publicly reconstruct **`δ = k · β mod n`** (since `β_f` + honest `β_{a*}` is uniform in `ℤ_n^*`, opening `δ` in the clear leaks **zero bits** of `k`!), invert `δ^{-1} mod n` **publicly in 1 scalar inversion**, and set each party's share of `w = k^{-1} = δ^{-1} · β` locally with **zero rounds**!
     * **Round 3**: Publish `W_a = w_a · R_slot` and check `sum W_a + W_f == G` (`CGGMP21`/`DKLs23` consistency check), completing `N_slot = 32` multi-shard ECDSA slots in **constant 3 rounds for any `m`**.

* **Estimated gain and derivation**:
  * **Coordinator mode (Schnorr/Ed25519)**: Fenrir node CPU, padded envelope bytes (`16 KiB`), TEE witness I/O, and Midnight `authorize` circuit rows are **100% invariant (`1.0×`) for any `m = 2, 5, 20`**, saving `m×` inner dealings (`5.2 KB × (m - 1)` wire and `4.1 × (m - 1)` mul-eq CPU).
  * **On-board fallback**: Pippenger RLC + local share summation cuts `m = 5` node dealing checks from `5 × 128 = 640` muls (`32 ms`) to **`~12` mul-eq (`0.20 ms`, 160× faster)** and cuts combiner/release work by **`5×` (`O(1)`)**.
  * **Multi-shard ECDSA**: Constant **3 rounds** for arbitrary `m` (vs `3 + 2 ceil(log_2 m)` cascade rounds), with `1` clear-text scalar inversion replacing distributed inversion protocols.

* **Security argument**:
  * **Multi-actor ROS / Wagner resistance (`O6` extension)**: Because every actor's `ρ_{a,v,j}` hashes the entire ordered set `M_S = {(b, D_b, E_b)}_{b ∈ S}` and `(tx_j, D_ℓ, E_ℓ)`, and Fenrir's `ρ_{v,j}` hashes `R_{u,v,j}`, no corrupt subset `S' ⊂ S` (even colluding with `t - 1` Fenrir nodes) can adapt its `(D_b, E_b)` after seeing an honest actor `a*`'s `(D_{a*}, E_{a*})` without changing `ρ_{a*,v,j}`. Reduction to OMDL/Gap-DL follows FROST2 (`[KG20]`/`[BHK+22]`), discharging the multi-shard extension of `O6`.
  * **Charter quorum secrecy (`DECISIONS.md` 25)**: Coordinator mode hides **both** `|S|` and which charter branch satisfied `A` from Fenrir operators and Midnight observers (`C10` strengthened).
  * **Multi-shard ECDSA unforgeability (`C3`, `C4`)**: If at least one honest party `p* ∈ S ∪ {Fenrir}` keeps `(k_{p*}, β_{p*}, x_{p*})` secret (`<= t - 1` corrupt Fenrir nodes **or** `>= 1` honest actor in `S`), `k = k_{p*} + k_{-p*}` and `β = β_{p*} + β_{-p*}` are information-theoretically hidden given public `δ = k · β` and `R_slot = k · G` (standard Bar-Ilan–Beaver simulatability: pick `δ <- ℤ_n^*`, simulate `β_{p*}` implicitly).

* **Implementation cost**: Medium (`~450` LoC off-board coordinator SDK + `~180` LoC homomorphic board share aggregator; `~900` LoC for multi-shard ECDSA extension on top of §3.10).
* **Sources**: `DECISIONS.md` 21–25; `DESIGN.md` §3.6, §12 (`O6`); Doerner et al. `DKLs23` (`ePrint 2023/765`).

---

### 3.10 Optimization 10: Vectorized `DKLs23` + `SoftSpokenOT` Dishonest-Majority ECDSA Slot Pool (`N_slot = 32`) + Single-Process Enclave Channel Termination

* **Mechanism**:
  1. **Instantiate `F_presig` (`O1`) and `F_mul` (`O2`) with vectorized `DKLs23` (`ePrint 2023/765`) over `SoftSpokenOT` (`ePrint 2022/192`)**: Do not instantiate `DESIGN.md` §3.6 (`t = n - f` dishonest majority: `t = 7` at `n = 9`, `t = 12` at `n = 17`) with Paillier-based `CGGMP21` (which requires expensive 2048/3072-bit Paillier encryptions and `Π^{enc}`/`Π^{aff-g}` range proofs per pair). Instead, run pairwise base OTs **once at epoch start**, expand silent small-field VOLE correlations via `SoftSpokenOT` (`k = 2..4`), and execute all `N_slot = 32` ECDSA presignatures + `F_mul` multiplications (`(w_U, x_U) * (w_F, x_F)`) in **one vectorized 3-round batch**.
  2. **RLC-batch §3.6 steps 5–6**: Batch the `32 × t` DLEQ proofs of `Φ'_k = x_U' · Φ_k` (`§3.6` step 5) into one 128-bit Strauss/Pippenger RLC (`~5` mul-eq vs `~672` muls at `n = 9`) and apply `f + 1` seeded shares (§3.6) to the `32` `E`-backup dealings (`§3.6` step 6).
  3. **Collapse the 3-container enclave proxy chain (`VERITEE-MODEL.md` §4.1)**: Terminate `bk_kem` / `bk_sig` attested TLS/Noise channels directly inside the Rust `mpc-node` binary (`rustls` + SEV-SNP `SNP_GET_EXT_REPORT` ioctl), deleting the `Caddy -> Go attestation_server -> loopback HTTP -> Docker mpc-node` hop chain.

* **Estimated gain and derivation**:
  * Generating/replenishing a full `N_slot = 32` ECDSA address pool drops from **`~1.5–3.0 s` CPU (`CGGMP21` Paillier + range proofs)** down to **`~45–60 ms` total CPU (`~1.5–1.9 ms/slot`) in 3 network rounds** (`silence-laboratories/dkls23` measures `10–19 ms` single-slot online + OT; vectorizing `32` slots over one `SoftSpokenOT` correlation stream amortizes OT setup and base steps by `~8×–10×`).
  * Collapsing the `VERITEE-MODEL.md` §4.1 proxy chain eliminates `4` localhost TCP/HTTP socket copies and `2` redundant AEAD encrypt/decrypt passes on every peer share and witness message (`~1.5–3 ms` saved per peer round) while shrinking the enclave TCB.

* **Security argument**:
  * `DKLs23` (`ePrint 2023/765`) is proven UC-secure against an arbitrary dishonest majority (`up to t - 1` corrupt signers out of `n`) in the Global Random Oracle Model, directly discharging open obligations **`O1` (`F_presig`) and `O2` (`F_mul`)** at `t = n - f` (`7`-of-`9` and `12`-of-`17`). `SoftSpokenOT` (`ePrint 2022/192`) lives strictly in **Minicrypt** (PRG/correlation-robust hash only, avoiding LPN noise-decoding assumptions).
  * Terminating `bk_kem`/`bk_sig` directly inside `mpc-node` closes the attestation-to-application binding gap flagged in `VERITEE-MODEL.md` §4.4 (ensuring the measured enclave binary, not an external reverse proxy, owns `bk_sig`).

* **Implementation cost**: Medium (`~800` LoC integrating `dkls23` / `SoftSpokenOT` trait adapter for `F_presig`/`F_mul` + `~300` LoC `rustls` custom SEV-SNP cert verifier in `mpc-node`).
* **Sources**: `DESIGN.md` §3.6, §12 (`O1`, `O2`); `VERITEE-MODEL.md` §4.1, §4.4; Doerner, Kondi, Lee, Shelat, *Threshold ECDSA in Three Rounds* (`ePrint 2023/765`) & `silence-laboratories/dkls23`; Roy, *SoftSpokenOT* (`ePrint 2022/192`).

---

## 4. What Not To Do: Tempting Optimizations That Break Security Claims

1. **DO NOT reuse one Schnorr committee slot `ℓ` across the `K` fee variants of an envelope** (tempting `K = 8×` reduction in slot burn and ticket checks).
   * **Claim broken**: **`C5` (Permanent root-key extraction of `x_f`) and `C12` (`DESIGN.md` §4.5, `SCHEME.md` §6.5, ledger `D7(b2)`)**.
   * **Exact reason**: Under RBF fee bumping (`DESIGN.md` §5.6), a stalled spend legitimately advances across generations `g = 1 -> 2 -> 3` (`j_1 < j_2 < j_3`) on the same input! If `j_1, j_2, j_3` share slot `(d_ℓ, e_ℓ)` with distinct `tx_j` and distinct bindings `ρ_1, ρ_2, ρ_3` and challenges `c_1, c_2, c_3`, the committee releases three linear equations `s_{f,k} = d_ℓ + ρ_k e_ℓ + c_k x_f mod q` (`k = 1, 2, 3`) in the three unknowns `(d_ℓ, e_ℓ, x_f)`. Whenever `det([1, ρ_k, c_k]_{k=1..3}) != 0 mod q` (overwhelming probability `1 - 1/q`), **anyone on earth solves the `3 × 3` system by Gaussian elimination and recovers Fenrir's permanent root share `x_f` in plaintext**, forging arbitrary spends on the address without Fenrir forever! (Even if `ρ` were forced equal across variants, `2` generations `(c_1 != c_2)` immediately solve `x_f = (s_{f,1} - s_{f,2})(c_1 - c_2)^{-1}`!)

2. **DO NOT use Hyper-Invertible / Vandermonde Matrices (e.g., Damgård–Nielsen / Beerliová-Trubíniová–Hirt) to extract `t - f` Schnorr slots per `t` dealer sharings** (tempting `5×` slot-pool speedup at `n = 9`, `7×` at `n = 17`).
   * **Claim broken**: **`C5` (Existential forgery / key extraction under `t - 1` corrupt nodes + owner)**.
   * **Exact reason**: Hyper-invertible randomness extraction yields `k` uniform independent secrets from `m` dealers only when `k <= m - t_adv`, where `t_adv` is the number of corrupt dealers. In `DESIGN.md` §3.5, a slot quorum `Q` has `m = t` dealers (`7` at `n = 9`, `12` at `n = 17` so `f` offline nodes cannot halt epoch setup), while `DESIGN.md` §9 `C5` gives the adversary **`t_adv = t - 1` corrupt nodes** (`6` at `n = 9`, `11` at `n = 17`). Inside `Q`, `t - (t - 1) = 1` honest dealer remains! Extracting `k >= 2` slots from `Q` imposes deterministic affine relations `(d_{\ell_2}, e_{\ell_2}) = α (d_{\ell_1}, e_{\ell_1}) + known` in the `(t - 1)`-coalition's view, turning two spends into an immediate nonce-correlation recovery of `x_f` (and requiring all `m = n` nodes to deal synchronously to get `n - (t - 1) = f + 1` slots destroys `f`-fault liveness `C11`).

3. **DO NOT treat a `q`-voter BFT Quorum Certificate as satisfying `w` TEE peer-witness acks** (tempting elimination of separate `WITNESS_ACK` tracking).
   * **Claim broken**: **`DESIGN.md` §7.7 TEE rollback bound (`c <= n - 1 - 2f`)**.
   * **Exact reason**: At `n = 9, f = 2`, a BFT QC has `q = n - f = 6` signers, which includes **the releasing node itself plus only `5` peers**, whereas `§7.7` requires **`w = n - 1 - f = 6` distinct *other* peers** (`q - 1 = 5 < w = 6`)! Accepting `5` peer acks drops rollback tolerance `2w' - (n - 1)` from `2(6) - 8 = 4` colluding rolled-back enclaves down to **`2(5) - 8 = 2`**, cutting the safety margin in half. Piggybacking witness records onto BFT traffic (§3.1) is safe **only** when the releasing node still waits for `w` distinct peer `WITNESS_ACK` signatures.

4. **DO NOT encrypt `s_{u,v,j}` inside `body_0` under `κ_0` alone to avoid `K · L` inner Shamir dealings** (tempting `16×` envelope dealing reduction).
   * **Claim broken**: **`C9` (Unselected variant privacy), `C10` (Pre-selection transaction secrecy), and `C7` (Revocation before `ADMIT`)**.
   * **Exact reason**: Every node reconstructs `κ_0` in plaintext at `OPENED` (`§5.2` step 4) *before* `ADMIT` and *before* fee selection `j_g`. If `s_{u,v,j}` lived in `body_0` without an inner `t`-of-`n` Shamir dealing, **a single honest-but-curious non-TEE node (`1 < t = 7`) or a single compromised enclave (`c = 1`)** would immediately read every `s_{u,v,j}` for all `j = 1..K`, derive `KDF(s_{u,1,j})`, decrypt **every unselected `capsule_j`** (violating `C9` and `C10`), and retain `s_u` even if `auth_ref` is revoked before `ADMIT` (`C7`).

5. **DO NOT drop the MEGa ephemeral-key DLEQ proof `(E', T_1, T_2, z_e)` (`[GS22b]` §4.3) or broadcast `κ_{0,i}` optimistically before Block 1's QC**.
   * **Claim broken**: **`C8` (`PROOFS.md` Theorem C `Reuse` reduction & pre-ordering mempool censorship resistance `B2`)**.
   * **Exact reason**: Because nodes publish `(K_i, π_DLEQ)` on `COMPLAINT`, an adversary that replays or mauls an honest envelope's `E` without proving knowledge of `r = dlog_G(E)` bound to `hd` turns honest nodes into static DH decryption oracles (`K_i = sk_i · E`), breaking Gap-CDH simulation in `PROOFS.md` Theorem C (`notes-2022-506.md`). Similarly, releasing `κ_{0,i}` before Block 1's QC lets a `t`-node / 1-enclave coalition open `body_0` in the mempool and censor the envelope based on its fee grid (`B2`). *(Trimming `(T_a, z_a)` in §3.6 is safe strictly because `(E', T_1, T_2, z_e)` is retained intact.)*

6. **DO NOT let only the initiating actor contribute a nonce factor (`k = k_0 · k_f`) in multi-shard ECDSA (`DECISIONS.md` 24)** (tempting `O(1)` 2-party birth regardless of `|A|`).
   * **Claim broken**: **`C3` and `C4` (Unilateral theft against every other actor `a ∈ A \ {0}`) under `t` corrupt Fenrir nodes**.
   * **Exact reason**: In ECDSA, `s = k^{-1}(h + r x) mod n`. If `k = k_0 · k_f` involves only initiator `0` and Fenrir, then `t` corrupt Fenrir nodes (`k_f`) colluding with **just initiator `0` (`k_0`)** know the complete scalar `k`! After a single legitimate spend `(r, s)` co-approved by the rest of `S`, that coalition computes **`x = r^{-1}(k · s - h) mod n`**, recovering the full root key `x` (including every honest actor `a* ∈ S \ {0}`'s secret shard `x_{a*}`!) in one division. Every actor `a ∈ S` must contribute secret entropy to `k` (`k = k_f + sum_{a ∈ S} k_a` in §3.9).

7. **DO NOT replace per-point Suite-3 subgroup checks with a naive RLC `[ℓ](sum_k r_k P_k) = O`, skip subgroup checks on `C_{m,1..t-1}`, or run cofactored `verify_batch` on final Solana signatures**.
   * **Claim broken**: **`C20` (`PROOFS.md` Theorem E(d) unique share reconstruction) and host-chain Solana validity (`ePrint 2020/1244`)**.
   * **Exact reason**:
     * On Edwards25519 (`cofactor h = 8`, torsion group `E[8] ≅ ℤ/8ℤ` generated by `T_8`), `[ℓ]P_k` lives in `ℤ/8ℤ`. If `P_1` carries order-2 torsion (`4 T_8`), `[ℓ](r_1 P_1) = 4 r_1 T_8 = O` **whenever `r_1` is even — a `1/2` soundness failure per check**!
     * Worse, skipping `is_torsion_free()` on higher commitment coefficients `C_{m,1..t-1}` and hoping honest share checks `s_i B == eval(Com, i)` catch torsion **fails completely**! Concrete counterexample at `n = 9, t = 7, f = 2`: let Byzantine nodes `{4, 8}` stay silent, so the `7` honest nodes are `H = {1, 2, 3, 5, 6, 7, 9}`. Modulo `8`, `H mod 8 = {1, 2, 3, 5, 6, 7, 1}` omits `{0, 4, 8}` (`1 ≡ 9 mod 8`)! Construct the degree-`4` (`<= t - 1 = 6`) torsion polynomial:
       `T(X) = (X - 1)(X - 3)(X - 2)(X - 6) · T_8`
       For `X ∈ {1, 3, 2, 6, 9}`, a linear factor vanishes `mod 8` (`9 - 1 = 8`); for `X ∈ {5, 7}`, `(X - 1)(X - 3)` is a product of two consecutive even integers (`4 × 2 = 8` for `X = 5`; `6 × 4 = 24 ≡ 0 mod 8` for `X = 7`)! Thus **`T(i) = O` at ALL SEVEN honest nodes `i ∈ {1, 2, 3, 5, 6, 7, 9}`**, so every honest share check `s_i B == eval(Com, i)` passes with zero torsion, while at `X = 0`, **`T(0) = (-1)(-3)(-2)(-6) T_8 = 36 T_8 = 4 T_8 != O`** injects an order-2 torsion point directly into `C_{m,0} = S_u`, breaking `C20`! Always validate every wire point once on decode (`PrimeOrderPoint` in §3.5).
     * Likewise, never run cofactored `ed25519_dalek::verify_batch` on final Solana host-chain signatures (`ePrint 2020/1244`): Solana validators check strict cofactorless verification, so a signature passing cofactored batch check with torsion can be rejected on-chain (`C11` griefing).

8. **DO NOT use Groth–Shoup Beaver quadruples (`ePrint 2022/506`), lower `t` from `n - f` to `f + 1`, or drop two-nonce `(D_ℓ, E_ℓ)` Schnorr slots for single-nonce `R_ℓ`**.
   * **Claims broken**: **Algebraic feasibility at `t = n - f`; `C6`/`C7`/`C8`/`C9` (minority coalition opening); `C5` (Wagner/ROS forgery)**.
   * **Exact reason**: `[GS22b]` degree-reduction multiplication requires honest majority **`2(t - 1) < n`**, which is algebraically impossible at `t = 7, n = 9` (`12 >= 9`) and `t = 12, n = 17` (`22 >= 17`). Lowering `t` to `f + 1` (`3` at `n = 9`, `6` at `n = 17`) lets `f + 1` nodes (`2` Byzantine + `1` coerced/broken node) open `κ_0` pre-QC (`C8`), open revoked spends (`C6`, `C7`), and decrypt every unselected capsule (`C9`, `C10`). Single-nonce `R_ℓ = d_ℓ · G` without `(D_ℓ, E_ℓ)` FROST binding falls to polynomial-time Benhamouda et al. (`ePrint 2020/945`) Wagner/ROS concurrent forgeries across `>= 256` open slots (`C5`).

---

## 5. Revised Cost Tables: Launch (`n = 9`) and `n = 17`

Workload: two-input Taproot spend (`K = 8, L = 2`, `16` inner dealings, `8` capsules) unless otherwise noted. Baseline figures are from `DESIGN.md` §11 (`50 µs`/mul *estimates*, plus omitted on-path combiner & post-sig costs from §2.3); optimized figures apply **Optimizations 1–10** (`17 µs`/var-base mul, `5 µs`/fixed-base mul on `libsecp256k1` + AVX2 `dalek` + `blst`, `B = 16` envelopes/block, `B_pool = 1,024`).

### 5.1 Wire Sizes, Consensus Rounds, and Latency

| Metric | Launch (`n=9, f=2, q=6, t=7`) **Before** | Launch (`n=9, f=2, q=6, t=7`) **After** | `n=17` (`f=5, q=12, t=12`) **Before** | `n=17` (`f=5, q=12, t=12`) **After** |
| :--- | ---: | ---: | ---: | ---: |
| Outer dealing `κ_0` (incl. `E` + `π`) | `748 B` | **`491 B`** (`-34%`) | `1,169 B` | **`752 B`** (`-36%`) |
| One inner dealing (`f + 1` seeded cts) | `519 B` | **`327 B`** (`-37%`) | `940 B` | **`588 B`** (`-37%`) |
| Unpadded `K=8, L=2` payload (TEE) | `~14,782 B` | **`11,453 B`** | `~21,939 B` | **`15,890 B`** |
| **Padded envelope wire frame** | **`16,384 B` (`16 KiB`)** | **`16,384 B` (`16 KiB`)** | **`65,536 B` (`64 KiB`)** | **`16,384 B` (`16 KiB`, 4× smaller)** |
| One Schnorr slot on board (`t` dealers) | `7.3 KB` | **`4.5 KB`** (`-38%`) | `22.6 KB` | **`13.8 KB`** (`-39%`) |
| Sequential BFT board blocks / spend | `5` (after `F_M`) | **`2` (Block 1 overlapped w/ `F_M`)** | `5` (after `F_M`) | **`2` (Block 1 overlapped w/ `F_M`)** |
| TEE `dm-integrity` `fdatasync`s / node | `2` / req (`32` @ `B=16`) | **`1` / block (`0.06` / req @ `B=16`)** | `2` / req (`32` @ `B=16`) | **`1` / block (`0.06` / req @ `B=16`)** |
| **Post-to-broadcast latency (`1 s` blk, `F_M <= 1 s`)** | `F_M + 5.07 s` (`~6.1 s`) | **`2.05 s`** (**3.0× faster**) | `F_M + 5.07 s` (`~6.1 s`) | **`2.05 s`** (**3.0× faster**) |
| **Post-to-broadcast latency (`400 ms` blk, `F_M <= 0.4 s`)** | `F_M + 5.07 s` | **`0.85 s`** (**~6× faster**) | `F_M + 5.07 s` | **`0.85 s`** (**~6× faster**) |
| **Non-TEE client `authorize` prove (CPU / WebGPU)** | `8–16 s` (`2^18` STARK + `2^20..21` wrap) | **`1.5–2.5 s` CPU / `~0.5 s` GPU** (`1 × 2^18` KZG) | `8–16 s` | **`1.5–2.5 s` CPU / `~0.5 s` GPU** |

### 5.2 Per-Node CPU, Sustained Throughput, Pool Birth, and Multi-Shard Scaling

| Per-Node CPU Metric (`K = 8, L = 2`) | Launch (`n = 9, t = 7`) **Before** | Launch (`n = 9, t = 7`) **After** | `n = 17` (`t = 12`) **Before** | `n = 17` (`t = 12`) **After** |
| :--- | ---: | ---: | ---: | ---: |
| 1. Outer `κ_0` (`DH` + eval + `π`) | `17` muls (`0.85 ms`) | **`3.6` mul-eq (`61 µs`)** | `22` muls (`1.10 ms`) | **`3.7` mul-eq (`63 µs`)** |
| 2. `16` inner dealings (eval + 128b RLC) | `70–128` muls (`3.5–6.4 ms`) | **`4.1` mul-eq (`70 µs`)** | `100–208` muls (`5.0–10.4 ms`) | **`5.0` mul-eq (`85 µs`)** |
| 3. `16` ticket `R_m` + batch affine inv | `24–32` muls (`1.2–1.6 ms`) | **`16.0` mul-eq (`272 µs`)** | `24–32` muls (`1.2–1.6 ms`) | **`16.0` mul-eq (`272 µs`)** |
| 4. `16` TEE §4.7(4) `S_u` checks (`0` non-TEE) | `48` muls (`2.40 ms`) | **`3.9` mul-eq (`66 µs`)** | `48` muls (`2.40 ms`) | **`3.9` mul-eq (`66 µs`)** |
| **Core algebra subtotal (§11.3 scope)** | **`160–220` muls (`8.0–11.0 ms`)** | **`27.7` mul-eq (`0.47 ms`)** | **`~200–310` muls (`10–15.5 ms`)** | **`28.7` mul-eq (`0.49 ms`)** |
| 5. Combiner (`L = 2`, optimistic + `S_u` pre-check) | `44` muls (`2.20 ms`) | **`3.0` mul-eq (`53 µs`)** | `74` muls (`3.70 ms`) | **`3.1` mul-eq (`55 µs`)** |
| 6. Board QCs (`blst`) + witness (`verify_batch`) | `~53` eq (`2.65 ms`) | **`150 µs`** (`@ B = 16`) | `~96` eq (`4.81 ms`) | **`208 µs`** (`@ B = 16`) |
| **Total On-Path TEE Node CPU / spend** | **`~12.9–15.9 ms`** | **`0.68 ms` (`1,470 req/s/core`)** | **`~18.5–24.0 ms`** | **`0.75 ms` (`1,330 req/s/core`)** |
| **Total On-Path Non-TEE Node CPU / spend** | `~10.5–13.5 ms` | **`0.61 ms` (`1,640 req/s/core`)** | `~16.1–21.6 ms` | **`0.68 ms` (`1,470 req/s/core`)** |
| 7. Off-path `16` burned Schnorr slots (amortized) | `2,192` muls (`109.6 ms`; `55 ms` batched) | **`40.8` mul-eq (`0.69 ms`)** | `6,240` muls (`312.0 ms`) | **`104.2` mul-eq (`1.77 ms`)** |
| **Total Sustained TEE CPU / spend (On + Pool)** | **`67.9–125.5 ms` (`8–15 req/s/core`)** | **`1.37 ms` (`730 req/s/core`)** | **`~330 ms` (`~3 req/s/core`)** | **`2.52 ms` (`395 req/s/core`)** |
| **8-core EPYC SEV-SNP Sustained Committee Throughput** | `~65–115 req/s` | **`~5,800 req/s`** | `~24 req/s` | **`~3,150 req/s`** |
| ECDSA address birth (`N_slot = 32` slots) | `~1.5–3.0 s` (`CGGMP21` *est.*) | **`~45–60 ms` (`3` rounds, `DKLs23`)** | `~3.0–6.0 s` | **`~85–110 ms` (`3` rounds, `DKLs23`)** |
| Multi-shard (`|A| = m = 5`) node & envelope overhead | `5×` inner dealings (`+16.6 KB`, `+20 ms`) | **`1.0×` (`+0 B`, `+0 µs` coord.)** / **`+0.13 ms` board** | `5×` inner dealings (`+60 KB`) | **`1.0×` (`+0 B`, `+0 µs` coord.)** / **`+0.18 ms` board** |

---

## 6. Sources

*Access note*: All repository files below were opened and read in full via `read_file`; all external URLs below were retrieved and verified via grounded `search_web` queries in this session. No unread or unverified references are cited.

### Local Repository Specifications, Proofs, and Prototype Code
1. `design/enhancement/BRIEF-SPEED.md` — Problem statement, five optimization domains, constraints, and deliverable structure.
2. `design/enhancement/DESIGN.md` — Full split-line dealing specification: parameters (§1.2), birth & slot pools (§3.5–3.6), ticket & envelope formats (§4), two-stage dealing & fee anchoring (§5), TEE strengthening & `§7.7` peer-witness durability bound, security claims `C1`–`C16` (§9), baseline cost tables (§11), and open proof obligations `O1`–`O18` (§12).
3. `design/enhancement/DECISIONS.md` — Settled architectural decisions `1`–`20` and multi-shard charter extension `21`–`25` (actor charters, coordinator vs board-collected shares, multi-shard ECDSA nonce question, quorum secrecy).
4. `design/enhancement/VERITEE-MODEL.md` — Concrete AMD SEV-SNP (`veritee`) architecture, 3-container loopback proxy chain (`§4.1`), attestation binding gap (`§4.4`), and `dm-integrity` Tier 0 sealing (`§3`, `§5`).
5. `design/SCHEME.md` & `design/PROOFS.md` — Base MEGa-sealed Shamir dealing, optimistic combiner pattern (`SCHEME.md` §3.8), single-slot RBF key-extraction failure (`SCHEME.md` §6.5), Theorem C adaptive MEGa Gap-CDH reduction (`PROOFS.md` §4), and Theorem E(d) Suite-3 `C20` torsion invariants (`PROOFS.md` §6).
6. `design/notes-2022-506.md` — Analysis of Groth & Shoup (`ePrint 2022/506`): why `(E', T_1, T_2, z_e)` is required against complaint-oracle attacks and why `[GS22b]` Beaver quadruples fail when `2(t - 1) >= n`.
7. `impl/BENCHMARKS.md`, `impl/bench9-output.txt`, `impl/Cargo.toml`, and `impl/src/{lib.rs,algebra.rs,ed25519.rs,hash.rs,message.rs,reshare.rs,signing.rs,simulation.rs}` — Measured Arm Cortex-X925/A725 benchmarks (`open` and `sealed-k8`) and the four code-level root causes in §2.1.

### External Primary Sources and Cryptographic Libraries
8. **Bitcoin Core `libsecp256k1`** — `https://github.com/bitcoin-core/secp256k1` (`src/ecmult_impl.h`): GLV endomorphism scalar splitting (`secp256k1_scalar_split_lambda`), constant-time `secp256k1_ecmult_gen`, and `secp256k1_ecmult_multi_var` Strauss-wNAF (`< 88` points) / Pippenger bucket MSM (`ECMULT_PIPPENGER_THRESHOLD = 88`), plus `~17 µs` single-mul benchmark baselines (§3.2, §3.4, §3.5).
9. **`ed25519-dalek` & `curve25519-dalek`** — `https://docs.rs/ed25519-dalek/latest/ed25519_dalek/fn.verify_batch.html` and `https://crates.io/crates/curve25519-dalek`: `verify_batch` 128-bit transcript-free random linear combination API (`batch` feature flag) and AVX2 / IFMA SIMD 4-way parallel Edwards arithmetic benchmarks (`22%–35%` speedup, `~11.5 µs/sig` batch verify; §3.5, §3.8).
10. **Chalkias, Garillot, Nikolaenko, *Taming the many EdDSAs* (SSR 2020)** — `https://eprint.iacr.org/2020/1244`: Cofactored `verify_batch` vs cofactorless individual Ed25519 verification divergence and small-order torsion edge cases justifying strict separation between internal committee `verify_batch` and Solana output verification (§3.8, §4.7).
11. **Supranational `blst`** — `https://github.com/supranational/blst`: Assembly-optimized BLS12-381 signature aggregation (`MinPk` `96 B` aggregate signatures, `~1.2–1.5 ms` constant 2-pairing `fast_aggregate_verify` for BFT QCs and Midnight `Checkpoints`; §3.8).
12. **Midnight Network `midnight-zk`** — `https://github.com/midnightntwrk/midnight-zk`: Midnight's BLS12-381 + JubJub Halo2 PLONK-KZG stack (`curves`, `proofs`, `circuits`, `zk_stdlib`, and native proof `aggregator` crate), confirming native lookup PLONK-KZG support without an external STARK wrapper (§3.3).
13. **Halo2 `Table16` SHA-256 Gadget Specification** — `https://zcash.github.io/halo2/design/gadgets/sha256/table16.html`: Exact row budget of `2,099` active PLONK rows per 64-byte SHA-256 block compression plus one shared `2^16 = 65,536`-row spread lookup table, grounding the `102 × 2,099 = 214,098`-row (`< 2^18`) native `authorize` circuit calculation (§3.3).
14. **Grassi, Khovratovich, Schofnegger, *Poseidon2: A Faster Version of the Poseidon Hash Function* (AFRICACRYPT 2023)** — `https://eprint.iacr.org/2023/323`: Algebraic sponge over prime fields (`BLS12-381` `𝔽_r`) with `~70%` fewer PLONK constraints than Poseidon1 and `~70×` fewer rows than `Table16` SHA-256 for internal commitments `ic`, `tkc`, `auth`, and `H_pm` (§3.3).
15. **Plonky3 & Binius Hash Proving Benchmarks** — `https://github.com/Plonky3/Plonky3` and `https://www.binius.xyz`: Empirical client-CPU throughput comparisons of SHA-256/Keccak vs Poseidon2/binary-tower proving, confirming why hoisting shared BIP341 SHA-256 blocks and replacing internal SHA-256 commitments dominates client latency rather than wrapping a separate STARK (§3.3).
16. **Doerner, Kondi, Lee, Shelat, *Threshold ECDSA in Three Rounds* (`DKLs23`, IEEE S&P 2024) & Silence Laboratories Rust Implementation** — `https://eprint.iacr.org/2023/765` and `https://github.com/silence-laboratories/dkls23`: 3-round UC-secure dishonest-majority (`t = n - f`) threshold ECDSA via OT multiplication (`10–19 ms` single-run benchmarks), grounding vectorized `N_slot = 32` ECDSA birth (`O1`, `O2`) and additive Bar-Ilan–Beaver multi-shard ECDSA (§3.9, §3.10).
17. **Lawrence Roy, *SoftSpokenOT: Quieter OT Extension From Small-Field Silent VOLE in the Minicrypt Model* (CRYPTO 2022)** — `https://eprint.iacr.org/2022/192`: Silent VOLE OT extension in Minicrypt (`~5×` faster and `λ/k` lower bandwidth than IKNP without LPN assumptions) underlying `DKLs23` vectorized multiplication (§3.9, §3.10).
