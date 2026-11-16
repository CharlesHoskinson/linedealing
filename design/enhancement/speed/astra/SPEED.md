# Making split-line dealing fast

## 1. Summary

Optimize the arithmetic and the nonce supply first. Then remove board scheduling barriers. Keep the custody split, the admitted message set, the thresholds, and the checks before release.

The five largest wins are:

| Priority | Change | Estimated gain |
|---|---|---|
| 1 | Evaluate Feldman polynomials with small-integer addition chains, cache the results, and use fixed-base multiplication | Launch online CPU targets **4–6 ms per node**, including a modest allowance for certificates and combination, against the design's **8–11 ms arithmetic estimate**. The isolated Feldman checks improve about **4–8×** against the unbatched estimate under the model below. |
| 2 | Apply the same arithmetic to Schnorr slot production and batch each dealer's transport and proof overhead | Replenishing 16 slots targets **24–40 ms per node**, against **109.6 ms** without the design's proposed batching or about **54.8 ms** with it. Online work plus replenishment targets **28–46 ms**. That is about **2.6–4.3×** the unbatched CPU capacity, or **1.4–2.3×** the already-batched estimate. |
| 3 | Replace separate ACK and OPENED block waits with certificates, retain a committed admission and anchor, and pipeline requests | The normal path targets **three board commits**, about **3.1 s** at one-second commits, against **5–6 s**. Ordering ciphertext while Midnight finalizes saves another **min(F_M, one commit)**. Host inclusion and required Midnight finality remain. |
| 4 | Verify outside actors' contributions, then aggregate shares that are not needed separately for capsule opening | With a ≥ 2 contributing actors and one capsule-key contribution retained separately, the scalar payload per selected input falls from **32(a+1) to 96 bytes per node**, including the committee partial. This is **3× at a = 8**. Admission and inbound traffic still grow with a. |
| 5 | Share sighash subcomputations, use a specialized hash AIR, and aggregate proofs before one final wrap | A concrete Taproot hash-work example falls from **240 to 148–180 compression equivalents**, about **1.3–1.6×**. A batch of B requests amortizes the final wrap's fixed cost by B. Neither number establishes the complete proof's time or size. |

These gains overlap. In particular, the first two use the same arithmetic changes. They do not multiply.

The estimates use the launch tuple (n, f, q, t) = (9, 2, 6, 7), followed by (17, 5, 12, 12). Let m = K·L be the number of tickets, a the number of contributing outside actors, B a batch size, and F_M Midnight finality. All new performance numbers are engineering estimates, not measurements of split-line dealing.

## 2. Profile: where the work goes

### Measured prototype

The prototype implements base line dealing. It does not measure the split protocol, its slot factory, Midnight, real BFT consensus, witness durability, or a Solana adapter.

| Measured operation, n = 9 | t = 3 | t = 7 |
|---|---:|---:|
| Open ECDSA, CPU per node per request | 2.331 ms | 3.320 ms |
| Additional combiner work | 0.106 ms | 0.151 ms |
| Open ECDSA, zero-delay simulation, batch 16 | 132.6 requests/s | 76.7 requests/s |
| Sealed BIP340, K = 8, owner deal and encrypt | 3.578 ms | 4.898 ms |
| Sealed BIP340, Step A | 1.623 ms | 2.193 ms |
| Sealed BIP340, decrypt and check shares | 1.026 ms | 2.072 ms |
| Sealed BIP340, verify one partial | 0.111 ms | 0.226 ms |
| Sealed Ed25519, Step A | 4.259 ms | 7.554 ms |

These rows come from different benchmark scopes. Adding all of them would double-count work. The simulation rates cover 16-request finite runs, include serial owner preparation, and exclude host-chain execution.

At t = 7, the hand-timed open ECDSA model includes 25 post-signature checks. At approximately 54 μs each, these consume 1.35 ms, or 41% of the 3.320 ms total. Transport batching in the simulator does not batch cryptographic verification.

The code explains two avoidable costs:

- In [algebra.rs](impl/src/algebra.rs:140), Commitment::evaluate uses Horner evaluation but converts the small node index into a full Scalar before each point multiplication. [ed25519.rs](impl/src/ed25519.rs:423) does the same.
- In [signing.rs](impl/src/signing.rs:160), partial creation calls verify_partial, which evaluates commitment polynomials again. Ed25519 serialization also repeats subgroup tests on already validated or internally generated points.

### Split-line estimates

For a single outside holder, TEE mode, K = 8 and L = 2, DESIGN §11 uses 50 μs per general scalar multiplication.

| Phase | Work per node | Estimate |
|---|---|---:|
| Public acceptance | Decode points, hash the frame, verify the 196-byte proof | Omitted as a separate line in the 8–11 ms total |
| Outer opening | Decrypt and check the outer share | 8 multiplication equivalents = 0.40 ms |
| Inner admission | Check 16 dealt shares | 128 equivalents = 6.40 ms, or about 70 = 3.50 ms with proposed batching |
| Ticket checks | Recompute binding factors and nonce points | 32 equivalents = 1.60 ms |
| TEE intent checks | Check 16 implied constant terms | 48 equivalents = 2.40 ms |
| Arithmetic subtotal | 216 equivalents, or 158 with batching | 10.80 ms or 7.90 ms |
| Combiner | Check 14 committee partials and the final signatures | About 2.10 ms plus final verification |
| Background replenishment | 16 slots × 137 equivalents | 109.60 ms, or roughly 54.80 ms with proposed batching |
| Ordering through broadcast | Five listed board commits, peer rounds, local work | 5–6 s + F_M |
| Non-TEE proof | Ticket relation, authorization, final wrap | No complete measurement |

Non-TEE Schnorr admission omits the 48-equivalent TEE constant-term check. Its arithmetic subtotal is approximately 5.5–8.4 ms before the omitted costs. It instead depends on a valid ticket proof.

The nonce cost dominates sustained CPU consumption. With the design's unbatched pool, a node spends approximately 118–121 ms per 16-ticket request, even when slots are ready before the request arrives. Moving work offline removes latency, not resource demand.

The per-slot board payload is:

    P(n,t) = 33t + 32n
    slot_bytes = 2t · P(n,t)

This gives 7,266 bytes per slot at launch and 22,560 bytes at n = 17. A launch request consumes 116,256 bytes of slot dealings before counting proofs, post signatures, or consensus replication. Its 16 KiB envelope is the smaller component.

At n = 17, a 16 KiB frame supports m ≤ 10 under the current single-holder layout. Comparing its ten tickets with launch's sixteen without stating the change misreports scaling.

### Security baseline

Every optimization retains the actual hypotheses of DESIGN §9.1. C5 and C14 remain open, ECDSA retains O1/O2, and a faster implementation does not upgrade a sketch to a proof.

The §9.2 table overstates C8 when it lists secrecy before order as surviving t or more broken enclaves. A coalition holding t dealing keys reconstructs the outer key. The usable guarantee is C8's explicit bound, fewer than t corrupt nodes. Performance estimates do not rely on the stronger sentence.

The multi-shard extension also needs a composition proof. Decisions 21–25 specify its access structure and signing sequence, but the single-holder claims do not automatically prove the arbitrary-actor construction.

## 3. Ranked optimizations

### 1. Replace general Feldman evaluation with small-integer arithmetic and cache it

**Mechanism.** For commitments C₀ through Cₜ₋₁, compute:

    V = Cₜ₋₁
    for k = t−2 down to 0:
        V = [i]V + Cₖ
    accept share sᵢ exactly when [sᵢ]G = V

Committee coordinates are i = 1,…,n. Implement multiplication by i with a short, fixed addition chain selected by this public index. For i = 9, compute [9]V = [8]V + V. This uses three doublings and one addition. It does not need a 256-bit scalar routine.

For n ≤ 9, binary chains need at most five additions or doublings per Horner step, including Cₖ. For n ≤ 17, the bound is seven. A degree-six evaluation therefore needs at most 30 elementary group operations. A degree-eleven evaluation needs at most 77. At i = 1, evaluation is just a sum.

Cache V for each immutable commitment vector and recipient. Cache the committee root's X_f,i once per epoch and D_ℓ,i and E_ℓ,i when a slot becomes qualified. Cache ECDSA W_f,i and M_f,i at slot creation. Cache interpolation weights for the exact ordered subset.

Use an explicit constant-time fixed-base routine for secret [sᵢ]G. Ed25519's documented precomputed basepoint path offers about a fourfold improvement over its corresponding unprecomputed path. The prototype's generic G * share expression does not establish that it selects that path. [Dalek documentation](https://docs.rs/curve25519-dalek/4.1.3/curve25519_dalek/)

**Gain and derivation.** An illustrative primitive model assigns 15 μs to fixed-base multiplication and 0.25 μs to an addition or doubling. The algebraic part of a share check becomes approximately:

- Launch: 15 + 30 × 0.25 = 22.5 μs.
- n = 17: 15 + 77 × 0.25 = 34.25 μs.

Point decoding, hashes, and validation remain. Budget 50–100 μs per complete launch inner check, or 0.8–1.6 ms for sixteen. This replaces the design's 3.5–6.4 ms inner-check allocation. The precise ratio depends on the curve and processor.

Ticket recomputation also needs only one full scalar multiplication, [ρ]E, plus additions. Applying σ = ±1 uses point negation. It does not require another full multiplication.

**Security.** This is an exact group identity. It changes no acceptance predicate or message. C1–C16 retain their existing status. Cache keys include the suite, epoch, key-list hash, commitment digest, recipient coordinate, and slot or request identity. A ticket-dependent cache also includes its complete binding transcript. A cache hit never substitutes for current authorization, hold, expiry, or slot checks.

The small-index branch is public. Field formulas must remain constant-time when their point operands are private to an enclave.

**Implementation cost.** Low to medium. Add a small-index group routine, typed validated commitments, fixed-base calls, and bounded caches. Check equality with the current implementation for every launch and later committee index, including identity intermediates.

### 2. Build a continuously replenished, batched slot factory

**Mechanism.** Each qualified dealer creates chunks of 32–256 independent two-polynomial slots. One immutable chunk transcript amortizes framing, authentication, and the dealing encryption setup. Every polynomial keeps its own pad label and independent coefficients. Preserve the first-t qualified-dealer rule and the existing complaint qualification.

Apply optimization 1 to each received share and to the aggregate commitment evaluations. Add each dealer's commitments coefficient by coefficient once. Build the per-recipient public nonce caches once per completed slot.

Keep a bounded ready pool. Its low-water mark satisfies:

    ready_slots ≥ peak_requests_per_second · m · refill_tail_seconds
                  + burst_reserve

Count all reserved, exposed, aborted, and unselected slots as consumed where nonce hygiene requires it. Schnorr shares stay in RAM. The pool survives an ordinary node loss through the specified repair mechanism, not by writing nonce shares to disk.

**Gain and derivation.** Launch checks 2t = 14 received nonce shares per slot. Its coefficient arrays contain 2t² = 98 points. Using the primitive model above, cached evaluation, amortized proof/DH work, and a 5–10 μs planning allowance per decoded secp256k1 point gives a **1.5–2.5 ms** slot-production target per node.

At n = 17, there are 24 share checks and 288 coefficient points. The corresponding target is **3–5 ms per slot**. These are complete factory budget targets, including an allowance for the node's own dealing work. They require measurement under continuous refill.

The fixed chunk setup cost falls from C_setup per slot to C_setup/B. The ciphertext and coefficient payload remains linear in B. A 32-slot chunk removes 31 of 32 repeated setup costs, not 31 of 32 total slot costs.

**Security.** Preserve independent polynomials, two nonces, one transcript per use, qualified-dealer selection, complaints, erasure, and recovery exclusions. These retain the premises of C3, C5, C8, C9, C12, C14–C16. Chunking needs an explicit extension of the encryption transcript argument in PROOFS Theorem C. It must bind every ciphertext and slot label before the proof is accepted.

Do not reduce the dealer count to f+1. That changes the distribution and corruption argument behind C5's stated t−1 exposure bound.

**Implementation cost.** Medium. Add a chunk scheduler, bounded pool, worker allocation, and failure isolation. Measure slots produced per CPU-second and board bytes per slot, including aborted chunks.

**Sources.** The local slot construction supplies the arithmetic and qualification rule. [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) supplies the two-nonce preprocessing and deletion requirements.

### 3. Reduce board waits while retaining committed order and release gates

**Mechanism.** Keep three ordered transitions on the normal path:

1. **ORDER.** Commit the envelope with a final ordering QC.
2. **ADMIT.** Commit a bundle containing the outer ACK certificate, a common header hash, and q admission attestations.
3. **ANCHOR.** Commit the generation's deterministic selection and the required release authorization record.

After ORDER, nodes exchange signed ACKs directly. A certificate of q distinct ACKs authorizes the outer-share exchange without a dedicated ACK block. Nodes still wait for the ordering QC and the required witness evidence. After opening and checking, each node signs a statement that includes both the header hash and its admission result. The ADMIT block records those certificates and claims slots atomically in board order.

For non-TEE mode, encode the existing RELEASE authorization in the anchor transition where its predicates are already fixed. For TEE mode, collect the required release witnesses after the complete release digest is known. Retain a separate round whenever a prerequisite is unavailable.

Pipeline different requests through these stages. A slow actor or proof for one request does not stop unrelated ready requests. Use a bounded batch timer rather than waiting indefinitely for a full batch.

**Gain and derivation.** Removing the ACK block and separate OPENED block saves two commit intervals. At one second per commit, the target is approximately 3.1 seconds after authorization availability, instead of 5–6 seconds.

Ciphertext ordering can overlap Midnight finality if the eventual authorization reference is already fixed and validated before use. Keep opening shares gated on final authorization in this conservative variant:

    old latency ≈ F_M + 5T_B + peer_work
    revised latency ≈ max(F_M, T_B) + 2T_B + peer_work

This saves 2T_B plus min(F_M,T_B). Add proof preparation before submission, actor response time, and host confirmation separately. A charter requiring anchor_before_release retains its additional finality wait.

**Security.** C8 requires a committed order, not a speculative proposal or an arbitrary prepare QC. C6/C7 still require final matching authorization and a fresh hold check before release. C9/C11/C12 retain the anchored variant, pin, nullifier, and atomic slot claims. C13 needs a state-machine refinement proof that certificate bundles reproduce the logical transitions and preserve complaint handling, expiry, and view changes. The other claims' cryptographic premises are unchanged.

**Implementation cost.** Medium to high. The bundle format and state transitions change. Retain the current separate-record path as a fallback, with identical ordering and slot-consumption rules. HotStuff supports pipelined consensus, but its throughput pipeline does not make a proposal immediately final. [HotStuff paper](https://arxiv.org/abs/1803.05069)

### 4. Aggregate verified outside contributions before committee release

**Mechanism.** Let p_j,v be actor j's sharing of its already weighted contribution for ticket v. For a threshold group, fix its chosen subset before the challenge. Apply its Lagrange weights exactly once, according to the signing convention.

Each committee node verifies and retains actor-specific evidence, then computes:

    p_A,v(i) = Σⱼ p_j,v(i)
    C_A,v,k = Σⱼ C_j,v,k

Capsule encryption constrains aggregation. The single-holder format derives its capsule key from that holder's contribution. An initiator cannot encrypt under an unknown aggregate scalar before the other actors respond. Preserve the initiator's capsule-key share separately and sum the remaining actors' shares. The committee releases those two outside shares plus its committee partial. At a = 1 it retains the original two-scalar release. Preserve individual evidence until completion so a failed contribution remains attributable.

A format with an independently available capsule-opening mechanism can release the entire outside sum once. That format needs its own construction and proof. The estimates here retain the existing contribution-derived capsule key and do not credit that further compression.

Compute the canonical actor-and-nonce transcript once per ticket. Hash its encoding once, then derive each actor's binding factor from that digest, actor identifier, message commitment, and context. This avoids rehashing the full actor list for every actor. Compute the aggregate nonce with an MSM over the actor nonce commitments.

**Gain and derivation.** Interpolation and release for outside contributions fall from a independent scalar vectors to two when a ≥ 2. With a = 8 and L = 2, outside scalars fall from 512 to 128 bytes per sender. Including the two committee partials, scalar payload falls from 576 to 192 bytes, a 3× reduction. Signature and transport overhead is additional.

At admission, a·m separate dealings still arrive and require validation. With m = 16, a = 8 and n = 9, their commitments and encrypted shares alone occupy:

    8 · 16 · 519 = 66,432 bytes

This already exceeds 64 KiB before tickets and framing. Aggregation after receipt does not compress that inbound traffic.

Treat the actors' messages as separately sealed, padded contribution frames committed to one session manifest. The extension needs this transport definition. Arbitrarily many actors cannot fit inside the original 16 KiB envelope. Actor count, frame count, timing, and network origin require an explicit leakage policy and suitable padding or relaying.

**Security.** Linearity preserves Shamir degree and the aggregate signature equation. It does not prove that each required actor contributed. Bind the access structure, chosen subset, actor keys, nonce commitments, generation, tickets, and contribution digests. Keep birth proofs of possession for all applicable shard keys. C1–C5 and C10 require the multi-actor composition proof. C6–C9 and C11–C16 retain their gates and assumptions.

An initiator must not collect plaintext outside halves before dealing them onward. That adds an early reconstruction party and changes the secrecy boundary. An actor replacement starts a fresh generation and uses fresh slots.

**Implementation cost.** High for the new multi-shard protocol, low for local summation once actor-specific dealings exist. [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) specifies canonical commitment lists, binding factors, and interpolation, and warns against an optimization that loses signer-set agreement.

### 5. Optimize the actual proof relation, then its hash computation

**Mechanism.** Specify the complete ticket relation before adopting the 2²⁰ wrap budget. DESIGN §5.3 includes:

    R = R_u + D + [ρ]E

For multiple actors, it includes the corresponding aggregate nonce. A hash AIR alone cannot establish this elliptic-curve equation, its parity, or the relationship between an address and its certified key. Prove these relations inside constrained arithmetic or connect a separately verified relation to the same hiding commitments. Merely accepting witness-supplied R is insufficient.

Use a specialized SHA-256 AIR with lookup-assisted bit operations. Build a shared computation graph for identical prevouts, amounts, scripts, sequences, and tagged-hash prefixes. Compute outputs separately when the change amount varies. Reuse a computed value only when constraints bind every consumer to that same value. BIP341 explicitly permits caching transaction subhashes. [BIP341](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341.mediawiki)

Use KoalaBear with a properly sized extension field and Poseidon2 as the first STARK implementation target. Its 31-bit arithmetic suits the hash workload and supported SIMD paths. Compare its complete wrap cost against Goldilocks before fixing the backend. Field conversion, range checks, and non-native curve arithmetic belong in that comparison. Plonky3 supplies these field families, NEON paths for the 31-bit families, batching, and proof-system components. [Plonky3](https://raw.githubusercontent.com/Plonky3/Plonky3/main/README.md)

Keep SHA-256 for Bitcoin's mandated hashes, SHA-512 for Ed25519, and Keccak-256 for Ethereum. Use Poseidon2 for internal proof commitments where its parameters and encoding receive a security analysis. It changes those cryptographic assumptions and transcript definitions. Its published improvement over Poseidon is not an end-to-end speedup for this application. [Poseidon2](https://eprint.iacr.org/2023/323)

**Gain and derivation.** Starting with the design's rough 15 compressions per ticket gives 240 for m = 16. If four compression-equivalent subcomputations are identical across all tickets, sharing gives 16·11 + 4 = 180. Eliminating two additional fixed-prefix compressions per ticket gives 148. The reduction is 25–38%, or 1.3–1.6× for that hash work.

The design calls this a “16-variant” request, but K = 8 and L = 2 means eight variants and sixteen tickets. Some work is per transaction, some per input. The final AIR must count both explicitly.

The original hash trace estimate is approximately 2¹⁸ rows. Saving 25–38% does not necessarily cross the next power-of-two padding boundary. Trace width and the omitted curve relation can dominate.

**Authorize and aggregation.** Prove an asset path and charter checks once per request, then bind all tickets to that intent. Keep one public circuit interface and fixed maximum ticket shape. Private selectors must enforce every applicable predicate without exposing profile, suite, actor subset, or variant count through verifier-key selection.

Use Compact's circuit-efficient transientHash for internal consistency checks where appropriate. Keep persistent hashes or commitments for durable identifiers and state. The runtime documents that transient hashes can change across upgrades. [transientHash](https://docs.midnight.network/api-reference/compact-runtime/functions/transientHash), [persistentHash](https://docs.midnight.network/api-reference/compact-runtime/functions/persistentHash)

Aggregate completed request proofs before one final BLS12-381 wrap. Each request still needs a distinct nullifier, intent binding, and hold handle. For B requests:

    amortized proof cost = T_leaf + (T_aggregate(B) + T_wrap)/B

The fixed wrap component improves B-fold. Total proving work does not. Batch submission alone adds no cryptographic aggregation. Folding is useful only with a proved accumulator and final decider for this relation.

**Device budget.** No defensible total seconds figure exists without the AIR, wrapper, and target-device benchmark. For scale, a 2¹⁸-row, 64-column trace with blowup eight and four-byte field elements has a 512 MiB expanded-field array alone. Other arrays and the wrapper add memory. Use a trusted companion for devices that exceed their memory budget. Sending plaintext witnesses to an ordinary remote prover changes privacy.

**Security.** C6 and C10 require soundness, zero knowledge, exact public-input binding, and uniform public shape across all proof layers. C1–C5 need the address and signature relations actually proved. Other claim mechanisms remain unchanged. O4 stays open until the full relation, including the wrapper, meets the cap.

**Implementation cost.** High. Record AIR rows, width, lookup tables, extension degree, soundness error, wrapper constraints, peak memory, and wall time separately. The 2²⁰ target and 2²¹ cap concern the final wrap's constraints in DESIGN §11.4, not an interchangeable count of STARK rows.

### 6. Batch public verification with random weights and bounded failure recovery

**Mechanism.** Freeze a batch of validated equations E_r = O. Draw independent nonzero random scalars α_r after the inputs are fixed. Check:

    Σᵣ [αᵣ]Eᵣ = O

For Feldman shares with a common base:

    [Σᵣ αᵣsᵣ]G = Σᵣ [αᵣ]Vᵣ

The aggregated scalar on the left remains secret. Compute it and its base multiplication in constant time. Use variable-time MSM only for operands whose disclosure is allowed to the observer of that machine.

Apply batching chiefly to post signatures, public proof equations, actor checks, and partial verification. Benchmark individual fixed-base Feldman checks after optimization 1. Adding a random full-width multiplier to every cached V_r can cost more than those checks.

Use Straus for small public MSMs and Pippenger for large batches. libsecp256k1's current internal implementation switches at 88 points. Treat that as a source-code tuning point, not a portable optimum. [libsecp256k1 MSM implementation](https://raw.githubusercontent.com/bitcoin-core/secp256k1/master/src/ecmult_impl.h)

On failure, split the batch, then verify failing leaves individually. A failed aggregate is not a complaint proof and does not identify a bad actor. Bound batch size and failure work to prevent one invalid request from stalling unrelated requests.

**Gain and derivation.** Target 2–4× for sufficiently large public verification batches, subject to the measured crossover. The measured t = 7 post-check allocation is 1.35 ms. Fourfold acceleration saves approximately 1.01 ms.

A complementary exact optimization signs one node's canonical vector of posts per batch. At B = 16, the signature count for those vectorized posts falls by up to 16×. Per-entry parsing, distinct-signer counting, and state validation remain. QC verification is also amortized over the block's requests.

**Security.** For prime-order groups, a fixed invalid set passes a fresh full-field random combination with probability at most about 1/r, where r is the group order. Across T trials, charge T/r to the relevant claims. This is a new quantified soundness term, not an exact equivalence. Do not use 64-bit weights.

Keep all point, subgroup, scalar-range, and signature encoding checks. Use independent weights for distinct equations of a proof. C1–C12 retain their intended security level after accounting for the bound. Bounded fallback preserves C13. State, rotation, and recovery rules remain unchanged.

**Implementation cost.** Medium. Keep a deterministic individual-verification path. Never perform secret-key decryption before successful public-proof verification. [BIP340 batch verification](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340.mediawiki), [Bellare–Garay–Rabin](https://eprint.iacr.org/1998/007)

### 7. Amortize encryption and retain the 196-byte proof

**Mechanism.** For one sender, recipient, envelope, and suite curve, compute sk_i·E once. Reuse that DH value with distinct per-polynomial pad labels. The base prototype already does this in Accepted::decrypt. Preserve it when adding outer and inner split dealings. Cross-curve use requires separate curve-specific keys and DH values.

Cache registered epoch-key validation and immutable transcript encodings. At an actor or slot dealer, precompute tables for public recipient keys only when repeated use amortizes their construction. Secret ephemeral multipliers require constant-time table access.

Deduplicate complaints by immutable dealing identity, recipient, and failed component. Carry one correctly bound DLEQ decryption proof plus the affected indices when the same DH value authenticates them. Verify each alleged failed share. Aggregate transport, not the evidence needed to justify VOID.

**Gain and derivation.** The 196-byte proof occupies 1.20% of a 16 KiB frame. Removing it does not reduce that padded frame at all. Its verification is worth batching, its size is not the primary target.

Replacing m identical DH computations with one saves (m−1) general multiplications, 0.75 ms at m = 16 under the design's cost unit. This is a regression to avoid: the measured base code already shares DH computation.

**Security.** PROOFS Theorem C binds the ephemeral-key proof to the ciphertext hash specifically to stop complaint-oracle reuse. Keep that binding, the authorship proof, and unique pads. C3/C8/C9 depend on it.

The split format also needs an explicit acyclic transcript schedule. Its final hd covers ciphertexts, while the base pad construction takes a pre-encryption dealing digest. Do not feed the final ciphertext-containing hd back into the pads that create those ciphertexts. Specify separate domain-separated pre-encryption context and final commitment, then check the encryption reduction.

Retain explicit inner constant commitments in non-TEE Schnorr mode because nodes cannot derive them from a hidden address. Replacing Feldman coefficients with KZG or an inner-product commitment adds a different proof system, assumptions, and opening costs. At t = 7 or 12, retain Feldman.

**Implementation cost.** Low for caching and transport deduplication, medium for the split transcript specification. No byte-saving estimate assumes a smaller public frame.

### 8. Vectorize ECDSA birth and refill, with a strict functionality boundary

**Mechanism.** Use malicious-secure OT-based multiplication as the first implementation path for O1/O2. DKLs23 provides a three-round threshold-signing construction and a two-round vectorized multiplication primitive. It does not directly certify the exact Shamir outputs and base-R commitments required here. [DKLs23 abstract](https://eprint.iacr.org/2023/765)

Batch the 32-slot session across each wallet-node pair. Amortize reusable base-OT setup where the chosen protocol permits it. Give each extension batch a fresh session identifier and retain malicious consistency checks. Select silent OT only after its concrete security parameters, reusable state, and crossover beat conventional OT extension for this workload.

For one outside holder, the design requires:

    3 · 32 · n = 864 F_mul calls at n = 9
    3 · 32 · n = 1,632 F_mul calls at n = 17

Each wallet-node pair handles 96 products. Those are a vectorized workload. They are not 96 base-OT setups.

Run committee presigning before wallet arrival where its inputs allow it. A slot enters the usable pool only after the required recovery-group acknowledgments. Refill before the remaining slots fail to cover the next complete fee grid and refill delay. At K·L = 6, a 32-slot pool supports only five complete P2WPKH requests before exhaustion.

**Gain and derivation.** If per-session setup accounts for fraction p of an unbatched cost, batching 32 slots gives:

    speedup = 1 / ((1−p) + p/32)

At p = 0.8 this is 4.44×. At p = 0.2 it is 1.24×. These are sensitivity calculations, not measured DKLs23 results. O1/O2 prevent a credible absolute birth-time estimate.

**Alternatives.** Keep CGGMP21 presigning as a comparison implementation. Its API supports non-interactive issuance from a presignature and explicitly forbids reuse. [CGGMP21](https://docs.rs/cggmp21/latest/cggmp21/signing/struct.Presignature.html)

Do not substitute an honest-majority protocol solely because its abstract reports 1.3 ms per presignature. That model does not establish C5 against an owner plus t−1 exposed committee shares. [Katz–Urban](https://eprint.iacr.org/2024/2011)

The two-round, one-OLE result concerns two-party ECDSA. It is a useful comparison for a two-party boundary, not an implementation of arbitrary-actor threshold custody. [Adjedj et al.](https://eprint.iacr.org/2024/1950)

For a outside actors, joint presigning must produce all required additive components without reconstructing the key. A generic pairwise construction has up to O((n+a)²) communication relationships. A claimed O(an) star construction needs its own proof. Non-interactive online signing does not remove the joint birth or refill session.

**Security.** C1–C5, C12, C14–C16 remain conditional on O1/O2 and the required recovery behavior. No speedup changes the threshold, discards multiplication checks, or reuses correlations outside their proved lifetime. The other release and privacy gates remain.

**Implementation cost.** High. Prove and test the exact functionality boundary before importing library throughput figures. The available [DKLs23 implementation](https://raw.githubusercontent.com/silence-laboratories/dkls23/main/README.md) supplies an implementation starting point, not this composition proof.

### 9. Batch witness durability and reuse attested peer channels

**Mechanism.** Verify attestation at boot, admission, and key changes. Reuse authenticated peer channels during the epoch, with current boot fencing. Keep request secrets in RAM. SEV-SNP protects a whole VM, so the main request costs are network and guest I/O, not an assumed SGX-style transition for each curve operation.

Batch witness entries into an authenticated vector or root. Each peer validates the individual keys and digests and durably commits the batch before acknowledging it. Every output waits for the required w distinct peer acknowledgments. Group commit amortizes fsync without making acknowledgment precede durability.

Attach witness requests and acknowledgments to existing peer traffic when their prerequisites match. An open witness includes the committed ordering position. A release witness includes the complete selected variant and ticket digest.

**Gain and derivation.** With B entries per durable write, the per-entry write overhead is approximately fsync_time/B. At B = 32, that component falls 32×. Piggybacking targets up to the two 20 ms witness round trips in DESIGN §11. It does not remove board or Midnight finality.

**Security.** Preserve w = 6 launch peers and w = 11 later peers. A launch QC of six signers can include the releasing node, leaving only five peers. At n = 17, requiring q = 12 peer acknowledgments exceeds the eleven honest peers guaranteed to a node.

An ordinary QC proves neither that the required peers recorded this node's digest nor that they made it durable. Piggybacked signatures must explicitly attest those facts. Keep the stated witness bound of four colluders at launch and six later, the replay floor, and anchor_before_release. These preserve C6/C7/C12/C16 and the TEE premises of the other claims.

**Implementation cost.** Medium. Test crash-before-fsync, crash-after-ack, stale boot keys, and replay during log compaction. Peer-assisted rollback protection has precedent in [ROTE](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic), but its theorem does not substitute for this witness protocol's counting argument.

### 10. Offer smaller fee grids as an explicit service choice

**Mechanism.** Keep K = 8 available for Bitcoin P2TR, and offer K = 4 for users who accept coarser fee selection. Continue using K = 1 for Ethereum where the chosen ceiling and tip meet the intended service. A cap alone does not guarantee inclusion during congestion. [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)

**Gain and derivation.** Reducing K from eight to four at L = 2 halves inner dealings, tickets, and slot consumption. Launch slot payload falls from 116,256 to 58,128 bytes. Under the revised factory budget, replenishment falls from 24–40 to 12–20 ms per node.

For a fee span r_max/r_min = 8, a geometric grid's ratio is:

    γ = (r_max/r_min)^(1/(K−1))
    K = 8: γ ≈ 1.346
    K = 4: γ = 2

The four-point grid therefore has worse fee granularity. Keep the fee ceiling, replacement validity, pinned inputs, and all signature checks.

**Security.** The admitted message set shrinks. C1–C12 and C14–C16 retain their premises. C13's useful service range changes because fewer fee choices remain. This is a user-visible tradeoff, excluded from the like-for-like revised table.

**Implementation cost.** Low. Keep public frame size and public proof shape unchanged, so choosing fewer variants does not identify the request class.

### 11. Use optimistic combination with deterministic fallback

**Mechanism.** After all release gates, collect t distinct canonical shares. Interpolate, open only the selected capsule, assemble the signature, and verify it independently against the actual transaction and prevouts. On failure, check cached individual share equations, reject bad contributors, and collect replacements.

The base prototype already takes this optimistic approach in SigningPackage::combine. Split-line dealing can carry it forward. A failed AEAD opening also triggers share diagnosis.

**Gain and derivation.** The honest path avoids t individual committee-partial checks per input. The design allocates 42 scalar multiplication equivalents, or about 2.1 ms, at launch with two inputs. Independent final signature verification remains. The revised table includes this saving.

**Security.** Final verification must use the committed transaction context, not merely a public key supplied by the combiner. All authorization, hold, selection, and one-use checks happen before release. C3–C12 retain those gates. C13 depends on bounded diagnosis and replacement, not repeated blind interpolation of every possible subset. C1/C2 and C14–C16 are unaffected.

**Implementation cost.** Low to medium. Preserve actor-specific evidence until fallback and completion. This changes error-detection order, not which signatures can be broadcast.

### 12. Specialize libraries and hardware after removing redundant work

Use libsecp256k1 for supported secp256k1 verification and secret scalar operations, retaining k256 as a differential reference. Its implementation includes fixed-base methods, endomorphism acceleration, and specialized verification arithmetic. Generic MSM internals are not a promised stable public API. A custom binding to them needs a pinned version and review. [libsecp256k1](https://github.com/bitcoin-core/secp256k1)

Keep curve25519-dalek for Edwards arithmetic. Represent validated subgroup points with a type that preserves that invariant under addition and scalar multiplication. Check each new wire point strictly once. Do not rerun a subgroup multiplication merely to serialize a value whose provenance already proves membership. Still check identity wherever the protocol forbids it. The pinned 4.1.3 SIMD backend targets x86 AVX2/AVX-512, so do not apply those speedups to the aarch64 benchmark machine. [Dalek](https://docs.rs/curve25519-dalek/4.1.3/curve25519_dalek/)

Use blst for BLS12-381 primitives where the selected wrapper needs them. It does not accelerate secp256k1 or implement the entire Midnight verifier. [blst](https://raw.githubusercontent.com/supranational/blst/master/README.md)

Send large public MSMs or authorized proving workloads to a GPU only after measuring transfer, launch, and queueing costs. Keep request shares, DH scalars, nonce material, and private proof witnesses inside their authorized trust boundary. An ordinary host GPU is outside the specified SEV-SNP confidentiality boundary. ICICLE documents batch size, window, memory, and precomputation tradeoffs, not a universal speedup for small request MSMs. [ICICLE](https://dev.ingonyama.com/2.8.0/icicle/primitives/msm)

**Gain and cost.** Assign **zero additional hardware multiplier** to the revised table. Benchmark before crediting one. Implementation cost is medium for library integration and high for a confidential accelerated prover.

**Security.** C3/C5/C8–C10 require secret-independent execution and the same validation semantics. In TEE mode, even ticket scalars and points can be private from the operator. A variable-time routine is acceptable only after an explicit leakage analysis for that operand set. The remaining claims keep their state and quorum rules.

## 4. What not to do

| Shortcut | Claim or premise it breaks |
|---|---|
| Release outer shares on a proposal, prepare certificate, or leader promise | C8 requires committed order. A speculative branch can expose a request that never gets that position. |
| Treat q votes as t secret shares | Launch q = 6 and t = 7 are different thresholds. Certificate compression does not change reconstruction. |
| Reduce t for a faster signer set | Changes C5, C8, C9, and the custody policy. |
| Replace all Feldman checks with an unweighted sum | Invalid shares with cancelling errors pass. Random batching needs a soundness bound and fallback. |
| Share one polynomial's nonconstant coefficients across variants | A recipient learns differences of constant terms. Revealing one selected value can reveal unselected values, violating C9. |
| Reuse a nonce after expiry, failure, a fee bump, or an actor-subset change | Violates C12 and can expose key material. A new subset means a new binding transcript and fresh slots. |
| Replace two nonces with one or omit actors from the binding transcript | Removes the stated concurrent-session protection and signer-set binding behind C3/C5. |
| Remove the ciphertext-bound ephemeral proof to save 196 bytes | Reintroduces the complaint-oracle attack excluded by PROOFS Theorem C. |
| Skip Edwards subgroup checks or substitute cofactor clearing at ingress | Changes accepted inputs and invalidates the prime-order proof premises. Caching a completed check is safe. |
| Use P0 as a faster P1/P2 path | P0 has different custody and enforcement guarantees. |
| Publish actor identities, request-specific roots, or raw R values to simplify proof verification | Can weaken C10 and cross-chain unlinkability beyond the stated leakage. |
| Replace a mandatory chain hash with Poseidon2, or accept an unconstrained sighash witness | Changes the signed message relation and breaks authorization binding. |
| Assume a STARK is zero knowledge without masking, or that recursion supplies privacy automatically | Can expose the private intent, charter, or actor set. |
| Acknowledge witnesses before durable commit, or keep a stale P2 hold result | Weakens rollback protection or C7. |
| Recycle RAM-lost slots from a stale checkpoint | Risks nonce reuse after cold start. Burn every ambiguous slot and preserve the recovery exclusions. |
| Claim throughput using an empty slot pool's warm-path benchmark | Omits the dominant recurring CPU and board cost. |
| Replace Feldman with pairing commitments because their commitment is shorter | Adds assumptions and opening proofs without establishing a win at these small thresholds. |

## 5. Revised cost table

The following table budgets one outside holder, BIP340, two inputs, and the same fee grids as stated. It combines exact arithmetic changes, chunked slot production, amortized certificates, and optimistic combination. It does not credit smaller grids, a GPU, a blanket library speedup, or an unproved proof-time reduction.

The online allocation includes outer/public checks, inner checks, ticket and TEE checks, and a modest allowance for certificates and final combination. It excludes host RPC stalls, storage latency, and user proving. The slot allocation is CPU work performed continuously in the background.

| Quantity | Launch: n = 9, t = 7, K = 8, L = 2 | Later: n = 17, t = 12, K = 5, L = 2 | Later comparison: n = 17, t = 12, K = 8, L = 2 |
|---|---:|---:|---:|
| Tickets m | 16 | 10 | 16 |
| Envelope size class | 16 KiB | 16 KiB | 64 KiB, subject to O7 |
| Inner dealing | 519 B | 940 B | 940 B |
| Original online arithmetic, unbatched | 10.8 ms | 9.65 ms, derived | 15.05 ms, derived |
| Revised online CPU target | **4–6 ms** | **4–7 ms** | **6–10 ms** |
| Revised slot CPU per slot | **1.5–2.5 ms** | **3–5 ms** | **3–5 ms** |
| Revised replenishment per request | **24–40 ms** | **30–50 ms** | **48–80 ms** |
| Revised online + replenishment | **28–46 ms** | **34–57 ms** | **54–90 ms** |
| CPU-only sustained ceiling, one fully utilized core per node | **22–36 requests/s** | **18–29 requests/s** | **11–19 requests/s** |
| Projection: 16 cores, 80% utilization | **278–457 requests/s** | **225–376 requests/s** | **142–237 requests/s** |
| Slot-dealing payload per request | 116,256 B | 225,600 B | 360,960 B |
| Envelope + slot payload, lower bound | 132,640 B | 241,984 B | 426,496 B |
| Normal board path after authorization is available | **3 commits + peer work** | **3 commits + peer work** | **3 commits + peer work** |
| One-second-commit latency target | **≈3.1 s** | **≈3.1 s**, same network assumption | **≈3.1 s**, same network assumption |
| Peer witnesses per emitting node | 6 | 11 | 11 |
| Non-TEE complete proof time | O4 measurement required | O4 measurement required | O4 measurement required |
| Final wrap budget | Target ≤2²⁰ constraints, cap 2²¹ | Same obligation | Same obligation |

The later online arithmetic uses:

    operations = (t+1) + m·(t+1) + 2m + 3m
               = t+1 + m·(t+6)

It is an extrapolation of the design's count, not a measured n = 17 result. For slot production, a rough unchanged-implementation extrapolation is 6.85·(12/7)² ≈ 20.1 ms per slot. This illustrates the danger of retaining quadratic repeated evaluation. It is not needed to justify the revised targets.

The launch total of 28–46 ms corresponds to 1,000/46 through 1,000/28 requests per second per core. The multicore projection multiplies by 12.8 effective cores. It assumes sufficient parallelism and ignores shared memory-bandwidth limits.

Actual sustained throughput is bounded by:

    min(node CPU capacity,
        ready-slot production rate / m,
        board payload capacity / bytes per request,
        Midnight authorization capacity,
        actor contribution capacity,
        host-chain inclusion capacity)

For example, 100 requests/s at launch requires at least 13.26 MB/s of unique envelope and slot payload. At n = 17 and m = 10, it requires 24.20 MB/s. Both exclude consensus replication, certificates, proof overhead, and actors' extra frames.

For multiple actors, retain the committee slot cost once per ticket. Add approximately a·m inner dealings and their validation before local aggregation. A rough launch planning increment is (a−1)·m·(0.05–0.10 ms) for additional Feldman checks alone. Actor proof checks, nonce computation, decoding, and ingress are additional. Completion latency includes the slowest required actor, not the sum of actors' response times. An AND policy cannot bypass an absent required actor.

Measure the next implementation with continuous refill enabled, all three curves, both committee sizes, both modes, and a = 1, 4, 8. Report online CPU separately from total CPU. Inject an invalid contribution, a withheld share, a witness restart, and an exhausted pool. Accept the three-commit path only after its state-machine checks preserve order, authorization, hold freshness, slot uniqueness, and fallback liveness.

## 6. Sources

### Local protocol and implementation

- [DESIGN.md](design/enhancement/DESIGN.md): split algebra, envelopes, claims C1–C16, witness bounds, and original cost estimates.
- [DECISIONS.md](design/enhancement/DECISIONS.md): decisions 21–25, arbitrary outside actors, access structures, fixed signer subsets, and joint ECDSA presigning.
- [SCHEME.md](design/SCHEME.md): base dealing, transcript labels, public validation, complaints, anchors, and optimistic combination.
- [PROOFS.md](design/PROOFS.md): ciphertext binding, complaint security, prime-order requirements, corruption bounds, nonce accounting, and restoration conditions.
- [BENCHMARKS.md](impl/BENCHMARKS.md): measured microbenchmarks, hand-timed CPU, simulation scope, and omitted production costs.
- [algebra.rs](impl/src/algebra.rs), [signing.rs](impl/src/signing.rs), [message.rs](impl/src/message.rs), [ed25519.rs](impl/src/ed25519.rs), and [Cargo.toml](impl/Cargo.toml): actual evaluation, verification, DH reuse, subgroup checks, and pinned libraries.

### Public sources opened

1. [libsecp256k1](https://github.com/bitcoin-core/secp256k1): specialized secp256k1 implementation and API scope.
2. [libsecp256k1 ecmult implementation](https://raw.githubusercontent.com/bitcoin-core/secp256k1/master/src/ecmult_impl.h): Straus/Pippenger dispatch, scratch-space behavior, and the current 88-point threshold.
3. [curve25519-dalek 4.1.3](https://docs.rs/curve25519-dalek/4.1.3/curve25519_dalek/): fixed-base tables, supported backends, and the x86-specific SIMD limitation.
4. [BIP340](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340.mediawiki): exact Schnorr verification and random-coefficient batch verification.
5. [BIP341](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341.mediawiki): mandatory sighash fields and reusable transaction subhashes.
6. [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html): Ed25519 hash and encoding requirements.
7. [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html): nonce handling, canonical signer lists, binding-factor computation, interpolation caching, aggregation, and the signer-set optimization warning.
8. [Bellare, Garay, Rabin, Fast Batch Verification](https://eprint.iacr.org/1998/007): probabilistic verification framework. The concrete residual bound above is derived directly for prime-order groups.
9. [HotStuff](https://arxiv.org/abs/1803.05069): partially synchronous responsive consensus and pipeline context.
10. [DKLs23, Threshold ECDSA in Three Rounds](https://eprint.iacr.org/2023/765): abstract establishing the malicious-security setting and vectorized multiplication construction. No detailed theorem from its PDF is used.
11. [Silence Laboratories DKLs23 README](https://raw.githubusercontent.com/silence-laboratories/dkls23/main/README.md): available implementation, setup structure, and benchmark entry points.
12. [CGGMP21 presignature API](https://docs.rs/cggmp21/latest/cggmp21/signing/struct.Presignature.html): non-interactive partial issuance and the explicit one-use restriction.
13. [Katz and Urban, 2024/2011](https://eprint.iacr.org/2024/2011): abstract's honest-majority scope and reported amortized presignature figure.
14. [Adjedj et al., 2024/1950](https://eprint.iacr.org/2024/1950): abstract's two-party, two-round, one-OLE result and its scope.
15. [Poseidon2, 2023/323](https://eprint.iacr.org/2023/323): revised linear layers and hash-specific constraint savings.
16. [Plonky3 README](https://raw.githubusercontent.com/Plonky3/Plonky3/main/README.md): field, SIMD, hash, batching, and proof-system components.
17. [Midnight transientHash](https://docs.midnight.network/api-reference/compact-runtime/functions/transientHash): circuit-efficient internal hashing and upgrade limitation.
18. [Midnight persistentHash](https://docs.midnight.network/api-reference/compact-runtime/functions/persistentHash): durable-state hashing and its circuit-cost distinction.
19. [ROTE](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/matetic): peer-assisted rollback protection.
20. [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559): fee cap, priority fee, and type-2 transaction semantics.
21. [blst README](https://raw.githubusercontent.com/supranational/blst/master/README.md): BLS12-381 scope and platform support.
22. [ICICLE MSM documentation](https://dev.ingonyama.com/2.8.0/icicle/primitives/msm): GPU MSM batching, window selection, precomputation, and memory tradeoffs.

