# Brief: make split-line dealing fast

You are a cryptographer and performance engineer, one of three independent lanes. Find where split-line dealing can run faster without weakening any security claim, search the web for the best current techniques, and deliver a ranked list of concrete optimizations.

## Read first

- `/home/hoskinson/Projects/mpcexperiments/design/enhancement/DESIGN.md`: the protocol (split-line dealing, TEE and non-TEE modes, profiles P0/P1/P2). It is being extended to many outside shard holders while you work; `/home/hoskinson/Projects/mpcexperiments/design/enhancement/DECISIONS.md` items 21-25 state that extension. Optimize for the multi-shard form too.
- `/home/hoskinson/Projects/mpcexperiments/design/SCHEME.md` and `design/PROOFS.md`: the base protocol and its proofs.
- `/home/hoskinson/Projects/mpcexperiments/impl/BENCHMARKS.md` and `impl/src`: the measured Rust prototype of the base protocol (n = 9: 2.3 ms CPU per node per request at t = 3, 3.3 ms at t = 7; 132.6 and 76.7 requests per second end to end in simulation).
- DESIGN.md §11 gives the cost estimates to beat: about 160-220 scalar multiplications (8-11 ms) per node per request, about 5-6 s latency plus Midnight finality, a STARK wrapped once in BLS12-381 budgeted at 2^20 rows (hard cap 2^21).

Parameters: n = 9, f = 2, q = 6, t = 7 at launch; n = 17, f = 5, q = 12, t = 12 later. Chains: Bitcoin (BIP340, ECDSA), Ethereum (ECDSA), Solana (Ed25519).

## What to examine

Everything on the critical path and in throughput:
- Per-node CPU: share verification (Feldman checks), batch verification, multi-scalar multiplication (Pippenger, Straus), precomputed tables for fixed bases, random linear combination checks across a batch of requests, verification of many dealings at once.
- Dealing and envelope: encryption to `PK_i`, the dealing proof (196 bytes today), the fee grid size `K·L`, compact commitments, aggregating complaints.
- Nonce and presignature slots: generation, pooling, batching, refill; the ECDSA birth session (DKLs23, threshold presigning, OT extension costs); non-interactive alternatives.
- Ordering and latency: the board's rounds, pipelining, the quorum certificate, when shares can move, overlapping Midnight finality with board work, optimistic paths with a fallback.
- Midnight proofs: circuit size of `authorize` and the ticket STARK, field choice, hash choice (Poseidon2 or others vs SHA-256 sighash), recursion and folding, proving time on the user's device, aggregation across many requests.
- TEE mode: enclave crossings, attestation cost, sealed-storage I/O, peer-witness round (can it piggyback on board votes?).
- Multi-shard: cost growth with the number of actors; aggregation of actor contributions; whether an actor's contribution can be verified in batch.
- Implementation: curve libraries (libsecp256k1, k256, curve25519-dalek, blst), SIMD, GPU, constant-time costs.

## Deliverable

Write one Markdown document (path in your launch message):

1. **Summary**: the five biggest wins with estimated speedup.
2. **Profile**: where the time goes today per request, per node, per phase (derive from DESIGN.md and BENCHMARKS.md; label estimates).
3. **Optimizations**, ranked by impact on throughput and latency. For each: the mechanism in exact terms, the estimated gain with its derivation, the security argument (why every claim of DESIGN.md §9 still holds, or what changes and needs a proof), the implementation cost, and the sources.
4. **What not to do**: tempting optimizations that break a claim, with the reason.
5. **A revised cost table** for launch and n = 17 after the optimizations.
6. **Sources**: URL and what each contributed. Do not cite what you did not open.

Take positions. Present tense. No hedged survey.
