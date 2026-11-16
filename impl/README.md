# line-dealing

Rust prototype of [SCHEME.md](../design/SCHEME.md). It implements open and sealed ECDSA, BIP340, and Ed25519, deterministic payment builders, and an ordered board state machine.

All dependencies are pinned in Cargo.lock and available in the local Cargo cache. Builds use `--offline`.

## Build and test

Run from this directory:

```sh
export CARGO_TARGET_DIR=impl/target
cargo test --offline --release -j 4
cargo clippy --offline --all-targets -j 4 -- -D warnings
cargo fmt --check
```

[wire-test-output.txt](wire-test-output.txt) records the release tests. [wire-clippy-output.txt](wire-clippy-output.txt) records the lint check. [final-wire.md](final-wire.md) records the results and scheme deviations. Run benchmarks and the simulation matrix only under the lead's exclusive heavy slot.

Tests cover:

- The original 26 algebra, dealing, encryption, signature, attack, encoding, and resharing regressions.
- UTXO pins, largest-first selection, canonical input ordering, ALL payments, confirmations, dust, and real fee ceilings.
- D12 flat-market replacement and D13 dust rejection, account nonces, EIP-1559 fee caps, and replacement fee rates with variable DER lengths.
- Sealed fee grids, fixed additional inputs, variant selection, and official BIP143/BIP341 sighash vectors.
- All three suites in both modes. Ed25519 signatures use `ed25519_dalek::VerifyingKey::verify_strict`.
- Ed25519 canonical encodings, identity and torsion rejection, altered ciphertexts, insufficient shares, and multiple generations and inputs.
- Board ACK quorums, complaints, median anchors, NACK retries, board cuts, lock-before-share, restart replay, and disk persistence failures.
- Freeze and handover, thresholds across repeated rotations, tombstones, and conflicting generations that share one pin.
- 600 randomized two-view schedules with equivocation and rollback, plus 200 lifecycle schedules of 120 steps each.
- The threaded simulator, both threshold profiles, batching, and delays in both link directions.

A restored node must replay to its independently retained board position and repeat required erasures before posting. A node that skips this rule counts as Byzantine.

## Library

`message::Owner` and `wire::Header` implement the secp256k1 path. `ed25519::{Owner, Header}` implement suite 3 with the same operations. Owner constructors create open polynomials or import sealed wallet signatures. `encrypt` creates the owner message. Step A checks public commitments, encodings, address binding, committee parameters, and authorship.

`AcceptanceContext` supplies trusted registry state and recomputed sealed messages. The cryptographic API deliberately permits repeated signing for attack tests. A service must call `board::NodeState::partial` before calculating a partial signature.

`SigningPackage` checks partials, interpolates distinct nodes, and verifies the final signature independently. ECDSA output uses low-s normalization and the adjusted Ethereum recovery parity. BIP340 verifies raw sighashes. Ed25519 uses its standard SHA-512 challenge and little-endian signature scalar. LD1 protocol scalars remain big-endian.

`reshare::{Subdealing, Transfer}` and `ed25519::reshare::{Subdealing, Transfer}` implement encrypted polynomial transfer for all three suites. The board selects the dealers and authorizes handover. These transfer records use the `LD1/rs-*` labels and preserve the original constant commitments.

### Proofs and hash-to-curve

The owner and dealer proof is `(E_prime, T_1, T_2, z_e, T_a, z_a)`, exactly 196 bytes. The ephemeral DLEQ uses `LD1/eph` and `LD1/ephpok`. The authorship challenge covers its four fields and `T_a`, after `hd` and the labelled ciphertext digest. Transfer proofs use the `LD1/rs-*` labels and the transfer prefix. `Accepted` is created only after both proofs pass; decryption and complaint methods require it.

`k256` 0.13.4 provides `secp256k1_XMD:SHA-256_SSWU_RO_` through `GroupDigest::hash_from_bytes<ExpandMsgXmd<Sha256>>`. The protocol label is the DST. The test suite includes the empty-message vector from [RFC 9380 section J.8.1](https://www.rfc-editor.org/rfc/rfc9380.html#section-J.8.1). Enabling the cached crate's `hash2curve` feature adds no dependency.

RFC 9380 names `edwards25519_XMD:SHA-512_ELL2_RO_`, but Dalek 4.1.3 does not implement that random-oracle suite. Its deprecated `nonspec_map_to_curve` explicitly warns that it is not a secure hash function. The prototype therefore uses the permitted try-and-increment fallback: compute `H_tag(message || counter_be32)` from counter zero, decode a canonical compressed Edwards point, multiply by eight, and reject the identity. The resulting point is in the prime-order subgroup. This public-input map has variable running time and is not RFC 9380 wire-compatible. It must not be replaced by a known scalar times the generator.

`LD1/ct` hashes the ciphertext block. `LD1/rs-ct` hashes the transfer prefix followed by that block. Both use the labelled SHA-256 construction. Suite 3 key registration inputs, complaints, proof points, and transfer points reject identity and non-prime-order points. Wire decoding also rejects noncanonical encodings.

`Accepted::complain` and `verify_complaint` verify the DH proof and require a failed share check. Edwards transfer complaints use the same DH proof; their local message digest is `LD1/rs-mid(hd || ct || proof)`. Section 5 does not define a transfer envelope or complaint message digest, so this prototype digest is an explicit local convention.

### Builders

`builder::build_utxo` consumes an intent, finalized snapshot, policy, generation, and locally reconstructed prior transactions. It supports P2PKH, P2WPKH, and P2TR. Outputs retain intent order. Inputs always include the pin and serialize in outpoint order. The builder produces unsigned transaction bytes and chain sighashes.

Bitcoin signed sizes use conservative upper bounds. Replacement checks use the prior transaction's authenticated `signed_vsize` when available. Otherwise, they use a conservative lower bound for its DER signatures. This prevents a short prior signature from defeating the required fee-rate increase. D12 supplies its stated prior size of 141 vbytes.

`build_eip1559` supports native payments to externally owned accounts with 21,000 gas and empty calldata and access lists. Its caps increase by rounded-up 12.5%, matching SCHEME.md and D12. This also meets the requested 10% minimum. The caller must establish that the recipient requires no contract execution.

Fee-rule zero uses the exact mean of the middle pair of six block median rates. Unknown fee rules are rejected. UTXO policy supplies dust and replacement-increment parameters.

`SealedUtxoIntent` freezes resolved input values and scripts alongside the wire intent. `variant_utxo` constructs the fee grid. `select_utxo` checks the snapshot and chooses the least eligible variant above the prior index. Sealed account payments use one fixed variant at the ceiling. Sealed ALL values are fixed before signing.

### Board and persistence

`board::Board::apply` reduces an authenticated, totally ordered event log. It handles binding, ACKs, anchors, failed attempts, locks, releases, generations, rotation, handover, and tombstones. Each anchor retains the prior-generation view at its board cut.

`LocalBuild` must come from the node's own builder and finalized chain snapshot. Its caller checks eligibility and reconstructs prior transactions from those saved anchors. Evidence flags in board events are verified adapter results, not assertions accepted from a peer.

`PersistedNodeState` explicitly models the slot ledger. `NodeState::open` provides a disk adapter: write, fsync, rename, then directory fsync before returning a vote or partial authorization. Storage failure disables that signer until restart. Give each ledger path one process owner. `open` and `restart` block all posts until `replay` reaches the independently retained earlier position. Replay abstains on slots with missing local records. Its fallible erasure callback deletes whole requests after FINAL or VOID, unlocked generations after expiry, and transferred generations after HANDOVER. Erasure failure keeps posting blocked.

Supply `None` if the earlier position is lost. `recover_position` requires at least `2f+1` distinct authenticated committee answers and uses their highest committed position. A host-chain adapter can instead supply its finalized tip. The caller must verify board consistency and answer authenticity.

Call `replay` as the local board advances, and call `ensure_can_post` before every non-signing post. PREVOTE and PARTIAL call the gate internally. The simulator also gates ACK and OBS. The disk ledger uses `LDLEDGER2` and includes the processed position; old ledger files are rejected. Keep the prior position separately from rollback-prone backups.

Quorums are `q = ceil((n+f+1)/2)` for `n >= 3f+1`. This equals `2f+1` at the scheme's canonical sizes. The nine-node benchmark uses `f=2`, quorum 6, and sharing thresholds 3 or 7. Anchors use entry `f+1` of the first quorum of distinct reports, sorted by decreasing height.

The board models transfer and erasure decisions. An application must connect those decisions to share storage, cryptographic transfer, physical erasure, chain verification, and authenticated transport.

## Benchmarks

Criterion covers six operations: owner deal and encrypt, public Step A, decrypt and verify shares, partial, verify partial, and combine. The matrix has 288 cases: three suites, both modes, four committee sizes, both threshold profiles, and six operations. Sealed messages contain eight variants. Open messages contain one generation and one input.

```sh
export CARGO_TARGET_DIR=impl/target
cargo bench --offline -j 4 --bench protocol -- --test
cargo bench --offline -j 4 --bench protocol -- --noplot
LD_BENCH_N=9 cargo bench --offline -j 4 --bench protocol -- --noplot
```

The first command checks every benchmark once. The last command measures only nine-node cases. Sealed wallet signatures and transaction fixtures are prepared outside the owner microbenchmark. The `partial` API includes its local verification check. `combine` includes final signature verification. Each Criterion case uses ten samples, a 100 ms warmup, and a one-second measurement target.

The legacy nine-node timing harness remains available:

```sh
cargo test --offline --release -j 4 --test bench9 -- --ignored --nocapture
```

Measured results and exact commands are in [BENCHMARKS.md](BENCHMARKS.md).

## Committee simulation

```sh
export CARGO_TARGET_DIR=impl/target
cargo run --offline --release -j 4 --bin committee-sim -- --requests 16 --suite ecdsa --mode open --threshold 3 --latency-ms 25 --batch-size 16 --board-ms 1 --seed 42
cargo run --offline --release -j 4 --bin committee-sim -- --help
bash run-simulation-matrix.sh > simulation-results.txt
```

Nine worker threads run Step A, decrypt shares, report heights, vote, and release cryptographic partials. A sequencer verifies Ed25519 post signatures and applies the board state machine. Bitcoin workers independently reconstruct builder transactions and sighashes. Ed25519 uses signature-level message fixtures because the Solana transaction adapter is outside this prototype.

`--latency-ms` applies to each one-way channel delivery. `--batch-size 1` disables batching. Larger values group channel messages and board commits. `--board-ms` adds sequencer service time between batches. Post signatures and partials are verified individually.

All requests are prepared before dispatch and then run concurrently. Per-request latency starts before its owner preparation and ends at verified reconstruction. Thus latency includes the remaining serial preparation work. Throughput includes all preparation and ends at the last reconstructed signature. Late posts are drained for stable post counts. Percentiles use nearest-rank samples.

The simulator reports p50, p99, requests per second, post counts, and batch counts. It models an honest workload with synthetic finalized chain state. It excludes BFT consensus, chain inclusion, physical share erasure, and disk fsync latency. Its seeded keys are public test data and must never control funds.

No Bitcoin node, Ethereum node, or Solana transaction acceptance test was run. The proof gaps recorded in [PROOF-CHECK.md](../design/PROOF-CHECK.md) remain outside this implementation task.
