# linedealing

Line dealing: a one-move spend protocol for existing blockchain addresses.

The owner of an existing address sends one message and goes offline. A committee then signs one spend when a condition on the chain holds. A Schnorr or ECDSA signature is a point on a line whose two coefficients the owner knows. The owner's message is a publicly checkable Shamir dealing of either finished signatures (sealed mode) or the line itself (open mode). The committee runs no distributed key generation, no presignature protocol and no secret multiplication.

- **Sealed mode.** The owner deals signatures on a grid of conflicting transactions that all spend one pinned input. The chain executes at most one of them, even if every node is corrupt, and the key is never exposed.
- **Open mode.** The committee builds the transaction from chain state, locks its digest with a quorum certificate, and signs with one linear partial signature per node. The one-spend limit holds while at most f of n ≥ 3f+1 nodes are Byzantine.
- **Impossibility.** No one-move protocol can confine a qualified coalition to one signature when the message depends on later chain state. Open mode therefore cannot have the sealed guarantee.

## Repository

| Path | Contents |
|---|---|
| `design/SCHEME.md` | The protocol specification, with corrections C1–C25 and their ledger (`FINDINGS-LEDGER.md`) |
| `design/PROOFS.md` | Security proofs: open ECDSA reduced to Groth–Shoup, open Schnorr under algebraic OMDL, share encryption under interactive CDH, the impossibility theorem |
| `formal/lean` | Lean 4 proofs of the algebra and the counting arguments (103 theorems) |
| `formal/natural` | The same results in Natural Lean |
| `formal/quint` | Quint model of the board rules, simulated at n = 4, 7 and 9, with a mutant check |
| `impl/` | Rust prototype: three suites (BIP340 Schnorr, ECDSA secp256k1, Ed25519), the 196-byte dealing proof, complaints, resharing; 91 tests |
| `impl/BENCHMARKS.md` | Measurements: per-core throughput, Criterion tables for n = 9 to 256, a 72-run simulation matrix |
| `paper/` | The paper (`main.pdf`, 38 pages), its sources and the review record |
| `paper-split/` | The paper split into parts, with its review record |
| `design/council/` | Design council proposals and reviews |
| `proto/` | Committee session simulator |
| `experiments/` | Line-dealing check and cost scripts |

## Performance

At n = 9 a request costs each node 2.3 ms of CPU at threshold t = 3 and 3.3 ms at t = 7 (quorum 6), so one core can sign about 410 or 288 requests per second. A request message is 1,461 or 1,725 bytes. A 16-core node could sign about 5,200 or 3,700 per second by arithmetic; that figure is not measured. The simulated committee with its board, measured end to end, completes 132.6 requests per second at t = 3 and 76.7 at t = 7 with batches of 16 (p50 latency 104.8 ms at t = 3). The board and the target chain bound throughput, not the committee's CPU.

## Status

Proved: sealed confinement, open ECDSA and open Schnorr unforgeability under their assumptions, and the impossibility theorem, all for static corruption. Open: resharing, adaptive corruption, and a proof that the protocol realizes the ideal functionality F_OMS. The measurements are of an in-process prototype, without a consensus protocol or chain submission.

## Build

```sh
cd impl && cargo test --release        # Rust prototype
cd formal/lean && lake build           # Lean proofs
cd paper && latexmk -pdf main.tex      # paper
```

## License

Copyright 2026 Charles Hoskinson <charles.hoskinson@gmail.com>

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
