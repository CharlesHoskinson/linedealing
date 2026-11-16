# Prototype completion

Implement SCHEME.md without changing the design files or committing.

1. Add deterministic UTXO and EIP-1559 builders in `src/builder.rs`. Check D12, D13, pins, ordering, and replacement fees.
2. Add the ordered board reducer and explicit persisted node state in `src/board.rs`. Test replay, equivocation, freeze, tombstones, and random schedules.
3. Add the Ed25519 cryptographic path in `src/ed25519.rs`. Check canonical prime-subgroup points and strict signature verification.
4. Add shared experiment fixtures, Criterion benchmarks, and a threaded committee simulator. Measure all three suites in both modes.
5. Update README.md and record only executed measurements in BENCHMARKS.md. Run formatting, all-target Clippy, and the full offline test suite.

Use cached dependencies and `impl/target`. The sandbox rejects the systemd connection required by `heavy-run`. Use four Cargo jobs.

For nine nodes, use f = 2 and quorum n-f = 7. This extends the specification's n = 3f+1 profile without weakening quorum intersection. For canonical committee sizes, n-f equals 2f+1.

Use the specification's 12.5% EIP-1559 bump. It meets the requested 10% minimum and reproduces D12.

All five items are complete. The final test run passed 80 tests, with one legacy timing test ignored. Clippy and formatting passed. All 288 benchmark smoke cases passed. BENCHMARKS.md records the nine-node Criterion measurements and 72 simulation runs. No commit was made.
