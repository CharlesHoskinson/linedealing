# Revised scheme implementation

Scope: `impl/` and `experiments/line-dealing/checks.py`. No git writes, new dependencies, or online builds.

1. Replace the owner and dealer proofs with the 196-byte DLEQ and authorship transcript. Use labelled ciphertext hashes, k256 hash-to-curve, and an Edwards try-and-increment map. Test transcript mutations, domain separation, and wire sizes.
2. Enforce suite 3 membership at key, proof, complaint, and transfer boundaries. Add complaint and Edwards transfer APIs with rejection and reconstruction tests.
3. Use `ceil((n+f+1)/2)` for board quorums while preserving the two sharing thresholds. Test all four quorum uses and the height anchor.
4. Add a restart replay barrier and replay-driven share deletion. Persist processed positions and test rollback, incomplete replay, and restored erased shares.
5. Update T15, run the full offline release tests, Clippy, and formatting checks. Run Cargo directly with at most four jobs. Leave bench9, Criterion, the simulation matrix, and benchmark table regeneration to the lead's exclusive heavy slot. Update `final-wire.md` with evidence and limitations.

The supplied scheme and explicit task authorize this implementation. Execute inline in the existing worktree.

Completed: all five steps within this lane's scope. Release tests: 91 passed, one benchmark ignored. Clippy and formatting pass. Python checks: 36/36. See `final-wire.md` for the six task items, output files, and deviations.
