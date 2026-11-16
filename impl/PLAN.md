# Line dealing implementation plan

The implementation follows `../design/SCHEME.md`. All files stay in `impl/`.
The crate uses edition 2021 and cached dependencies. Builds run offline with
`CARGO_TARGET_DIR` set to `impl/target`. No commits or network installs occur.

- [x] Read the specification, findings ledger, and Python reference in full.
- [x] Add tests for field operations, strict encodings, labels, and hash construction.
- [x] Implement the complete header and owner-message encoding from section 3.2.
- [x] Implement per-component encryption and the two-witness authorship proof.
- [x] Implement Step A with explicit inputs for board state and sealed transaction validation.
- [x] Implement open and sealed ECDSA and BIP340 dealing and partial signing.
- [x] Verify all 8,008 six-node subsets of a 16-node ECDSA dealing.
- [x] Test wallet nonce recovery, low-s recovery parity, attacks, and malformed messages.
- [x] Implement and test encrypted resharing with the section 5 domains.
- [x] Run formatting, clippy, and the complete offline test suite.
- [x] Record run instructions, scope, tests, and exact output in README.md.

Modules: `algebra.rs` owns polynomials and interpolation. `hash.rs` owns domain
separation. `wire.rs` owns headers and parsing. `message.rs` owns dealings,
encryption, proofs, and acceptance. `signing.rs` owns partials and signature
combination. `reshare.rs` owns per-dealer transfer and interpolation.

Tests use fixed seeds. Library callers supply a cryptographic random source.
The board state machine and chain transaction builders remain caller components.
The acceptance interface must reject a message when those checks fail.
