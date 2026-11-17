# Lane: Rust implementation and tests of line dealing

The design is /home/hoskinson/Projects/mpcexperiments/design/SCHEME.md (line dealing). Read it in full, plus design/FINDINGS-LEDGER.md and experiments/line-dealing/checks.py (a pure-Python reference of the algebra and attacks, 36 passing assertions). Treat SCHEME.md as the specification. Do not edit SCHEME.md or anything outside your own folder. Do not commit or push. Run every build or test through heavy-run, e.g. `heavy-run --mem 16G --name <name> -- <cmd>`; if heavy-run is unavailable in your sandbox, run the command directly with low parallelism. No network installs.

Your folder: /home/hoskinson/Projects/mpcexperiments/impl/ . Create a Cargo crate 'line-dealing' there (edition 2021). Use the k256 crate version 0.13.4 (features: arithmetic, ecdsa, schnorr, sha256, serde not needed) and sha2; they are in the local cargo cache, so build with --offline. Set CARGO_TARGET_DIR=/home/hoskinson/Projects/mpcexperiments/impl/target. Do not add other crates unless they are already in ~/.cargo/registry/cache (check with ls); never fetch from the network.

Implement, following SCHEME.md exactly (message fields, domain-separation labels and the injective encoding of section 3.1, Step A checks of section 3.4, partials of section 3.8):
- Feldman Shamir dealing over the secp256k1 scalar field with commitments in an arbitrary base point, Eval of commitments at node i, Lagrange combine.
- Labeled hashed-ElGamal share encryption to node keys (pad per polynomial component, per SCHEME 3.1), and decryption.
- Owner side: open ECDSA slot (w = k^-1, mu = k^-1 x, base R), sealed ECDSA point (s with base R, F0 = hG + rX), open BIP340 (x and nonce pair D, E', binding factor rho, even-y handling), sealed BIP340 point (F0 = lift_x(x(R)) + cX).
- Committee side: Step A checks (canonical points, x(R) mod q != 0, F0 != identity, even-y R for BIP340, constant terms implied), partial signing, public partial verification, combine with low-s and Ethereum yParity.

Tests (cargo test --offline), at least:
1. Open ECDSA end to end n=16, t=6: combined (r, s) verifies with k256::ecdsa::VerifyingKey (prehash verify) under X; any 6 of 16 partials work; 5 do not; a tampered partial is rejected by verify_partial.
2. Sealed ECDSA end to end; recovery of R from a low-s wallet signature.
3. Open and sealed BIP340 end to end, verified with k256::schnorr::VerifyingKey; cover both parities of the nonce point.
4. Attack tests: with one shared pad per slot (a test-only encoder) an observer recovers x from ciphertexts plus one signature; with the SCHEME labels the same attack fails. Two signatures on one open ECDSA slot recover x. Odd-y BIP340 dealing is rejected by Step A. Zero F0 dealing is rejected. A changed header makes shares undecryptable / fail verification.
5. Resharing: a reshared open slot still signs and verifies.
6. yParity: recovery of X from (h, r, s, v) with k256::ecdsa::RecoveryId after low-s normalization.

Run cargo fmt, cargo clippy --offline -- -D warnings if available, and cargo test --offline. Write README.md in your folder with how to run, the test list, and the exact test output summary. Your final message is a short summary including the cargo test result line.
