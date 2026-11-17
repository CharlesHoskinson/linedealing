# Merge notes from component reports

## attest (committee/attest a8f51b1, 0fd026e)
- Gated by Cargo feature `committee` + runtime `VERITEE_COMMITTEE_MODE=1`; default behavior unchanged.
- Mutual akx uses fail-closed `UnavailableVerifier` until veritee-verify implements `akx::committee::PeerVerifier` -> wire at merge.
- `committee_bound_attestation` (committee + raw-report) not compiled on aarch64 (sev -> rdrand x86-only); tests use maa build + FakeAttester; maa refuses committee mode.
- Class 0x02 = guest holds private keys (import/export with seald), not "generated this process".
- Encodings: HCL user data = 32-byte digest unpadded; quote qualifying data same. Class 0x01 payload = epoch u64 BE ‖ pk_e(32), empty nonce. Class 0x02 payload = SHA-256(NodeKeys JSON), caller nonce ≤64 B. Class 0x04 payload = raw provision_x25519. Vector class0 payload "payload" nonce "nonce" -> 28a14fc2581db5eeba6ee01b75a4e53fe5c44b6c5f69fa5e3b92b18f1b22a25c. NodeKeys fixed record digest 3197505c426463790221715ce91ef08c9f46a73f0b5ee39bce2ad479aa188f39.
- os must: Earthfile features `raw-report,committee`; set VERITEE_COMMITTEE_MODE and VERITEE_ATTEST_SOCK_UID from measured config; Caddy routes /peer/session*; cli/veritee/attested_channel.py:342-360 must move to class 0x01.
- seald owns attest_boot payload layout and persistence of node key export.
- `x-veritee-peer-akx` names an akx key, not node index; map via NodeKeys/BOOT/ledger.
- Remove duplicated evidence/NodeKeys from akx once veritee-verify merged; vectors must match.
- 2 pre-existing tpm test failures (no TPM on host); 25 pre-existing clippy errors in old code.
