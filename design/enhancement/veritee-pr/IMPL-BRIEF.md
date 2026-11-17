# Implementation brief: Veritee committee-signing mode

Veritee (`/home/hoskinson/Projects/veritee/veritee-vm`, Apache-2.0, Input Output) gets a new opt-in **committee-signing mode** so a threshold-signing committee (n = 9 nodes, f = 2, peer quorum q = 6, key threshold t = 7) can run inside it. Default Veritee behavior for other DApps does not change.

## Read first

- `/home/hoskinson/Projects/mpcexperiments/design/enhancement/VERITEE-MODEL.md`: what Veritee does today, with file:line citations.
- `/home/hoskinson/Projects/mpcexperiments/design/enhancement/DECISIONS.md`, items 11-18: the chosen hardening.
- The three hardening designs `hardening/{fable,astra,carbon}/HARDENING.md` in the same folder: detail and sources. Where they differ, DECISIONS.md governs.
- The repo's `AGENTS.md` and the files you change.

## Rules

- Work only in your assigned worktree and branch. Commit there with `git -c user.name="Charles Hoskinson" -c user.email=charles.hoskinson@gmail.com commit`. No Co-Authored-By line and no AI attribution of any kind in commits, code comments or docs. Never push.
- Gate every new behavior behind the committee mode (Cargo feature `committee` and/or a measured metadata flag `"committee_mode": true`). Existing tests keep passing.
- Do not install system packages. Rust crates from crates.io are fine. If something cannot build on this aarch64 host (Azure HCL or TPM libraries), keep it behind a feature or trait, add a mock, and say so in your report.
- Run heavy builds as `heavy-run cargo ...` if `heavy-run` exists, else `systemd-run --user --scope --slice=heavy.slice cargo ...`. Use a target dir inside your worktree.
- Code matches the repo's existing style. Tests for every new module. `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test` (and `pytest` for Python) pass for what you touched.
- Secrets: `zeroize::Zeroizing`/`ZeroizeOnDrop` for every secret type; no secret in logs, errors or Debug output.

## Shared interfaces (all components use exactly these)

1. **Evidence classes.** Attestation report data is `SHA-256("veritee/evidence/v1" ‖ class ‖ len(payload) as u32 BE ‖ payload ‖ nonce)`, with one class byte:
   - `0x00` PUBLIC: caller-chosen payload, served on the public route. Peers and wallets never accept it for keys.
   - `0x01` AKX_EPOCH: the akx epoch key.
   - `0x02` NODE_KEYS: the node's epoch key set (below).
   - `0x03` BOOT: the boot key and boot counter.
   - `0x04` PROVISION: the attested provisioning key.
   Classes `0x01`-`0x04` are produced only through a Unix socket `/run/veritee/attest.sock` (mode 0600, owner of the app), never from the public HTTP route. TPM quotes carry the same digest as qualifying data.
2. **Node epoch key set** (`NodeKeys`, canonical JSON, keys sorted): `{ "version":1, "committee":hex32, "epoch":u64, "node_index":u32, "boot_counter":u64, "hpke_x25519":hex32, "dealing_secp256k1":hex33, "post_ed25519":hex32, "provision_x25519":hex32 }`. Its SHA-256 is the payload of class `0x02`. All private keys are generated in the guest and never leave it.
3. **SealedToNode** envelope: HPKE (RFC 9180) mode Base, X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305; `info = "veritee/sealed-to-node/v1" ‖ SHA-256(NodeKeys canonical JSON)`; `aad = context` given by the caller. Wire: `{ "version":1, "keys_digest":hex32, "enc":hex32, "ct":base64 }`.
4. **Boot ticket**: `{ "committee":hex32, "node_index":u32, "boot_counter":u64, "boot_pubkey_ed25519":hex32, "image_pcr4":hex, "app_root":hex, "prev_ticket":hex32 }`, recorded on Midnight. A node accepts work only while its ticket is the latest for its index.
5. **Ledger trait** (Midnight access), in the `veritee-verify` crate: `trait CommitteeLedger { fn latest_boot_ticket(&self, committee, node_index) -> Option<BootTicket>; fn epoch_key_set(&self, committee, epoch) -> Option<Vec<NodeKeys>>; fn latest_checkpoint(&self, committee) -> Option<Checkpoint>; fn submit(&self, record) -> Result<TxId>; }` plus an in-memory mock. The real Midnight contract is out of scope; describe it in docs.
6. **Peer witness**: before a node releases an irreversible output it sends `Witness{ committee, node_index, boot_counter, slot: (rid hex32, g u32, kind u8), digest hex32 }` signed by its boot key to peers over mutual akx. A peer that has stored a different digest for `(node_index, slot)` refuses; otherwise it stores durably (sealed storage) and returns a signed `WitnessAck`. The node releases only with `q = 6` acks from distinct current-ticket peers.
7. **Group seal secret**: `K_grp = HKDF-SHA256(salt = committee ‖ epoch, ikm = threshold-PRF output)`. The threshold PRF is the DH-based PRF `PRF(k, x) = k·H2C(x)` on ristretto255, with `k` Shamir-shared t-of-n among the peers' enclaves (RAM only). For input `x = committee ‖ epoch ‖ node_index` (stable across reboots, so a rebooted node can unseal its keyring; the boot counter is checked, not hashed in), peer j sends `y_j = k_j·H2C(x)` SealedToNode, and only after it verifies the requester's class `0x03` evidence and current boot ticket. The node computes `PRF(k, x) = Σ λ_j·y_j` over t responses and feeds its encoding to the HKDF above. `K_seal = HKDF(K_tpm ‖ K_grp ‖ ratchet)`.

## Components

- **attest** (`server/azure_attestation_server`, `server/akx`, `server/guest_attestation`): evidence classes and the Unix socket; TPM quote qualifying data; close the oracle on the public route (class 0x00 only); mutual akx (both sides present class-0x01 evidence, peer verification through `veritee-verify` API stubs if that crate is not merged yet: define a local trait and note the swap); in-guest generation and class-0x02 attestation of `NodeKeys`; SealedToNode open API exposed to the app on the Unix socket.
- **verify** (new crate `server/veritee_verify`): Rust verification of raw SEV-SNP reports (VCEK chain to AMD ARK/ASK, signature, policy, TCB floor, measurement fields) and Azure HCL runtime data binding to the vTPM AK and report data; evidence-class digest; NodeKeys and BootTicket types; SealedToNode seal/open; `CommitteeLedger` trait and mock; a small CLI `veritee-verify` that wallets and operators can run. Use test vectors from the repo's fixtures where they exist.
- **seald** (new service `server/seald`): sealed storage API for the app (put/get/destroy by name over the Unix socket); vTPM-sealed `K_tpm` (tss-esapi behind feature `tpm`, mock otherwise); group-secret client and peer server (item 7); ratchet and key destruction; peer witness store and server (item 6); boot-ticket fencing (refuse service when the ledger shows a newer ticket); `mlock`, `PR_SET_DUMPABLE=0`, `MADV_DONTDUMP`.
- **os** (`veritee-os`, `services`, `cli/veritee`, `projects/`): measured_setup formats `/mnt/persist` as LUKS2 with dm-integrity (aes-256-gcm) keyed from seald in committee mode; extend PCR14 with the committee role; systemd hardening for committee images (no swap, `LimitCORE=0`, `kernel.core_pattern=|/bin/false`); remove the Key Vault managed-identity secret path and the `azure_vault` TLS mode for committee images (refuse at package time); in-guest TLS keys (internal CA or ACME TLS-ALPN-01 via Caddy); committee metadata flag and validation in the CLI; a `projects/committee-node` template with a measured egress allowlist; CLI command `veritee verify-node` calling the verify crate; tests.

Your final answer: what you built (files, line counts), tests run with results, what is mocked or not buildable here, and open items.
