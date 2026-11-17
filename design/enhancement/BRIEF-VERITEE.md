# Brief: close four gaps in Veritee for a threshold-signing committee

You are one of three independent lanes. Research current best practice online, then deliver a concrete design that closes four gaps in Veritee, the in-house TEE system, so a Fenrir signing committee (n = 9, f = 2, key threshold t = 7) can run inside it. Other lanes do the same task; a lead merges the results.

## Read first

- `/home/hoskinson/Projects/mpcexperiments/design/enhancement/VERITEE-MODEL.md`: a cited digest of what Veritee does today.
- `/home/hoskinson/Projects/veritee/veritee-vm/`: the code. Key paths: `server/akx/src`, `server/azure_attestation_server/src`, `server/guest_attestation`, `veritee-os/measured_setup`, `veritee-os/mkosi`, `cli/veritee`, `docs/attested-channel-implementation-plan.md`, `docs/tls-channel-binding.md`, `AGENTS.md`. A graph is in `graphify-out/GRAPH_REPORT.md`.
- `/home/hoskinson/Projects/mpcexperiments/design/enhancement/BRIEF.md`: the protocol context (TEE mode and non-TEE mode of a co-custody signing committee with a threshold-encrypted mempool on a BFT board, Midnight as the authorization chain).

Veritee today: Azure Confidential VMs on AMD SEV-SNP with a vTPM (Azure HCL paravisor), dm-verity root in RAM, PCR4 boot image, PCR15 app root hash plus TLS evidence, nonce-bound attestation via MAA or raw HCL report, akx (per-boot Ed25519 key attested with a constant nonce, interactive HPKE sessions), measured egress proxy, a Warden that reproduces images and records measurements on Midnight. The companion repos (Warden, spec, contracts) are not available; state assumptions about them.

## The four gaps

1. **No sealed storage.** Keys are not sealed to the enclave. The persist partition is plain ext4 that disk snapshots expose. No TPM- or SNP-derived key. No secure erasure (zeroize).
2. **No rollback protection.** No monotonic counter. The operator can roll back the persist partition, or clone a node's state to a second VM, and nobody notices. For a signing node this means nonce or presignature reuse, double release of a sealed variant, and resurrected key shares after a reshare.
3. **No offline encryption to an enclave.** An enclave is reachable only over a live interactive akx session. An owner must be able to encrypt a request to the committee (or to each node) once, from an offline wallet, and go away.
4. **Secrets not gated on attestation.** Keys come from Azure Key Vault released to the VM's managed identity, whatever the VM is running. The operator also uploads the TLS private key.

## Research

Search the web for current (2025-2026) practice and read what you cite. Candidates, not a limit: AMD SEV-SNP `MSG_KEY_REQ` derived keys (VCEK/VMRK, measurement- and policy-bound), Azure vTPM sealing and its limits on CVMs, Azure Secure Key Release with MAA policies, Azure Managed HSM SKR, Azure confidential disk encryption, Confidential Containers KBS/Trustee and its attestation-gated resource release, Intel Trust Authority, Google Confidential Space workload identity, AWS Nitro Enclaves KMS attestation conditions, Phala dstack KMS (on-chain key governance, key derivation per app), Flashbots TDX key management and "Andromeda" / BuilderNet, Secret Network and Oasis key managers, Fortanix; rollback: ROTE (distributed rollback protection), Narrator, Nimble (Microsoft, append-only trusted counters), LCM, TPM NV counters and why vTPM counters are host-controlled on Azure, confidential ledgers (Azure Confidential Ledger, CCF), blockchain-anchored state (state root on Midnight), peer-quorum freshness; erasure: zeroize crates, mlock, no swap, core-dump disable, memory encryption key rotation on reboot; offline encryption: attested static HPKE epoch keys published on chain, threshold encryption keys whose shares live in enclaves, key transparency, binding the public key into the attestation report data. Also known attacks: SEV-SNP rollback/replay, Heracles, CacheWarp, BadRAM, WeSee, Ahoi, TEE.fail (2025), and what they mean for these designs.

## Deliverable

Write one Markdown document (path in your launch message) with these sections:

1. **Summary**: the four fixes in one page and the one design idea that ties them together.
2. **One section per gap**: the threat; best practice found (with sources); the chosen design for Veritee with exact mechanism (keys, derivation inputs, policies, protocols, message formats); what it stops and what it does not; how it behaves across reboot, redeploy, image upgrade and committee reshare.
3. **How the four fit together** as one node lifecycle: boot, attest, obtain secrets, join epoch, receive dealings, sign, erase, upgrade, retire.
4. **Use by the signing committee**: how the fixes support the co-custody protocol (sealed user dealings, threshold-encrypted mempool, presignature and nonce slots, reshare). State which protocol guarantees still need the cryptography (non-TEE mode) because a TEE can be broken.
5. **Implementation plan for veritee-vm**: files and components to change or add, in order, with an estimate of size; tests; what the Warden and Midnight contracts must add.
6. **Residual risks**: what an Azure host operator, a malicious image builder, AMD or Microsoft can still do; known attacks.
7. **Sources**: URL and what each contributed. Do not cite what you did not open.

Take positions. Present tense. No hedged survey.
