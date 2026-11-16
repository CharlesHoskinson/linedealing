# Veritee hardening for the Fenrir signing committee

Lane: fable. Date: 2026-11-14. Scope: the four gaps of `BRIEF-VERITEE.md`, for a committee of n = 9, f = 2, board quorum q = 6, key threshold t = 7.

Code citations are `path:line` in `~/Projects/veritee/veritee-vm` (branch `main`). Protocol terms (`rid`, generation `g`, lock digest `dg`, PREVOTE, PARTIAL, epoch key `PK_i`, profiles T1 and T2) are those of `design/SCHEME.md`. The Warden, the Midnight contracts and the app image are not available; every statement about them is marked **[assumption]**.

Symbols used throughout:

| Symbol | Value | Meaning |
|---|---|---|
| n, f, q, t | 9, 2, 6, 7 | committee size, Byzantine bound, board quorum, key threshold (T2 = n − f) |
| w | n − 1 − f = 6 | peer answers a node needs for admission and for a witnessed commitment |
| t_g | n − f = 7 | threshold of the seal-group secret σ (the node's own share plus w peers) |
| c | | number of operators who collude while every TEE still holds |

---

## 1. Summary

**The one idea.** A node has exactly one door, and the chain says whose door it is. Each boot of each node creates a fresh key inside the guest, binds it into SEV-SNP evidence, and records it in a **Node Record** on Midnight with a boot counter that only increases. The committee's own enclaves (the **seal group**) are the root of trust for every member: they verify the evidence themselves, and they hold the three things a single Azure VM cannot hold for itself, namely half of its storage key, the memory of what it has already released, and its place in the current epoch. Every fix below is a function of the Node Record and the seal group.

The reason is one fact about the platform. The operator can snapshot, restore and clone the OS disk together with the VM guest state blob that holds the vTPM. Everything local to the VM, including a TPM-sealed key and a TPM NV counter, sits inside that snapshot. A local mechanism therefore gives confidentiality bound to an image and nothing else. Freshness, single-instance and erasure come from outside the VM.

**Fix 1, sealed storage.** The persist partition holds ciphertext only. The storage key is `K_seal = HKDF(K_tpm ‖ K_grp)`. `K_tpm` is a random secret sealed in the vTPM under a PCR policy (PCR 4, PCR 14, and PCR 15 at its post-setup value). `K_grp` is the output of a threshold PRF that w = 6 peer enclaves evaluate for the node after they verify its fresh evidence and its Midnight boot ticket. A disk snapshot is unreadable. A snapshot plus a broken vTPM is still unreadable without the group. An image that the registry has revoked gets no `K_grp`. Secrets that are consumed once never reach the disk. Erasure is destruction of keys in RAM and rotation of the group secret each epoch, with zeroize, mlock, no swap and no core dumps in the guest.

**Fix 2, rollback and clone protection.** Three layers. (a) Every boot needs a **boot ticket**: the node's fresh boot key lands in a finalized Midnight block with boot counter + 1, and from then on peers and the board accept only that key for the node, which fences clones and zombies. (b) Before a node commits to anything it may commit to only once (its PREVOTE in open mode, a sealed release, a new keyring) it obtains **witness acks** from w peer enclaves, which record `(node, rid, g) → digest` and refuse a second digest. A restarted node learns its own witnessed releases from w peers before it acts, so SCHEME rule 4 has the facts it needs. (c) Board checkpoints on Midnight give a floor that no group of operators can move. With TEEs intact, one-digest-per-slot holds against c ≤ n − 1 − 2f = 4 colluding operators (SCHEME alone: f = 2), and against any c for requests that set `anchor_before_release`, where Midnight itself records one lock per `(rid, g)`.

**Fix 3, offline encryption.** Each node generates static epoch keys in the guest (an X25519 HPKE key `EK_i`, the SCHEME dealing key `PK_i`, a board post key), binds them into evidence under a reserved class, and the committee publishes the **Epoch Key Set** on Midnight after w peers have each verified the evidence. An offline wallet reads one Midnight record and encrypts once. Two envelopes exist: `SealedToNode` (single-shot HPKE to one node) and `SealedToCommittee` (a data key that is Feldman-committed and Shamir-shared t-of-n, each share padded to the node's attested `PK_i` the way SCHEME pads dealt shares, with the same public complaint). The second one is a threshold encryption that needs no new cryptosystem and is the same object in TEE mode and non-TEE mode.

**Fix 4, secrets gated on attestation.** Key Vault release to a managed identity is removed from the trust path. Committee secrets are born inside enclaves by DKG and reshare. Node-local secrets (TLS key, boot key) are generated in the guest. Operator secrets enter only as a `SealedToNode` envelope to an attested key, built by a CLI that verifies the evidence itself. Azure Secure Key Release is rejected as the gate: the operator owns the vault, the key, its mutable release policy and the managed identity, the token is signed by Microsoft's attestation service, and the documented confidential-VM token attests PCR 0 to 7 only, which leaves out the app measurement in PCR 15.

**Two prerequisite repairs.** The public endpoint `GET /tee_attestation` attests a caller-chosen payload, so today any key can be "attested". Evidence gets a class byte, and the public endpoint can only produce class 0. TPM quotes get qualifying data. Committee nodes run the raw-report path and peers verify raw evidence in the guest; neither MAA nor a single Warden is on the committee's trust path.

**What the fixes do not do.** They do not survive a platform-level break. Microsoft (hypervisor, paravisor, datacenter) or AMD can break every node at once, and the attacks in section 10 show the routes. In that case operator blindness (B1 to B3) is lost and open-mode guarantees fall back to the f bound. Requirement R1 holds through the user's share and sealed mode, which is cryptography.

---

## 2. Common base: evidence, classes, verification

All four fixes use the same evidence object, so it is fixed first.

### 2.1 What Azure gives a guest

- The guest does not talk to the AMD secure processor. Microsoft states that AMD's `sevctl` does not work on Azure confidential VMs because of the paravisor design (source S6), and the Veritee code never opens `/dev/sev-guest` (`server/azure_attestation_server/src/enclave_key.rs:9`). `MSG_KEY_REQ` derived keys are reached through `/dev/sev-guest` in Linux (S7). **Position: SNP-derived keys are not available to Veritee on Azure, and they would be the wrong key anyway**, because the SNP launch measurement covers the Microsoft paravisor and not the Veritee image (S5: "Guest OS: TPM Quote (PCRs)"; "Guest Paravisor (including vTPM): Hardware Report"). Check on a deployed VM: `ls /dev/sev-guest` fails.
- The hardware report carries the vTPM attestation key: runtime claims list `HCLAkPub` and `HCLEkPub`, the report's `report_data` is the hash of the runtime claims, and a 64-byte `user-data` claim is read from NV index `0x01400002` (S5).
- Each confidential VM "has its own virtual TPM, where customers can seal their secrets/keys" (S4). The vTPM state lives in the VMGS blob, "always encrypted", with a platform-managed key when the OS disk is not confidential-encrypted (S4), which is the Veritee setting (`cli/deploy-azure-snp/main.tf:257`). The lifecycle of the VMGS blob is tied to the OS disk, and Azure creates VMs from snapshots and restore points that include vTPM state (S8, written for Trusted Launch; **[assumption]** the same holds for confidential VMs, test in section 9.3). This is why a vTPM NV counter is not a rollback defence here: the host restores it with the disk.
- The SNP policy of an Azure CVM reports `migration-allowed: false` (S3 example token). RAM is not cloned by live migration.

### 2.2 Evidence classes (closes the attestation oracle)

Today `report_data = SHA256(JSON{nonce,payload})` for any caller (`main.rs:650-659`, `:736-748`), and the akx epoch key is bound through the same public path with a constant nonce (`enclave_key.rs:40-55`). A verifier cannot tell a key the enclave holds from bytes a caller supplied.

New rule. The 64-byte user data is

```
user_data = SHA-256( "VT1/ud" ‖ class(1) ‖ body_hash(32) ) ‖ 0^32
```

| class | body | who can request it |
|---|---|---|
| 0x00 | `SHA-256(JSON{nonce,payload})`, as today | public `GET /tee_attestation` |
| 0x01 | akx epoch key: `"VT1/akx" ‖ epoch(8) ‖ pk_e(32)` | attestation server, internal |
| 0x02 | BootClaim (section 4.3) | `seald`, internal |
| 0x03 | NodeKeys (section 5.3) | `seald`, internal |
| 0x04 | provisioning key `PVK` (section 6.3) | `seald`, internal |

The public HTTP handler hard-codes class 0x00. Classes 0x01 to 0x04 exist only on the Unix socket `/run/veritee/attest.sock` (mode 0600, peer credential check for uid 0), which no container mounts. A verifier accepts a key only under its own class. The vTPM quote that accompanies the report carries qualifying data `SHA-256("VT1/q" ‖ user_data)`; today both quote calls pass none (`main.rs:447-460`).

### 2.3 Evidence bundle and verification

```
EV := snp_report(1184) ‖ runtime_data ‖ vcek_chain ‖ ak_cert_chain ‖ tpm_quote{msg, sig, pcrs[0..15]} 
```

A verifier (peer enclave, CLI, Warden) runs all of these checks; one failure rejects.

1. `vcek_chain` ends in the pinned AMD root for the CPU family; the report signature verifies.
2. Report policy: debug off, migration off. Reported TCB (bootloader, TEE, SNP firmware, microcode) is at or above the floors in the Midnight Image Registry. Launch measurement is in the registry's allowed set for the paravisor. No value is taken on first use.
3. `report_data[0..32] = SHA-256(runtime claims)`; the claims contain `HCLAkPub` and `user-data = user_data`.
4. `ak_cert_chain` ends in the pinned "Azure Virtual TPM Root Certificate Authority 2023" (already shipped in `server/guest_attestation/veritee_attestation/`) and certifies `HCLAkPub`. This pins hardware custody to Azure datacenters (section 10 uses this).
5. The quote verifies under `HCLAkPub`, its qualifying data matches, and its PCR digest matches `pcrs`.
6. PCR 4 and the PCR 15 chain match an image that the registry lists as approved for the current epoch. PCR 12 and 13 are zero. PCR 14 is the cap value of section 3.3 once the node is admitted.
7. `vm_id = SHA-256(HCLAkPub modulus)` matches the Node Record slot.
8. The class and body are the expected ones.

Committee nodes run the `raw-report` build. The `maa` build puts a Microsoft-signed token with an 8-hour lifetime (S3) and a hard-coded instance (`main.rs:801`) between the hardware and the verifier, and it is not used on the committee path.

---

## 3. Gap 1: no sealed storage

### 3.1 Threat

The persist partition is plain ext4 with a fixed partition UUID (`veritee-os/mkosi/combined.repart/30-persist.conf`), mounted before any measurement (`measured-setup.service`: `ExecStartPre=/bin/sh /usr/lib/temenos/mount-persist`), and bound into the app container (`projects/mpc-node/run.d/docker-compose.yml:28`, `:64`). An operator exports the disk and reads every key share, epoch key and slot ledger on it. The repository says so: "Guest lockdown does not establish confidentiality of persisted data" (`AGENTS.md:69`). Nothing in the image disables swap, core dumps, ptrace or kexec, and no Rust secret type is zeroized.

### 3.2 Practice found

- **Local seal.** Azure documents the per-VM vTPM as a place to seal secrets (S4). Linux SNP guests elsewhere derive sealing keys from the secure processor with `SNP_GET_DERIVED_KEY` (S7). Both are local roots, and section 2.1 shows why a local root gives no freshness on Azure.
- **Key managers that release after attestation.** Phala dstack derives a per-app sealing key `KDF(RootKey, (deployer_id, app_hash, nonce, "seal", epoch))` inside a KMS enclave, checks the workload measurement against an on-chain allowlist before release, revokes by removing the measurement, and treats an app update as a key rotation; it names the KMS as a single point of failure and leaves threshold generation of the root key as an option (S13, S14). Oasis publishes a signed policy that says which enclave identities may query keys and which may replicate the master secret (S16). Confidential Containers splits the same job into a key broker, an attestation service and a reference-value service (S15). Flashbots BuilderNet lets the TDX image pull its disk encryption key from a central BuilderHub and calls that a stopgap (S17).
- **Lesson.** The industry answer is "the disk key comes from a key manager that checks attestation and an on-chain allowlist". The weak point of every example is the key manager itself: one enclave or one service. A signing committee already is a threshold of mutually attesting enclaves, so the committee is the key manager and no new trusted service appears.

### 3.3 Design

**Keys.**

```
K_tpm   : 32 random bytes, created at first boot (getrandom XOR TPM2_GetRandom),
          sealed as a TPM keyedhash object under the storage root key.
          authPolicy = PolicyPCR(sha256: 4, 14, 15); no password authorization; fixedTPM, fixedParent, noDA.
          Unsealed over a salted HMAC session with parameter encryption.
ctx_e   : "VT1/ctx" ‖ committee_id(32) ‖ node_id(2) ‖ vm_id(32) ‖ epoch(8)
K_grp   : HKDF-SHA256( ikm = enc(P), salt = "VT1/kgrp", info = ctx_e ),
          P = Σ_j λ_j · P_j,   P_j = σ_j · HashToGroup("VT1/dprf" ‖ ctx_e)   over ristretto255
K_seal  : HKDF-SHA256( ikm = K_tpm ‖ K_grp, salt = "VT1/kseal", info = ctx_e )
K_ring, K_vol_enc, K_vol_mac : HKDF-Expand(K_seal, "VT1/ring" | "VT1/vol-enc" | "VT1/vol-mac")
```

σ is the **seal-group secret** of epoch e: a ristretto255 scalar that the committee generates by DKG at each epoch boundary, shared t_g = 7 of 9, with public share commitments `S_j = σ_j·G` in the Epoch Key Set. A peer sends `P_j` with a Chaum-Pedersen proof that `log_G S_j = log_h P_j`, so a wrong partial is detected and attributed. No party learns σ, and a node learns only its own `K_grp`.

**PCR policy.** PCR 4 is the UKI (kernel, initrd, command line with the root hash). PCR 15 at unseal time is `E(E(0, app_root_hash), 0^32)`, the value after `measured_setup` and before the TLS extension (`veritee-os/measured_setup/main.py:91-133`); the full PCR 15 changes on every boot in `internal` TLS mode and cannot be a policy input. PCR 14 is zero at unseal time **[assumption: unused in a UKI boot without shim; test in section 9.3]**. Directly after the unseal `seald` extends PCR 14 with `SHA-256("VT1/seal-cap")`, so `K_tpm` cannot be unsealed again until the next boot, and the later TLS extension moves PCR 15 as a second lock. There is no signed or authorized PCR policy: no signer can move `K_tpm` to another image.

**Two sealed tiers on disk.**

| Tier | Key | Content | Why |
|---|---|---|---|
| 0, boot store | `K_tpm` only | `committee_id, node_id, vm_id`, provisioning secret key `PVK`, the node's σ shares for the current and grace epoch, the witness log this node keeps for its peers | must open before the group answers; needed to serve peers during a cold start |
| 1, keyring | `K_ring` | committee key shares, T1 dealt shares after transfer, epoch secret keys (`EK_i`, `PK_i`, post key), highest secret versions, own release ledger | everything whose loss or exposure matters |
| volume | `K_vol_*` | board cache, databases, logs | bulk data; dm-integrity (HMAC-SHA256) under dm-crypt (AES-256-XTS), parameters fixed in the measured image, no on-disk header trusted |

```
tier-0 blob := "VTS0" ‖ ver(1) ‖ len(2) ‖ TPM2B_PUBLIC ‖ len(2) ‖ TPM2B_PRIVATE ‖ nonce(24) ‖ XChaCha20-Poly1305(K_tpm, pt, aad = "VTS0" ‖ ver)
tier-1 blob := "VTS1" ‖ ver(1) ‖ ctx_e ‖ seq(8) ‖ nonce(24) ‖ XChaCha20-Poly1305(K_ring, keyring, aad = "VTS1" ‖ ver ‖ ctx_e ‖ seq)
```

Tier 0 lives on a new 16 MiB raw partition `seal`. The volume gives confidentiality and detects corruption; it does not claim freshness, because per-sector authentication does not stop a mix of old and new sectors. Freshness is claimed only for the tier-1 blob, through its `seq` and digest (section 4).

**Never on disk.** Plaintext requests, decrypted data keys, boot keys, akx session keys, the combined `K_grp`, `K_seal`, and any nonce share between its decryption and its PARTIAL. A reboot loses them and the board supplies the ciphertext again.

**Erasure.**

- Rust secrets use `zeroize` with `ZeroizeOnDrop` and live in `mlock`ed, `MADV_DONTDUMP` pages. `seald` and the app call `mlockall(MCL_CURRENT | MCL_FUTURE)` and `prctl(PR_SET_DUMPABLE, 0)`.
- Image: no swap unit and `systemd.swap=0`; `DefaultLimitCORE=0`, `kernel.core_pattern=|/bin/false`, `fs.suid_dumpable=0`; `kernel.kexec_load_disabled=1`; `kernel.yama.ptrace_scope=2`; `init_on_free=1` on the kernel command line; Docker default ulimit `core=0`.
- An overwrite of a block on an Azure managed disk proves nothing, because the operator holds snapshots. Erasure of persisted data is therefore **key destruction**: at the end of the grace period of epoch e each node zeroizes its epoch-e keyring keys and its σ_e share in RAM, rewrites tier 0 without the σ_e share, and stops answering PRF requests for `ctx_e`. Once n − t_g + 1 = 3 honest enclaves have done this, no party can recompute `K_grp` for epoch e from live nodes.
- Retirement ends with `poweroff`, not reboot. The SNP memory key belongs to one VM launch, so the RAM image dies with the launch.

### 3.4 What it stops and what it does not

Stops: reading a disk export or snapshot; reading it with a stolen `K_tpm` alone; opening state under an image other than the one that sealed it; opening state after the registry revokes the image, while a quorum of honest enclaves is alive; reading swap or core files.

Does not stop: a platform owner who breaks the paravisor reads `K_tpm`; t_g = 7 operators who each keep a tier-0 snapshot from epoch e and each obtain `K_tpm` (through a paravisor break or through a formerly approved image with an extraction bug) recompute σ_e and open every tier-1 snapshot of that epoch. Reshare does not change the committee key, so old shares of one epoch still reconstruct it. This is a bound of TEE mode; R1 does not rest on it.

### 3.5 Lifecycle

- **Reboot (same VM).** vTPM state persists; `K_tpm` unseals; tier 0 opens; admission (section 4.3) yields `K_grp`; tier 1 opens. The keyring and epoch keys survive. RAM-only items are gone.
- **Redeploy (new VM, same image).** New vTPM, new `vm_id`, empty disk. Nothing is carried over. The operator signs a slot replacement on Midnight; the new VM joins as a new member at the next epoch boundary through the DKG of σ_{e+1} and the reshare of committee key shares. Until then the slot is down. In-flight T2 requests finish with the other eight nodes (t = 7), as SCHEME section 5 "finish" requires.
- **Image upgrade.** Identical to redeploy, plus the new `image_id` must be approved in the Image Registry before admission. Veritee has no in-place update (`docs/vm-inventory.md:1-4`), and the PCR policy forbids one. At most one slot upgrades per epoch under T2, so the margin never drops below f − 1 = 1 spare fault. Revocation of the old image takes effect at an epoch boundary, or at once in an emergency.
- **Committee reshare.** The new committee runs the σ_{e+1} DKG, each node writes a tier-1 blob for epoch e+1 under the new `K_seal`, commits it (section 4.4), and after HANDOVER and the grace period destroys the epoch-e keys as in 3.3. A member that leaves zeroizes and powers off.

---

## 4. Gap 2: no rollback protection

### 4.1 Threat

The operator restores an old disk and VMGS, or starts a second VM from a copy. In SCHEME open mode a node that forgets its slot ledger entry `(rid, g) → dg` signs a second digest with the same nonce shares; two partials of one node on one slot reveal that node's shares, and t such nodes reveal the address key. SCHEME rule 4 (section 3.9) tells a restored node to replay the board and to abstain where the board shows its own PREVOTE or PARTIAL. That holds for f operators. It needs two things the node cannot get alone: a fresh view of the board, and knowledge of releases that the operator withheld from the board. The same gap lets an old epoch's key shares come back after a reshare, and lets two instances of one node run at once.

### 4.2 Practice found

- **ROTE** (S9): rollback protection is a distributed system. A node writes its counter to assisting enclaves, which keep it in volatile memory; the write needs two rounds, because a one-round echo is defeated by restarting the assisting enclaves one at a time; a restarted enclave waits for new session keys with all peers, which stops a second instance; the sizing is n = f + 2u + 1; if all nodes restart together the group halts and its owner re-initializes it. The guarantee is "all-or-nothing rollback".
- **Nimble** (S10): endorsers in TEEs hold only the tail of an append-only ledger in volatile memory and sign `(tail, client nonce)`; a quorum of signatures proves freshness; endorsers "have no API to rollback their state"; the system separates safety (in the TEE) from liveness (outside); a new configuration takes over only after a quorum of the old one renounces; if a majority of endorsers is lost the ledger is unavailable for good.
- **Narrator** (S11): uses a blockchain only to initialize the group of TEEs and keeps frequent updates off-chain, because a chain transaction per state update costs minutes; it reports a flaw in ROTE's restart protocol.
- **Local counters.** ROTE measures SGX counter writes at 80 to 250 ms with a write limit reached in days; Narrator cites about 97 ms for a TPM counter update. On Azure a vTPM counter is also inside the VMGS snapshot (section 2.1).

Lessons taken: peer enclaves are the counter; a nonce in the answer gives freshness; restarts need a single-instance rule; a total restart needs an anchor outside the group. Fenrir already has both an inner ledger (the BFT board) and an outer anchor (Midnight), so Narrator's split applies directly, and the board removes ROTE's halt on total restart because votes and locks are public and durable there.

### 4.3 Design, part 1: admission with a boot ticket

Every boot runs this before the node posts, signs or decrypts anything.

```
BootClaim := "VT1/boot" ‖ committee_id(32) ‖ node_id(2) ‖ vm_id(32) ‖ image_id(32)
             ‖ boot_ctr(8) ‖ bk_sig(32) ‖ bk_kem(32) ‖ rand(32)
```

`bk_sig` (Ed25519) and `bk_kem` (X25519) are the **boot key**, generated in RAM at this boot. `boot_ctr` is the registry value plus one. `image_id = SHA-256(PCR4 ‖ PCR15_setup)`.

1. `seald` unseals `K_tpm`, opens tier 0, creates the boot key, and obtains evidence `EV` of class 0x02 over `SHA-256(BootClaim)`.
2. The operator's agent and the Warden submit `admitBoot(BootClaim, SHA-256(EV), operator_sig, warden_sig)` to the Midnight **Node Registry**. The contract requires the slot's operator key, `boot_ctr = stored + 1`, an approved `image_id`, and stores `(boot_ctr, SHA-256(bk_sig ‖ bk_kem))`. **[assumption]** Compact does not verify SNP evidence; the Warden signature stands for that check on chain, and the operator signature stops anyone else from superseding a live node.
3. The node waits for the finalized block that contains its claim. `rand` is fresh, so that block is later than this boot. The proof of inclusion is the **boot ticket**; `seald` gets it from the in-guest follower described below.
4. Over mutually attested channels (akx with both boot keys and both boot counters in the transcript, each side signing) the node sends `BootClaim ‖ EV ‖ ticket` to its peers. Each peer verifies `EV` itself (section 2.3), checks the ticket, drops every session with an older boot of this node, and answers:

```
ADMIT_ACK_j := sig_bk_j( "VT1/ack" ‖ SHA-256(BootClaim) ‖ epoch(8) ‖ board_height_j(8) ‖ board_root_j(32)
                         ‖ SHA-256(witness entries of node i) )
               ‖ witness entries of node i ‖ P_j ‖ DLEQ_j
```

5. With w = 6 valid acks the node combines `K_grp`, opens tier 1, takes the union of the witness entries, sets its replay floor to the maximum of the reported board heights and the latest board checkpoint that Midnight held at the ticket block, replays the board to that floor, and posts `BOOT(node_id, boot_ctr, bk_sig)`. From that board position the board accepts posts of node i only under this boot key.

**Where admission runs.** `seald` is a host service of the base image and holds no chain client. Three things must be up before the app, so `measured_setup` starts them in a platform phase that needs no secret: Caddy (peers reach `seald` at `https://<attestation-host>/seal/*`, proxied to the host like `/tee_attestation*` is today; the payload is an end-to-end mutually attested akx channel, so Caddy carries ciphertext), the `guest-attestation` helper, and a Midnight finality follower that serves finalized headers and inclusion proofs to `seald` on loopback. The follower stores public chain data on a tmpfs and gets no key. **[assumption]** Such a follower exists as a container; `projects/indexer-standalone` is the nearest thing in the repository. A stale follower delays admission and cannot fake it, because the node's own ticket contains fresh randomness and a peer's ticket is checked against a finalized header. Outbound peer traffic leaves through the platform egress proxy; the peer hosts are a measured list in `metadata.json` `platform_outbound`.

**Group uniqueness.** Narrator reports that ROTE's restart can be driven to create two parallel groups, and repairs it by making members confirm they are still in the group before they accept a restarted member (S11; the appendix with the attack is in the extended version and was not available). Here the Node Registry decides membership: one boot key per slot, set by a chain transaction. A peer answers admission, PRF and witness requests only while its own boot key is the registry's current one at its follower's tip, and a requester counts an answer only from a boot key that is current at its own ticket block or later.

A clone must pass admission to open tier 1, and its admission supersedes the original. A zombie (the superseded instance, still in RAM) cannot post, and cannot release, by part 2.

### 4.4 Design, part 2: witnessed commitment

A commitment is any output that a node may make at most once: its PREVOTE for `(rid, g)` in open mode, its sealed release for `(rid, g)`, a keyring commit for an epoch, a new secret version. The witness sits on the PREVOTE, not on the PARTIAL. Two locks for one `(rid, g)` are fatal even if no node signs twice: under T1 three honest nodes can sign `dg` and three others `dg′`, and the two finished signatures share one nonce. Two locks need 2q − n = 3 nodes that vote twice, so the vote is the thing to make unique.

```
WITNESS_REQ := "VT1/wreq" ‖ node_id(2) ‖ boot_ctr(8) ‖ kind(1) ‖ key(34) ‖ value_hash(32)
     kind 0x01 open PREVOTE   key = rid ‖ g         value = dg
     kind 0x02 sealed release key = rid ‖ g         value = SHA-256(j_g)
     kind 0x03 keyring        key = epoch ‖ 0^26    value = SHA-256(seq ‖ tier-1 blob)
     kind 0x04 secret version key = SHA-256(name) ‖ 0^2  value = SHA-256(version)
WITNESS_ACK_j := sig_bk_j( "VT1/wack" ‖ SHA-256(WITNESS_REQ) )
```

A peer enclave acks only if `boot_ctr` is the current one in its view of the registry, and, for kinds 0x01 and 0x02, only if it holds no different value for `(node_id, kind, key)`. It appends the entry to its witness log (tier 0, hash-chained, synced to disk before the ack). For kinds 0x03 and 0x04 it keeps the highest value. A node lets a PREVOTE or a sealed release leave the guest only after it has written its own ledger entry and holds w = 6 acks. Its PARTIAL after the lock is a deterministic function of the slot and of the `dg` it had witnessed (SCHEME 3.8), so it needs no second witness, and a superseded instance that still emits it adds nothing new. Entries for a `rid` are dropped at its tombstone (SCHEME 3.10).

This is ROTE's counter write with two changes. The witnesses store the entry on disk before they ack, so an honest peer's restart loses nothing and one round is enough; ROTE needs its second round because its counters are volatile. A peer whose operator rolls its witness log back is counted among the colluders below. And the entry names the digest, so a restarted node learns exactly which `(rid, g)` to abstain on. The node applies SCHEME rule 4 to the union of its board posts and its witness entries.

The mempool decryption shares and the sealed-point shares after a witnessed selection are deterministic functions of board data, so repeating them is harmless and they need no witness of their own.

**Counting.** Let c operators collude with TEEs intact. Node X votes `dg` after acks from a set W of 6 of its 8 peers. For X to vote `dg′`, a rolled-back or cloned X needs acks from a set W′ of 6 of its 8 peers. W and W′ share at least 6 + 6 − 8 = 4 peers, and each of them refuses unless it has forgotten the entry. A peer forgets only if its own operator rolls it back, so the colluders can supply at most c − 1 forgetful peers. If 4 > c − 1, X cannot vote twice, whether or not its operator withheld the first vote from the board. The same intersection makes admission return the entry, so X also knows where to abstain. One vote per node per `(rid, g)` therefore holds for **c ≤ n − 1 − 2f = 4** (6 of 17 at n = 17, f = 5, w = 11), and with it one lock and one digest per slot. SCHEME alone holds for f = 2. For c ≥ 5 part 3 applies.

### 4.5 Design, part 3: Midnight anchors

- **Checkpoints.** Every Δ board blocks (default 60 s of board time) the committee posts `checkpoint(epoch, board_height, board_root, witness_root)` to Midnight with q signatures, where `witness_root` is a Merkle root over all live witness entries. A booting node replays at least to the latest checkpoint at its ticket block and loads the entries under `witness_root`. Operators cannot move this floor, in any number.
- **`anchor_before_release`.** A request header flag. When set, the lock certificate (or the sealed selection) is posted to Midnight as `anchorLock(rid, g, digest)` with its q votes, the contract stores one digest per `(rid, g)` and rejects a second, and a node sends its PARTIAL only after its follower shows that entry finalized with the digest the node built. Then one digest per slot holds for every c with TEEs intact, at the price of one Midnight finality delay per signing. Default: on for open-mode requests under T1, where three partials finish a signature; off elsewhere.
- **Epoch floor.** The Epoch Key Set on Midnight names the current epoch. A node whose opened keyring is older than the registry epoch minus the grace period zeroizes it and waits for the next reshare. Old shares never sign.

### 4.6 What it stops and what it does not

Stops, with TEEs intact: a second vote, a second lock and so nonce reuse after disk rollback, including the case where the operator withheld the node's first vote from the board (c ≤ 4, or any c with the flag); two live instances of one node (the ticket and the boot-key rule); use of resurrected shares after a reshare (epoch floor, and no `K_grp` for a closed epoch); replay of an old operator secret (kind 0x04).

Does not stop: denial of service by an operator who rolls its node back again and again (the node abstains and the slot is lost for that node); any of the above once the TEE itself is broken, where the bound returns to SCHEME's f; double release in sealed mode by a fully corrupt committee, which SCHEME already makes harmless because each sealed point is a signature the owner made on a transaction spending one pinned input.

### 4.7 Lifecycle

- **Reboot.** Full admission. Boot counter + 1. One Midnight transaction, then one round with peers.
- **Total restart of the committee.** No halt. The platform phase (Caddy, follower, `seald`) needs no group secret. Tier 0 opens locally on each node, tickets come from Midnight, each node answers peers as soon as its own tier 0 is open and its own ticket is final, and the witness logs are on disk in tier 0. Seven nodes with intact tier 0 are enough. ROTE halts in this case because its counters are volatile and its group has no outside anchor.
- **Redeploy and image upgrade.** The new VM has no ledger. It is a new member from the next epoch; it holds no slot of an older epoch, so it has nothing to replay.
- **Reshare.** The new tier-1 blob is committed with kind 0x03 before the node posts READY. Witness entries of unfinished requests move with the request: the checkpoint that contains `ROTATE` carries `witness_root`, and new members load it.

---

## 5. Gap 3: no offline encryption to an enclave

### 5.1 Threat

The only attested key is the Ed25519 signing key `pk_e` of the attestation server, new at every process start (`main.rs:884-892`). Recipient keys exist per session for at most 300 s (`server/akx/src/session_store.rs:51-52`), and plaintext ends in the host attestation server, which forwards it over loopback (`services/attestation_server.service:23`). An owner who must act once from an offline wallet has nothing to encrypt to. SCHEME's dealing does encrypt to per-node epoch keys `PK_i`, but nothing ties `PK_i` to an enclave: an operator can publish a `PK_i` whose secret it holds and read every share dealt to its node.

### 5.2 Practice found

- **HPKE, RFC 9180** (S12): a single-shot mode exists for one message to a public key. The RFC is explicit about the limits: "HPKE does not provide forward secrecy with respect to recipient compromise", "HPKE provides no other replay protection", and Base mode does not authenticate the sender. The `info` parameter binds context for the whole encryption context and `aad` binds per-message data. akx already uses suite DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001, AES-256-GCM 0x0002 through the `hpke` crate (`server/akx/Cargo.toml`).
- **Key published by a governed registry.** dstack requires the root public key on chain so anyone can verify application keys, and gates changes with a multisig and a timelock (S13, S14). Oasis publishes key-manager policy and status through consensus (S16).
- **Binding a key into evidence.** Azure's own guidance ends with "Bind any subsequent protected exchange to the attested guest and intended recipient key; a valid quote alone doesn't secure that exchange" (S18). Azure SKR and the guest attestation token do this with an RSA key in the `x-ms-runtime.keys` claim (S3).

### 5.3 Design

**Keys, per node and epoch, generated in the guest by `seald` and kept in the tier-1 keyring.**

```
NodeKeys_i := "VT1/keys" ‖ committee_id(32) ‖ epoch(8) ‖ node_id(2) ‖ vm_id(32) ‖ boot_ctr(8) ‖ image_id(32)
              ‖ suite(2) ‖ EK_i(32) ‖ PK_i(33) ‖ post_i(32) ‖ S_i(32) ‖ not_before(8) ‖ not_after(8)
```

`EK_i` is the X25519 HPKE key. `PK_i` is the SCHEME dealing key on the signature curve. `post_i` is the board post key. `S_i` is the node's σ commitment. `not_before` and `not_after` are board heights. The node obtains evidence of class 0x03 over `SHA-256(NodeKeys_i)` and sends both to its peers. Each peer verifies the evidence in its own guest and signs `"VT1/kack" ‖ SHA-256(NodeKeys_i)`.

**Epoch Key Set.** `EKS_e := "VT1/eks" ‖ committee_id ‖ epoch ‖ MerkleRoot(NodeKeys_1..n) ‖ t(2) ‖ not_before ‖ not_after`. The Midnight **Key Registry** stores `EKS_e` when it carries, for every listed node, w peer acks under boot keys that the Node Registry holds, and the Warden's signature. It also stores the hash of each evidence bundle; the bundles are served by any node and by the Warden.

**What the offline wallet does.** It reads `EKS_e` for the newest epoch whose window covers its intended posting height, fetches the nine `NodeKeys` with Merkle paths, and encrypts. Its trust is the Midnight contract plus the rule that six enclaves and the Warden checked each key. A wallet that wants no trust in them fetches the evidence and runs the checks of section 2.3 itself. Suite 0x0001 is HPKE 0x0020/0x0001/0x0002, the akx suite. The `suite` field lets an epoch switch to a hybrid post-quantum KEM without a format change; the board is public and permanent, so that switch is scheduled as soon as the wallet stack supports one.

**Envelope to one node.**

```
SealedToNode := "VTE1" ‖ suite(2) ‖ committee_id(32) ‖ epoch(8) ‖ node_id(2) ‖ purpose(1) ‖ enc(32) ‖ len(4) ‖ ct
info := "VT1/env" ‖ committee_id ‖ epoch ‖ node_id ‖ SHA-256(NodeKeys_i)
aad  := purpose ‖ rid(32) ‖ SHA-256(public header of the request)
```

Single-shot HPKE Base mode. `purpose`: 0x02 request leg addressed to one node, 0x10 operator secret. Binding `SHA-256(NodeKeys_i)` into `info` means a ciphertext opens only under the exact attested record the sender saw. Replay protection is the board's `rid` rule (SCHEME claim 6) plus `rid` in the `aad`; the node keeps no replay cache. The sender is authenticated inside the plaintext by what the protocol already requires (the dealing's address binding, or the owner's signature).

**Envelope to the committee (threshold).**

```
SealedToCommittee := "VTC1" ‖ committee_id ‖ epoch ‖ t(2) ‖ E(33) ‖ eph_proof ‖ C_0..C_{t-1} (33 each)
                     ‖ c_1..c_n (32 each) ‖ nonce(12) ‖ body_ct
c_i  := p(i) + Hq( "VT1/dkpad" ‖ rid ‖ i ‖ PK_i ‖ K_i )  mod q,     K_i = e·PK_i,  E = e·G
DEK  := HKDF-SHA256( enc(p(0)), salt = "VT1/dek", info = rid )
```

The data-key shares reuse the dealing machinery of SCHEME 3.2 and 3.4 on the signature curve: a polynomial `p` of degree t − 1, Feldman commitments `C_k = p_k·G`, one ephemeral key `E` with its proof of knowledge, and a pad per node from `K_i`. The body is encrypted with AES-256-GCM under `DEK` with the public header as `aad`. Node i checks `p(i)·G` against the commitments. A complaint is the point `K_i` with a proof that `log_G PK_i = log_E K_i`; anyone then removes the pad and checks the share, so a true complaint voids the request and a false one is attributable to the node, as for dealt shares. A node sends `p(i)` to the combiner only when a quorum certificate fixes the request's position on the board. Fewer than t nodes hold fewer than t points of `p`; the commitments hide `p(0)` under the discrete-log assumption and `DEK` is a hash of it. This object gives B3 in TEE mode now and is unchanged in non-TEE mode, where the rule "share after order" is enforced by the honest quorum and not by the enclave. `SealedToNode` stays in use where no public complaint is needed: a request leg for one node, and operator secrets.

SCHEME's own dealing ciphertext (`ct`, pad from `K_i = e·PK_i`) stays as it is. The change is that `PK_i` now comes from `NodeKeys_i`.

**The app holds the key.** Decryption runs in `seald` and the result goes to the app over `/run/veritee/seal.sock`. The interactive `/proxy` path through the attestation server is not used for owner traffic.

### 5.4 What it stops and what it does not

Stops: an operator substituting its own key for an enclave key; a ciphertext being opened by a node on a different image or a later boot record than the sender saw; replay under another `rid`; decryption before ordering by fewer than t nodes.

Does not stop: disclosure of every envelope of an epoch if that node's `EK_i` or `PK_i` secret leaks during the epoch (RFC 9180, no forward secrecy toward the recipient). The exposure is one share per envelope, which is below t, and it ends when the epoch keys are destroyed. A sender who uses a stale `EKS` is rejected at the board by the public `epoch` field and loses nothing but the attempt.

### 5.5 Lifecycle

- **Reboot.** The epoch secrets are in the keyring and survive. The node re-binds the same public keys to its new boot counter with a fresh class-0x03 evidence and a board post; the Key Registry entry does not change, and `SHA-256(NodeKeys_i)` in `info` stays that of the published record.
- **Redeploy and image upgrade.** The old node's epoch secrets are gone. Envelopes already ordered are served by the other eight nodes. The new VM publishes keys in the next `EKS`.
- **Reshare.** `EKS_{e+1}` is published one grace period before `ROTATE`. Epoch-e keys stay usable for requests ordered before `ROTATE` and during the grace period, then are destroyed (section 3.3). An owner's request needs its keys only from posting to ordering; after ordering the shares live in keyrings and move by SCHEME's transfer where the profile allows it.

---

## 6. Gap 4: secrets not gated on attestation

### 6.1 Threat

The run hook fetches `temenos-tls-privkey-pem` from Azure Key Vault with a managed-identity token from IMDS, and takes the vault name from an IMDS tag (`projects/templates/run.d/main:57-123`). Key Vault releases to the identity, whatever the VM runs. The operator uploaded that key, sets the tag, and can read or replace the secret. The Warden gets its wallet seed the same way (`projects/warden/README.md:51-56`). A debug image with a root password receives the same secrets as a release image.

### 6.2 Practice found

- **Azure Secure Key Release** (S2, S3, S26): an HSM-backed exportable key carries a release policy; the VM sends an MAA token; the vault wraps the key to an RSA key from the token's `x-ms-runtime.keys` claim. The grammar page states "In the first iteration, the only allowed condition is 'equals'" and "Array specifications aren't presently supported". The confidential-VM example token lists `x-ms-azurevm-attested-pcrs: [0..7]`, the launch measurement, the VM id and Secure Boot flags; it shows no PCR values and nothing for PCR 15. The concept page (September 2026) says vTPM tokens can carry an `x-ms-azurevm-attested-pcr-values` claim that a policy can gate on; no Microsoft page read here shows that claim covering PCR 15 on a confidential VM, and the grammar's array limit applies to it. The caller needs a managed identity with the `release` permission, and the example response shows `"immutable": false` on the policy. Microsoft's dm-verity guide says the same from the other side: "Verifying the VM environment through guest attestation doesn't by itself establish that a workload image is approved", and it puts the approval decision in a separate relying party, a "release broker" (S18).
- **Release brokers elsewhere.** dstack's KMS checks the quote, then on-chain allowlists, then releases (S13). Google Confidential Space grants a workload identity only when attribute conditions on the attestation token hold, and states that the operator "can't influence or modify the workload code or execution environment" (S19). Trustee's KBS releases resources after its attestation service validates evidence against reference values (S15). BuilderNet's TDX image bootstraps from a central BuilderHub and pulls its disk encryption key from it (S17).

**Position.** SKR is not the gate. The deciding reason is ownership: the party the gate must exclude (the operator) owns the vault, the key, the mutable policy and the identity, and the verifier is Microsoft's service. The documented token also does not pin the Veritee app measurement. An operator may add SKR to its own vault as a second lock on the ciphertext blobs of section 6.3; no guarantee in this document depends on it. The release broker for committee secrets is the committee. The release broker for operator secrets is the operator's own CLI, which encrypts to an attested key.

### 6.3 Design

| Secret | Source | Rule |
|---|---|---|
| Committee key shares, σ shares, data-key shares | DKG, reshare, envelopes | exist only in enclaves; no provisioning path |
| Boot key, epoch keys, akx key | generated in the guest | bound by evidence classes 0x01 to 0x03 |
| TLS private key | generated in the guest (Caddy internal CA, or ACME with a guest-generated key kept in the keyring) | `azure_vault` TLS mode is refused when `metadata.json` sets `"secrets_policy": "attested-only"` |
| Operator secrets (Warden wallet seed, API tokens, ACME account key) | `veritee secret seal` | `SealedToNode` with purpose 0x10 |

**Provisioning key.** At first boot `seald` creates an X25519 key `PVK`, stores the secret in tier 0, and serves `PVK ‖ EV` (class 0x04, body `"VT1/pvk" ‖ vm_id ‖ image_id ‖ PVK`) at `GET /provision-key`. It exists before the node has epoch keys, so a fresh deployment can receive secrets.

**`veritee secret seal --node N --name K --version V --in FILE`.** The CLI fetches `PVK ‖ EV`, runs the full checks of section 2.3 against the Image Registry (the CLI does no cryptographic verification today, `cli/veritee/cli.py:1131-1136`), and writes

```
SealedToNode(purpose 0x10), info = "VT1/env" ‖ committee_id ‖ 0^8 ‖ node_id ‖ SHA-256(vm_id ‖ image_id ‖ PVK),
                             aad  = 0x10 ‖ SHA-256(name) ‖ version(8)
```

The ciphertext is stored anywhere: a Key Vault secret used as a plain blob store, or instance user data. The guest fetches it, `seald` opens it, records `(name, version)` with a kind-0x04 witness and refuses a lower version, and hands the plaintext to the one container named in the measured `metadata.json` over the seal socket. The IMDS tag that names the vault remains untrusted input: a wrong vault yields a ciphertext that does not open.

**Release by the committee.** `K_grp` (section 3.3) is the attestation-gated release for everything at rest. A peer evaluates the PRF only for a node with a valid ticket, an approved image and the current boot counter.

### 6.4 What it stops and what it does not

Stops: a subscription admin reading secrets from the vault; secrets reaching a debug or modified image; the operator holding the TLS key of an attested endpoint; replay of an old secret version.

Does not stop: the operator knowing the secrets it supplied itself (a wallet seed it generated is known to it; a seed that must be unknown is generated in the guest and never exported); misuse of a secret by the approved app.

### 6.5 Lifecycle

- **Reboot.** `PVK` is in tier 0; stored ciphertexts open again. The highest versions are in the keyring and in peers' witness logs.
- **Redeploy and image upgrade.** New `vm_id` or `image_id`, new `PVK`. The operator re-seals its secrets to the new key after verifying it. Nothing sealed to the old key opens on the new VM.
- **Reshare.** No effect on operator secrets. Committee secrets move by the reshare itself.

---

## 7. One node lifecycle

| Step | What happens | Fix |
|---|---|---|
| Boot | UKI and root verified (PCR 4). `measured_setup` phase 1 extends PCR 15 with the app root hash, opens verity, installs the egress policy. `seald` unseals `K_tpm`, opens tier 0, caps PCR 14. The platform phase starts Caddy, `guest-attestation` and the Midnight follower; none of them holds a secret. | 1 |
| Attest | `seald` creates the boot key and gets class-0x02 evidence. Boot ticket on Midnight, boot counter + 1. | 2 |
| Obtain secrets | Peers verify evidence and ticket, return acks, witness entries and PRF partials. `K_grp`, `K_seal`, tier 1 and the volume open. Operator secrets open under `PVK`. `measured_setup` phase 2 starts the app. | 1, 2, 4 |
| Catch up | Replay the board to the floor; apply rule 4 to board posts and witness entries; post `BOOT`. | 2 |
| Join epoch | At the next boundary: σ DKG, new epoch keys, class-0x03 evidence, peer acks, `EKS` on Midnight, reshare of committee key shares, keyring commit (kind 0x03). | 1, 3 |
| Receive dealings | Owners encrypt to `EKS_e`. The board orders ciphertexts. After the quorum certificate the node sends its data-key share to the combiner; the body opens in RAM only. Dealt shares are decrypted from the board with `PK_i` when needed. | 3 |
| Sign | Build the transaction, write the ledger entry, witness request (kind 0x01), w acks, then PREVOTE. On LOCK for the same digest (and its `anchorLock` if the flag is set): PARTIAL, then zeroize the nonce shares. | 2 |
| Erase | At FINAL or VOID: zeroize the shares of the `rid`, drop its witness entries. At the end of the grace period: destroy epoch keys and the old σ share, rewrite tier 0. | 1 |
| Upgrade | A new image is approved in the Image Registry. A new VM is deployed, receives operator secrets under its new `PVK`, joins at the next boundary. The old VM leaves at that boundary. | 1, 4 |
| Retire | Zeroize, `poweroff`. The registry removes the slot. The operator deletes disk and VMGS; nothing depends on that deletion below the bound of section 3.4. | 1 |

---

## 8. Use by the signing committee

**Sealed user dealings.** The owner's one message is encrypted to `PK_i` from the Epoch Key Set, so each share reaches an enclave and no operator. Shares rest only in the tier-1 keyring or are decrypted again from the board. A sealed release is witnessed (kind 0x02), so a committee of honest enclaves releases one variant even after rollbacks.

**Threshold-encrypted mempool.** `SealedToCommittee` hides request content, owner, intent and covenant terms from operators and from the board until a quorum certificate orders the request (B1 to B3). In TEE mode a node's share release is a function of that certificate. Bodies exist in RAM only.

**Presignature and nonce slots.** In line dealing the owner deals the nonce shares, so no presignature protocol runs. The durable slot ledger of SCHEME rule 3 becomes three records: the node's ledger in the keyring, the peers' witness entries made before the PREVOTE, and the board. Rule 4 gets a fresh floor from admission and Midnight. Decrypted nonce shares never reach the disk and are zeroized after the PARTIAL; destroying the epoch key at the end of the grace period makes the board ciphertext of unused slots unreadable.

**Reshare.** Applies to committee-held address key shares of the co-custody design and to T1 dealt shares; T2 requests finish or void, as SCHEME section 5 states. σ is regenerated, keyrings are re-sealed under the new `K_seal`, old keys are destroyed, and the epoch floor on Midnight keeps resurrected shares from signing. Rotation moves no coins because the committee key itself is never rotated.

**Guarantees that still need the cryptography.** The Azure AK certificate and the VCEK chain say "this is an approved image on Azure hardware". Section 10 lists published attacks that extract secrets or forge that statement with hypervisor or physical access. When a TEE is broken:

| Guarantee | TEE intact | t or more TEEs broken | Carried by |
|---|---|---|---|
| R1, no spend without an admitted authorization | holds | holds | the user's share and sealed mode (SCHEME claim 2, every node corrupt) |
| Sealed points stay sealed below t | holds | holds for fewer than t broken nodes | Shamir secrecy (claim 3) |
| One digest per slot, open mode | c ≤ 4, any c with the flag | f = 2 | witness and anchor in TEE mode; quorum intersection otherwise (claim 4) |
| Mempool content hidden before ordering (B3) | holds for any c | holds for fewer than t broken nodes | `SealedToCommittee` threshold |
| Content hidden from operators after ordering (B1, B2) | holds | lost for a single broken node | TEE only; non-TEE mode needs ZK predicates and MPC |
| Old shares useless after reshare | holds | lost if t_g snapshots of one epoch open | TEE and erasure only |

The non-TEE mode therefore keeps: threshold shares for every secret, publicly checkable dealings, the board's quorum certificates, and Midnight proofs of authorization. The TEE mode adds blindness after ordering and raises the collusion bound for rollback from f to n − 1 − 2f. Nothing in the TEE mode replaces a cryptographic check; each one is an extra condition on the same messages, which is why the non-TEE mode layers on without a redesign.

---

## 9. Implementation plan for veritee-vm

### 9.1 Order of work

| # | Component | Files | Change | Size |
|---|---|---|---|---|
| 1 | Evidence classes and quote nonce | `server/azure_attestation_server/src/main.rs` (`report_data_binding`, `get_attestation`, both `tpm2_quote` calls), `enclave_key.rs`, `vtpm.rs`; new `internal_api.rs` (Unix socket) | class byte, internal socket, qualifying data, akx epoch key moved to class 0x01 | 450 lines Rust |
| 2 | Verifier | new crate `server/veritee-verify` (uses the `sev` crate already in `Cargo.toml`) | checks 1 to 8 of section 2.3, registry policy input, AMD and Azure roots pinned | 1,800 lines + 800 test |
| 3 | akx additions | `server/akx/src/envelope.rs` (single-shot seal and open), `session.rs` and `transcript.rs` (mutual mode), `epoch.rs`, `record.rs`, `session_store.rs` (`ZeroizeOnDrop`) | static-key envelopes, peer channel, zeroize | 600 lines + 300 test |
| 4 | `seald` | new crate `server/seald`, unit `veritee-seald.service`; `tss-esapi` 7.5 is already a dependency | TPM seal and unseal with PolicyPCR, tier 0 and tier 1 blobs, admission client, PRF client and server with DLEQ, witness log, volume setup through `integritysetup` and `cryptsetup` (2.4.3 is in the image), seal socket API | 3,500 lines + 1,500 test |
| 5 | Measured setup | `veritee-os/measured_setup/main.py`, `egress.py`; `mkosi.extra/etc/systemd/system/measured-setup.service`; delete `usr/lib/temenos/mount-persist` | split `main()` into phase 1 (through egress policy), a platform phase (compose profile `platform`: Caddy, `guest-attestation`, follower), `seald open`, and phase 2 (hooks and compose profile `app`); refuse `azure_vault` under `attested-only`; reject `/dev/tpmrm0` for any container except `guest-attestation` | 350 lines + tests |
| 5a | Peer route and firewall | `projects/mpc-node/run.d/Caddyfile.template` (`handle_path /seal/*` to the host on port 8001), `veritee-os/mkosi/rootfs/mkosi.extra/etc/iptables/rules.v4.j2` (port 8001 from `br+`, beside 8000) | peers reach `seald` before the app runs | 20 lines |
| 6 | Image | `veritee-os/mkosi/combined.repart/30-persist.conf` (no filesystem, formatted by `seald`), new `25-seal.conf` (16 MiB raw), `mkosi.conf.j2` kernel command line, sysctl and systemd drop-ins, Docker daemon ulimits | storage layout and the erasure settings of 3.3 | 120 lines config |
| 7 | MPC node project | `projects/mpc-node/metadata.json` (`secrets_policy`, a measured egress allowlist in place of `unrestricted`), `run.d/docker-compose.yml` (profiles `platform` and `app`, a follower service, mount `/run/veritee/seal.sock`, `ulimits: core: 0`), `projects/templates/run.d/main` (remove the Key Vault TLS fetch for this profile) | app uses the seal socket; no plaintext `/data` secrets | 150 lines |
| 8 | CLI | `cli/veritee/cli.py`, `cli/veritee/attested_channel.py` (its binding check at `:342-360` recomputes the old constant-nonce payload and must use class 0x01), new `cli/veritee/verify.py` and `secret.py` | local verification through `veritee-verify`, `secret seal`, `node-keys`; hydration reads measurements from the registry | 750 lines Python |
| 9 | Stale script | `compute-pcr15.py` | model all three extensions and the PCR 14 cap | 60 lines |

Steps 1 and 2 come first because every later step depends on evidence that a caller cannot forge. Total: about 7,800 lines of code and 3,000 of tests.

### 9.2 Tests

- Unit: class separation (a public request never yields classes 0x01 to 0x04); envelope vectors against RFC 9180 test vectors; PRF combine and DLEQ rejection; blob formats; witness refusal of a second value.
- Software TPM (`swtpm`) in CI: seal, reboot, unseal; unseal fails after the PCR 14 cap; unseal fails under a different PCR 4 or PCR 15 setup value.
- Nine-node simulation with a fake attester (the akx `FakeAttester` pattern): a rolled-back node whose first PREVOTE was withheld cannot obtain acks for a second digest and abstains; three such nodes cannot form a second lock; clone admission fences the original; five-operator collusion breaks without the flag and holds with it; total restart recovers with seven nodes; epoch change destroys old keys.
- Quint model of admission and witnessed commitment with the invariants "at most one PREVOTE digest per `(node, rid, g)` leaves any instance" and "at most one lock per `(rid, g)`" for c ≤ 4, run by the lead.

### 9.3 Checks on a real Azure CVM before the build is trusted

1. `/dev/sev-guest` is absent in the guest.
2. A vTPM-sealed object survives stop, deallocate, start and a host move.
3. A disk snapshot restored to a new VM brings the vTPM state with it, or does not. The design is safe either way; the result decides only how tier 0 behaves after a restore.
4. PCR 14 is zero after boot on the Veritee UKI.
5. `tpm2_quote` under AK `0x81000003` accepts qualifying data, and the AK certificate at `0x01C101D0` chains to the pinned root.
6. Writing 64 bytes to NV `0x01400002` changes `user-data` in a fresh report.
7. `HCLAkPub`, and so `vm_id`, is the same after reboot, after deallocate and start, and after a restore from snapshot.

### 9.4 Warden and Midnight additions [assumption throughout]

- **Image Registry.** `image_id → {PCR 4, PCR 15 setup value, allowed launch measurements, TCB floors, status, valid_from, revoked_at}`. Approval through the existing OS release flow with reproduction required (`require_reproduced_os` true for committee images) and a timelock. Releases can be revoked; today they cannot (`docs/os-release-approval.md:185-186`).
- **Node Registry.** Per committee and slot: operator key, `vm_id`, `image_id`, `boot_ctr`, boot key hash, status. Entry points `admitBoot` (operator and Warden signatures, counter + 1), `replaceSlot` (operator signature, effective at the next epoch, one per slot per epoch), `removeSlot`.
- **Key Registry.** `epoch → EKS_e`, evidence hashes, validity window; accepts an entry with w peer acks per node and the Warden signature.
- **Checkpoints and locks.** `checkpoint(epoch, board_height, board_root, witness_root)` with q signatures under registered post keys; heights strictly increase. `anchorLock(rid, g, digest)` with q PREVOTE signatures; one entry per `(rid, g)`.
- **Warden.** Verifies class-tagged evidence with `veritee-verify`; serves evidence bundles by hash; stops being the only verifier for committee traffic. At least two independent Wardens sign registry writes; one compromised Warden can then neither admit a fake node nor block one.
- **Signature schemes.** Boot and post keys are Ed25519 here. If Compact verifies another scheme more cheaply, the contract-facing signatures change scheme and nothing else does.

---

## 10. Residual risks

**Azure host operator (the node operator, a subscription admin).** Can stop, restart, roll back, clone and starve its node, drop or delay its traffic, and feed it stale but valid chain data until admission. The result is an abstaining or absent node, which the committee tolerates up to f. Can deploy any image, which the registry rejects. Can run the debug image, which fails check 6. Sees ciphertext sizes and timing; no padding is specified here. Five or more colluding operators can force a second digest for requests without `anchor_before_release`. Seven colluding operators with seven `K_tpm` values of one epoch open that epoch's keyrings (section 3.4).

**Malicious image builder.** An approved image is the whole TCB: kernel, `seald`, the app, and the root hooks (`docs/operator-guide.md:158-168`). A backdoored image that passes approval reads everything its node holds, and on t nodes it holds the committee key shares. Defences are outside the guest: reproduction by more than one Warden, the timelock, one-slot-per-epoch rollout so a bad image holds at most one share when it is found, and revocation. An image signer has no power by signature alone, because no signed PCR policy exists.

**Microsoft.** Operates the hypervisor, the paravisor that implements the vTPM, the VMGS key (platform-managed in this configuration) and the datacenters. A malicious or compelled Microsoft reads `K_tpm`, forges vTPM quotes and AK certificates, and can apply every attack below to all nine nodes at once. Spreading nodes over operators does not spread them over hardware owners. Blindness and the raised collusion bound are void against Microsoft; R1 is not.

**AMD.** Signs VCEKs and firmware. A forged VCEK chain or a firmware backdoor defeats check 1 for every node.

**Known attacks and what they mean here.**

| Attack | Attacker and effect, per the source opened | Meaning for this design |
|---|---|---|
| CacheWarp, CVE-2023-20592 (S22) | Malicious hypervisor reverts guest memory writes at single-store granularity; demonstrated old-session revival and code execution; fixed by microcode | A software route to in-RAM rollback and takeover, by the host owner. Check 2 enforces the microcode floor from the registry; today floors are taken on first use. |
| Ahoi family: Heckler, WeSee (S23) | Malicious interrupts and #VC injections from the hypervisor break confidential VMs | Host-owner attack. The page read lists no mitigation. The guest kernel in the image is pinned at 6.2.0-1018 (`mkosi.conf.j2:47`); before production the committee reviews that kernel and the Azure paravisor version against both papers, and the registry names the versions it accepts. |
| BadRAM, CVE-2024-21944 (S21) | A modified DIMM SPD chip (about $10) aliases memory; on SEV-SNP it allows ciphertext replay and replay of attestation measurements, "breaks all trust in the SEV-SNP ecosystem"; fixed by AMD firmware that validates memory configuration | Forged evidence on attacker-owned hardware. Checks 2 and 4 answer it: the firmware floor, and the Azure AK certificate, which limits the hardware to Microsoft's. |
| Heracles, CCS 2025 (S20) | The hypervisor moves guest pages; re-encryption is deterministic; a chosen-plaintext oracle leaks guest memory, including keys | Host-owner read of node RAM, where `K_seal`, shares and plaintext requests live. No guest-side defence is claimed. |
| TEE.fail, Oct 2025 (S24) | A DDR5 bus interposer (under $1,000, physical access) extracts keys from SEV-SNP guests even with Ciphertext Hiding, and attestation keys on Intel; AMD states physical attacks are out of scope and plans no mitigation | Deterministic memory encryption gives no defence against a party with hands on the server. For Azure nodes that party is Microsoft or its staff. A committee that adds nodes on other hardware owners turns one such party into several. |

The common reading: every published break needs the hypervisor or the hardware. The node operator has neither on Azure. The design therefore states its TEE-mode claims against operators, pins evidence to Azure custody so an operator cannot substitute hardware it controls, enforces TCB floors from the chain, and leaves every guarantee that must survive a platform break to the threshold cryptography of section 8.

---

## 11. Sources

Each entry was opened and read for this document; the note says what it contributed.

- **S1** Veritee code, `~/Projects/veritee/veritee-vm`: `measured_setup/main.py`, `azure_attestation_server/src/{main,enclave_key}.rs`, `akx/src/{epoch,attest}.rs`, both `Cargo.toml`, `attestation_server.service`, `measured-setup.service`, `mount-persist`, `combined.repart/*`, `fstab`, `projects/mpc-node/*`, `projects/templates/run.d/main`, `AGENTS.md`, `docs/tls-channel-binding.md` section 7; and the digest `VERITEE-MODEL.md`. Present behaviour and file names. `path:line` citations to files not in this list (`cli/veritee/cli.py`, `session_store.rs`, `docs/operator-guide.md`, `docs/os-release-approval.md`, `docs/vm-inventory.md`, `projects/warden/README.md`, `cli/deploy-azure-snp/main.tf` beyond a grep) are taken from the digest.
- **S2** Microsoft Learn, Secure Key Release with AKV and Azure Confidential Computing, https://learn.microsoft.com/en-us/azure/confidential-computing/concept-skr-attestation (dated 2026-09-09). SKR releases exportable HSM keys on MAA claims; policies do not attach to secrets or certificates; vTPM tokens can carry `x-ms-azurevm-attested-pcr-values`; other attestation authorities need a DigiCert-rooted OpenID Connect issuer.
- **S26** Microsoft Learn, Azure Key Vault secure key release policy grammar, https://learn.microsoft.com/en-us/azure/key-vault/keys/policy-grammar. "The only allowed condition is equals", no array matching, the required `x-ms-runtime.keys` RSA key.
- **S3** Microsoft Learn, Secure Key Release with Azure Key Vault and application on Confidential VMs with AMD SEV-SNP, https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp. The full SKR flow, the `equals`-only policy, the managed-identity requirement, the complete example token (no PCR values, `migration-allowed: false`), the 8-hour token lifetime, the mutable policy.
- **S4** Microsoft Learn, Azure confidential VMs FAQ, https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-faq. vTPM sealing is supported; the VMGS disk holds vTPM state, is always encrypted, and uses a platform-managed key without full-disk encryption.
- **S5** Microsoft Learn, Azure Confidential VM guest attestation design detail, https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design. What the hardware report and the quote each cover; NV indexes `0x01400001`, `0x01400002`, `0x01C101D0`, AK handle `0x81000003`; runtime claims `HCLAkPub`, `user-data`.
- **S6** Microsoft Q&A, Why does the tool sevctl work incorrectly with a CVM-SNP VM, https://learn.microsoft.com/en-us/answers/a/1844982. The paravisor design is why AMD guest tooling does not work on Azure CVMs.
- **S7** Linux kernel documentation, The Definitive SEV Guest API Documentation, https://docs.kernel.org/virt/coco/sev-guest.html. `SNP_GET_DERIVED_KEY` uses `MSG_KEY_REQ` through `/dev/sev-guest`; the VMPCK and its message counter.
- **S8** Microsoft Learn, Trusted Launch FAQ, https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq. The VMGS lifecycle follows the OS disk; VMs are created from snapshots that carry vTPM state; vTPM-sealed keys on ephemeral disks may not persist.
- **S9** Matetic et al., ROTE: Rollback Protection for Trusted Execution, USENIX Security 2017, https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-matetic.pdf. Read: sections 1, 4 (architecture, initialization, state update, restart) and 5 (security analysis); the evaluation and related work were not read. Counters in peer enclaves' volatile memory, two-round write and the attack on one round, session-key refresh against second instances, the non-zero-counter check against a parallel group, n = f + 2u + 1, halt on total restart.
- **S10** Angel et al., Nimble: Rollback Protection for Confidential Cloud Services, OSDI 2023, https://www.usenix.org/system/files/osdi23-angel.pdf (abstract also at https://eprint.iacr.org/2023/761). Read: the introduction, the endorser overview and the reconfiguration overview; the detailed protocol, proofs and evaluation were not read. Endorsers hold the ledger tail in volatile memory, quorum signatures over a client nonce, safety in the TEE and liveness outside, reconfiguration by renouncing, loss of a majority is permanent.
- **S11** Niu et al., Narrator: Secure and Practical State Continuity for Trusted Execution in the Cloud, CCS 2022, https://pw0rld.github.io/files/Narrator_ccs_22.pdf. Read: abstract, introduction, threat model and the restart protocol (section 4.7); Appendix A is not in this file. Blockchain for initialization only, the cost of a chain write per update, TPM counter cost, the reported flaw in ROTE's restart and its repair.
- **S12** RFC 9180, Hybrid Public Key Encryption, https://www.rfc-editor.org/rfc/rfc9180.html (sections 5 to 9.1 read). Single-shot use, no forward secrecy toward the recipient, no replay protection, `info` and `aad`, suite identifiers.
- **S13** Phala, dstack KMS and key delivery, https://docs.phala.com/dstack-cloud/kms-and-key-delivery.md. Quote check, on-chain allowlist, multisig and timelock, revocation by removing a measurement.
- **S14** Phala, dstack key management protocol, https://docs.phala.com/dstack/design-documents/key-management-protocol.md. The sealing-key derivation formula, app update as rotation, the KMS as single point of failure, threshold root key as an option.
- **S15** Confidential Containers, Attestation, https://confidentialcontainers.org/docs/attestation/. Trustee's parts: key broker, attestation service, reference-value provider.
- **S16** Oasis, Key Manager consensus service, https://docs.oasis.io/core/consensus/services/keymanager/. The signed policy that names which enclave identities may query keys and which may replicate the master secret.
- **S17** BuilderNet v1.2 release notes, https://buildernet.org/blog/2025/02/19/buildernet-v1.2. The image bootstraps from BuilderHub and pulls its disk encryption key from it as a stopgap; reproducible measurements.
- **S18** Microsoft Learn, Attest a Linux workload with dm-verity and IMA, https://learn.microsoft.com/en-us/azure/confidential-computing/how-to-attest-linux-workload (dated 2026-09-14). Guest attestation alone does not approve a workload; a release broker decides; bind the exchange to the recipient key; quotes carry a challenge.
- **S19** Google Cloud, Confidential Space overview, https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview. Workload identity granted on attestation attribute conditions; operator exclusion.
- **S20** Heracles project page, https://heracles-attack.github.io. Hypervisor page moves, deterministic re-encryption, memory leak; CCS 2025.
- **S21** BadRAM project page, https://badram.eu. SPD aliasing, replay of ciphertext and attestation measurements, AMD firmware fix, CVE-2024-21944; IEEE S&P 2025.
- **S22** CacheWarp project page, https://cachewarpattack.com. Hypervisor reverts guest memory writes; microcode fix; CVE-2023-20592.
- **S23** Ahoi attacks page, https://ahoi-attacks.github.io. The family of malicious-notification attacks: Heckler (USENIX Security 2024), WeSee (IEEE S&P 2024).
- **S24** BleepingComputer, TEE.Fail attack breaks confidential computing on Intel, AMD, NVIDIA CPUs, 2025-10-28, https://www.bleepingcomputer.com/news/security/teefail-attack-breaks-confidential-computing-on-intel-amd-nvidia-cpus/. DDR5 interposer, keys from SEV-SNP guests with Ciphertext Hiding on, AMD's out-of-scope position. The project site https://tee.fail returned an error and was not read.
- **S25** `design/SCHEME.md` sections 1, 2, 3.7 to 3.10 and 5, and `design/enhancement/BRIEF.md`. The slot ledger, rule 4, profiles T1 and T2, the freeze and transfer rules, requirements R1 to R5 and B1 to B6.

Not opened, and therefore not used: the AWS KMS Nitro attestation page (the fetch returned no content), the SEV-SNP ABI specification, the Flashbots forum posts, AMD security bulletins.
