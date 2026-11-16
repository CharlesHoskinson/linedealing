# Veritee as a TEE for a threshold-signing committee: what the code provides

Source: local checkout `~/Projects/veritee/veritee-vm` (branch `main`, read 2026-11-14).
All citations are `path:line` relative to that checkout. The related repositories (veritee-warden,
veritee-spec, veritee-smart-contracts, veritee-attestation-verifier-ts) were not available. Where a
property depends on them, the text says **[spec needed]**. Statements marked **[inference]** follow
from the code or configuration but no code or document states them directly.

Status: "experimental and has not been audited ... not intended for production use"
(`README.md:12-15`). The attested channel is "Phases 0–6 implemented ... (on-CVM e2e pending)"
(`docs/attested-channel-implementation-plan.md:3`, `:291`).

---

## 1. Platform and boot chain

- **Hardware/host:** an Azure Confidential VM on AMD SEV-SNP with a vTPM. Terraform sets
  `vtpm_enabled = true` and `secure_boot_enabled = false` (`cli/deploy-azure-snp/main.tf:246-247`).
  The OS disk uses `security_encryption_type = "VMGuestStateOnly"` (`main.tf:257`). Only the VM guest
  state blob is confidential. The OS disk is not confidential-disk-encrypted.
- **Image:** mkosi Ubuntu 22.04 with a pinned Azure kernel `6.2.0-1018`
  (`veritee-os/mkosi/rootfs/mkosi.conf.j2:47`). It boots a UKI (`mkosi.conf.j2:18`). The root
  partition is squashfs plus dm-verity (`veritee-os/mkosi/rootfs/mkosi.repart/10-root.conf`,
  `11-root-verity.conf`). The kernel command line has `systemd.volatile=overlay`
  (`mkosi.conf.j2:84`), so the root is read-only with a tmpfs upper layer. The initrd copies the
  whole verified root device into a RAM tmpfs and mounts it read-only
  (`veritee-os/mkosi/initrd/mkosi.postinst:22-31`).
  **[inference]** After boot, root-filesystem reads do not go back to the host-visible disk.
- **Root verity hash to PCR4:** PCR4 for the Azure CVM profile is
  `extend(EV_EFI_ACTION "Calling EFI Application from Boot Option", separator, Authenticode(UKI))`
  (`scripts/compute_expected_pcr4.py:193-199`). **[inference]** mkosi puts the root `roothash=` on
  the UKI command line, so PCR4 covers kernel, initrd, command line and root filesystem. The repo
  does not show this explicitly.
- **Fixed PCRs:** PCR12 and PCR13 are expected to be all zeros (`compute_expected_pcr4.py:155-164`).
  PCR0-3 are "not treated as local golden measurements; they are filled from the deployed VM's TPM
  quote during hydration" (`docs/operator-guide.md:205-208`). That hydration is TOFU: "Baseline
  capture only ... trust model is TOFU over a deployment the operator already controls"
  (`cli/veritee/cli.py:1131-1136`, `:1431-1434`).
- **Debug vs release:** these are build profiles. Debug adds `RootPassword=root`
  (`mkosi.conf.j2:20-22`), SSH with a baked-in authorized key
  (`veritee-os/mkosi/rootfs/mkosi.postinst.j2:9-13`), the serial console, and the
  `TEMENOS_ALLOW_PCR15_FAILURE=1` drop-in (`veritee-os/mkosi/rootfs/copy_services.sh.j2:14-25`).
  A verifier distinguishes debug from release only by measurement (PCR4, image).

## 2. What is measured

| Register / value | Content | Where |
|---|---|---|
| SNP launch measurement, TCB, policy bits | Measures the Azure HCL/paravisor launch image. The guest OS is not in it. Hydrated from the first deployment. | `cli/veritee/cli.py:1131-1166`, `:1471-1514` |
| vTPM PCR0-3 | Firmware/platform. Taken from the deployed VM's quote (TOFU). | `docs/operator-guide.md:205-208`, `cli/veritee/cli.py:1001`, `:1442-1468` |
| vTPM PCR4 | Authenticode hash of the UKI (see §1). Computed offline from `disk.raw`. | `scripts/compute_expected_pcr4.py:167-200` |
| vTPM PCR12, PCR13 | Expected zero | `scripts/compute_expected_pcr4.py:155-164` |
| vTPM PCR15 | `E(E(E(0, app_root_hash), 0^32), tls_evidence_hash)` with `E(p,d)=SHA256(p‖d)` | see below |
| App dm-verity root hash | 32 bytes = PARTUUID(app) ‖ PARTUUID(app-verity) | `veritee-os/measured_setup/main.py:268-270` |

**PCR15 construction.**
1. `measured_setup/main.py` reads the app root hash from the two partition UUIDs
   (`main.py:268-270`). systemd-repart derives those UUIDs from the verity root hash. The script
   writes the hash to `/root/application_disk_root_hash` (`main.py:272-274`).
2. It extends PCR15 with `root_hash`, then with 32 zero bytes, but only if PCR15 was zero
   (`main.py:91-133`). It then opens dm-verity with that same hash (`main.py:281`).
   **[inference]** The partition table is untrusted input. Swapping the app disk changes PCR15
   because the hash is extended before verity opens.
3. A release image refuses to start the DApp if this fails (`main.py:136-150`). The debug drop-in
   allows continuing.
4. The `guest-attestation` container extends PCR15 a third time with a domain-separated hash of the
   TLS evidence (`server/guest_attestation/veritee_attestation/document.py:112-127`, `:181-207`).
   - `internal` mode hashes `"temenos-tls-internal-v1\0" ‖ Caddy root CA PEM`.
   - `azure_vault` mode hashes `"temenos-tls-spki-v1\0" ‖ canonical JSON of {host, spki_sha256}`.
   - **[inference]** In `internal` mode the Caddy CA lives in the `caddy_data` Docker volume, and
     `/var/lib/docker` is tmpfs (`veritee-os/mkosi/rootfs/mkosi.extra/etc/fstab:4`). A new CA and a
     new PCR15 therefore appear on every boot.
5. `compute-pcr15.py:24-32` is stale. It models only the CA extension, not the root-hash extensions.

**Who can extend PCR15.** The `guest-attestation` container is given `/dev/tpmrm0`
(`projects/mpc-node/run.d/docker-compose.yml:11`). The DApp lifecycle hooks `setup.d/main` and
`run.d/main` run as host root (`docs/operator-guide.md:158-168`). **[inference]** These components
can extend PCR15 further. A further extension changes PCR15, so it breaks verification but cannot
forge a value.

**Not measured:**
- the `persist` partition (§5);
- Azure IMDS tags, for example `temenos_tls_keyvault_name`, read at boot (`projects/templates/run.d/main:62-65`);
- Key Vault secret contents (TLS key, Warden wallet seed);
- the TLS private key in `azure_vault` mode (only its SPKI is measured).

## 3. How a remote party verifies a VM

### 3.1 Evidence endpoint `GET /` (public as `https://<attestation-host>/tee_attestation`)

- **Routing:** Caddy `handle_path /tee_attestation* { reverse_proxy attestation:8000 }`
  (`projects/mpc-node/run.d/Caddyfile.template:12-14`).
- **Nonce handling:**
  - Requests without `nonce` are rejected unless the binary has the `dev-unbound-attestation` feature
    and the env flag is set (`server/azure_attestation_server/src/main.rs:505-548`).
  - `payload` requires `nonce` (`main.rs:542`).
  - Release builds do not compile the feature (`main.rs:517-520`, `Earthfile:140-148`).
- **Build mode `maa`** (default) (`main.rs:769-835`):
  1. The server builds an Azure "AzureGuest" request containing the HCL report from NV index
     `0x01400001` (`vtpm.rs:22`, `:166-177`), the VCEK chain from IMDS `/THIM/amd/certification`
     (`imds_operations.rs:3-4`), the TCG log, and a vTPM quote with **empty qualifying data**
     (`main.rs:302`). The client nonce/payload go into `client_payload` (`main.rs:780-783`).
  2. It posts the request to a hardcoded MAA instance
     `https://midnightl2.eus.attest.azure.net/attest/AzureGuest` (`main.rs:801`).
  3. MAA returns a JWT encrypted to an RSA-2048 key. The vTPM creates that key in the Null hierarchy
     under a PCR policy and certifies it with the AK (`eph_key_tpm.rs:45-114`). The server decrypts
     the inner key (`eph_key_tpm.rs:148-180`) and returns the token plus the key to the caller
     (`main.rs:825-834`).
  4. In this mode the SNP report is the boot-time HCL report, read unchanged. The nonce and payload
     binding exists only inside the Microsoft-signed token.
- **Build mode `raw-report`** (`main.rs:837-873`): `report_data = SHA256(JSON{nonce,payload})`
  (`main.rs:650-659`) is passed to `az_snp_vtpm::vtpm::get_report_with_report_data`. The response
  carries the SNP report, VCEK chain, HCL runtime data and a separate `tpm2_quote` over PCR0-15
  (`main.rs:439-495`).
  - **[inference / Azure behaviour]** The HCL puts that value in its runtime-data JSON, and SNP
    `REPORT_DATA` commits to a hash of the runtime data. The repo does not show this hop.
  - The runtime data carries `HCLAkPub`, which binds the vTPM AK to the SNP report
    (`cli/veritee/cli.py:1201-1234`).
- **TPM quote freshness:** no TPM quote carries a nonce. Both `tpm2_quote` invocations omit
  qualifying data (`main.rs:447-460`, `server/guest_attestation/veritee_attestation/tpm_quote.py:23-26`),
  and the CLI checks quotes without `-q` (`cli/veritee/cli.py:1402-1412`). Freshness comes only from
  the MAA token or the SNP `report_data`. Whether Warden checks quote clock/reset counters is
  **[spec needed]**.

### 3.2 Static document `https://<attestation-host>/attestation.json`

Written once per boot by `guest-attestation` (`document.py:258-301`). It contains:
- the AK certificate chain from NV `0x01C101D0` (`document.py:242-255`);
- the TLS evidence;
- an unbound vTPM quote;
- the app root hash.

It is not nonce-bound. Its role is to carry the TLS root CA or SPKI that PCR15 commits to.

### 3.3 Warden and Midnight

- **CLI side:** `register-app` sends Warden the packaged `metadata.json`, the Caddyfile and compose
  file, `tls_mode`, the address, `pcrs.json` + `policy.json` and a random `temenos_app_key`
  (`cli/veritee/cli.py:4984-5062`, `:2631-2648`). Per the README, Warden "reproduces the application
  disk, verifies live attestation from the VM, and records the registration on the Midnight ledger"
  (`README.md:45-50`). The OS release must be a confirmed on-chain entry, resolved by Warden from the
  digest-pinned `base_os_image` (`docs/os-release-approval.md:130-152`).
- **Verification:** `verify-attestation` forwards `{dapp_id, tee_attestation, payload, nonce}` to
  Warden `/dapps/verify_attestation` (`cli/veritee/cli.py:4831-4914`). The CLI does no cryptographic
  verification of its own. Raw-mode parsing "intentionally does not verify the AMD signature, VCEK
  chain, or runtime_data/report_data binding" (`cli.py:1131-1136`).
- **[spec needed]:**
  - which PCRs and TCB floors Warden enforces;
  - whether it checks quote freshness or MAA token `exp`;
  - the on-chain record schema (the repo states only `base_os_version` and
    `base_os_release_manifest_digest` in "the bounded on-chain metadata projection",
    `docs/os-release-approval.md:150-152`);
  - what `temenos_app_key` authorizes (it never enters the guest);
  - how a third party reads the Midnight record without Warden.

## 4. Attested key exchange (akx)

### 4.1 Construction

The construction is in `server/akx`, which has no TPM or HTTP dependencies (`server/akx/Cargo.toml:8-9`).

- **Label:** `"temenos-akx-v1"` (`server/akx/src/transcript.rs:8`).
- **Epoch key:**
  - Ed25519 `sk_e` from the OS CSPRNG (`epoch.rs:21-26`).
  - `report_data = SHA256(LABEL ‖ "epoch" ‖ epoch_u64_be ‖ pk_e) ‖ 0^32` (`epoch.rs:48-58`). The
    fields are not length-prefixed; all are fixed-length except LABEL.
  - Attested once by `EpochManager::new` (`epoch_manager.rs:40-49`) and refreshed every
    `AKX_ATTEST_REFRESH_SECS=300` with the same key (`epoch_manager.rs:78-86`,
    `azure_attestation_server/src/main.rs:945-976`).
  - Timed rotation is off (`AKX_EPOCH_ROTATE_SECS=0`, `services/attestation_server.service:41`).
- **Platform binding:** `PlatformAttester` passes `base64(report_data)` as the attestation
  `payload` with the **constant nonce** `"temenos-akx-v1-epoch"`
  (`azure_attestation_server/src/enclave_key.rs:40-55`).
  - Maa mode: the binding is the MAA token's `client_payload`.
  - Raw mode: the binding is `SHA256(JSON{nonce,payload})` in the HCL report data.
  - The client verifier sends the same constant nonce and the recomputed payload to Warden
    (`cli/veritee/attested_channel.py:342-360`).
- **`GET /enclave-key`** returns `{epoch, epochPublic, attestation}` (`enclave_key.rs:58-82`).
- **Session handshake** (`server/akx/src/session.rs`):
  1. `POST /session {sid ≤32B, nonce_c 1..64B}` (`azure_attestation_server/src/session_routes.rs:26-30`, `:61-79`).
  2. The enclave generates an X25519 keypair `S`.
  3. It computes `T = SHA256(len‖LABEL ‖ len‖sid ‖ len‖nonce_c ‖ len‖S)` with 8-byte length prefixes
     (`transcript.rs:25-32`).
  4. It returns `{S, Ed25519(sk_e, T)}` (`session.rs:60-76`).
  5. The client verifies the signature with `verify_strict` (`epoch.rs:63-68`).
  6. The client runs HPKE Base mode `DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM` to `S` with
     `info = T` (`session.rs:103-121`).
  7. The client sends `enc` with `POST /session/complete`, and the enclave runs `setup_receiver`
     (`session.rs:80-92`).
  8. Both sides export `k_c2s` and `k_s2c` with contexts `"temenos-akx-v1 c2s"/"s2c"` (`session.rs:20-21`).
- **Record layer:**
  - AES-256-GCM, nonce `dir ‖ 0^3 ‖ seq_be64`, AAD = `sid` (`record.rs:38-46`).
  - `open` advances `seq` even on failure (`record.rs:62-77`).
  - Any failure drops the session (`azure_attestation_server/src/proxy_routes.rs:265-343`).
  - There is no authenticated close.
- **Session store:** in memory, TTL 300 s, at most 10,000 sessions
  (`server/akx/src/session_store.rs:51-52`). Nothing survives a restart.
- **`POST /proxy`:**
  1. Decrypts the record in the host `attestation_server`.
  2. Forwards it as plaintext HTTP to `DAPP_UPSTREAM_URL=http://127.0.0.1:8080`
     (`services/attestation_server.service:23`).
  3. Allows only paths in the measured `proxy_allowed_paths` (`proxy_routes.rs:192-210`, `:438-456`).
     A missing policy file means an empty allowlist (`proxy_routes.rs:441`).
  4. Forwards only the `content-type` header (`proxy_routes.rs:486-498`).
  5. Re-encrypts the response.

### 4.2 Key material in the guest

| Key | Where | Lifetime |
|---|---|---|
| `sk_e` (Ed25519) | `attestation_server` process memory (`EpochManager`) | Process lifetime. A new key on every start (`main.rs:884-892`). |
| Session X25519 `s`, `k_c2s/k_s2c` | `SessionStore` memory | ≤300 s |
| TPM ephemeral RSA (MAA unwrap) | vTPM Null hierarchy | Per request |
| Caddy internal CA key (`internal` TLS) | `caddy_data` Docker volume on tmpfs | Per boot **[inference]** |
| TLS private key (`azure_vault`) | Key Vault → `/run/temenos/tls` (`projects/templates/run.d/main:115-117`) | Uploaded by the operator; exists outside the TEE (`docs/operator-guide.md:414-427`) |
| App secrets | Whatever the app writes, e.g. `/mnt/persist/mpc-node` (§5) | Unencrypted by the platform |

- The `epoch` counter is described as persisted and incremented per boot (`main.rs:921-939`), stored
  at `/var/lib/attestation_server/epoch` (`attestation_server.service:18-19`).
- **[inference]** No mount puts `/var/lib/attestation_server` on the persist partition, and the root
  is `systemd.volatile=overlay`. The counter therefore probably restarts at 1 on every boot. It still
  increments if the service restarts within a boot. Uniqueness of `report_data` rests on the fresh
  `pk_e`, not on `epoch`.

### 4.3 Channel binding for a client

A client binds a channel to an attestation by these steps:
1. Fetch `/enclave-key`.
2. Have Warden verify that the attestation commits to `report_data_for(epoch, pk_e)` and to the
   registered measurements.
3. Verify the epoch signature over its own `(sid, nonce_c, S)`.
4. Run HPKE (`cli/veritee/attested_channel.py:432-455`).

Notes:
- The client's freshness lives in the signed transcript, not in the attestation. The epoch
  attestation is fresh only as far as Warden enforces token or report age **[spec needed]**.
- A second binding exists for capable clients: PCR15 commits to the TLS CA or SPKI, and the client
  pins it (`docs/tls-channel-binding.md:43-73`, `:489-531`).
- **Gap — public attestation oracle [inference]:** nothing reserves the nonce
  `"temenos-akx-v1-epoch"` or restricts `payload` on `GET /`.
  - `get_attestation` takes both from the query string (`main.rs:736-748`), and Caddy forwards all
    of `/tee_attestation*`.
  - Anyone can therefore obtain genuine evidence whose payload is
    `report_data_for(e, pk_attacker)` for a key the enclave never held.
  - A verifier that checks only "evidence binds `report_data_for(epoch, pk)`" would accept an
    attacker-held `pk`. The client would then complete a session with the attacker.
  - Payload-bound evidence proves only that someone asked the VM to attest those bytes.
  - Whether Warden or the client separates this path (for example by a distinct endpoint marker) is
    **[spec needed]**. No such marker is in this repo.

### 4.4 Can a client encrypt TO an attested enclave key?

**Only interactively, and only to the host attestation server.**
- The only long-lived attested key is the Ed25519 signing key `pk_e`. It cannot receive encryption.
- The recipient keys are per-session X25519 keys. They are minted on demand and deleted after 300 s
  or on error.
- There is no static, attested KEM public key. A party cannot seal a message offline to a node and
  have it opened later or after a restart.
- The plaintext terminates in the host `attestation_server` process, not in the application. The
  app receives plaintext over loopback and holds no attested key of its own.
- `projects/mpc-node/metadata.json` declares no `proxy_allowed_paths`, so `/proxy` forwards nothing
  for the MPC node as packaged (`proxy_routes.rs:441`, `:194-196`).
- The TLS key (internal CA, or SPKI) is a second attested endpoint for standard TLS clients. Its
  termination point is Caddy in a container.

## 5. Secret handling and the operator

- **Sealed storage:** none. The code makes no use of TPM sealing (`tpm2_create`/`unseal`, NV policy),
  has no LUKS on the data disk, and has no SNP derived keys (`MSG_KEY_REQ`). A search for
  seal/unseal/luks/zeroize found only GCM `seal` and lockfile `zeroize` entries.
- **Persist partition:** a plain ext4 partition with a fixed PARTUUID in every image
  (`veritee-os/mkosi/combined.repart/30-persist.conf:3-7`). It is mounted at `/mnt/persist`
  (`veritee-os/mkosi/rootfs/mkosi.extra/etc/fstab:6`,
  `veritee-os/mkosi/rootfs/mkosi.extra/usr/lib/temenos/mount-persist`). It is neither measured nor
  encrypted. The repo says: "Guest lockdown does not establish confidentiality of persisted data ... A
  running-disk snapshot may intersect a checkpoint write" (`AGENTS.md:69-72`). The MPC-node compose
  mounts `/mnt/persist/mpc-node` into the app (`projects/mpc-node/run.d/docker-compose.yml:28`,
  `:64`). Any confidentiality of committee key shares at rest depends on the app image, which is
  not in this repo.
- **Persistence across reboot:** the persist partition survives a reboot of the same VM. All other
  writable state is tmpfs: `/var/lib/docker` and `/var/lib/containerd`
  (`veritee-os/mkosi/rootfs/mkosi.extra/etc/fstab:4-5`) and the root overlay. `sk_e` is regenerated.
- **Across redeploy:** each deploy is immutable, with a new resource group and a new disk created
  from the image (`docs/vm-inventory.md:1-4`, `docs/operator-guide.md:237-241`). The persist
  partition starts empty. The repo has no mechanism to migrate keys between deployments.
- **Key provisioning:** the only mechanism in the repo is Azure Key Vault plus the VM's
  system-assigned managed identity (`cli/deploy-azure-snp/main.tf:249-251`, `:278-291`;
  `projects/templates/run.d/main:57-123`). Key Vault releases secrets to the managed identity, not
  against attestation (no Secure Key Release policy). The Warden uses this to get its wallet seed
  (`projects/warden/README.md:51-56`). **[inference]** Anyone with sufficient rights in the Azure
  subscription can read those secrets directly.
- **Secure erasure:** none explicit. Ephemeral secrets drop with Rust values; there is no
  `zeroize`. The threat model lists this as a defence still to do
  (`docs/tls-channel-binding.md:482-485`).
- **Operator (VM deployer / Azure subscription admin) capabilities:**
  - *Can* choose and replace the image, which changes the measurements.
  - *Can* restart, stop or delete the VM, read the OS disk (including persist) through
    export/snapshot (`AGENTS.md:69-72`), and restore an older disk snapshot. **[inference]** Nothing
    in the guest detects rollback of persist.
  - *Can* set IMDS tags that the boot scripts read (Key Vault name), and control network
    reachability and DNS outside the guest.
  - *Can* read and replace Key Vault secrets, including the `azure_vault` TLS key.
  - *Can* call `GET /tee_attestation` with chosen inputs (§4.3).
  - *Can* run the debug image, which a verifier rejects only by measurement.
  - *Cannot* (per SEV-SNP, **[inference]** from platform guarantees) read guest memory, including
    `sk_e`, session keys and the RAM copy of root.
  - *Cannot* log in to a release image. It has no SSH, no serial console and no Azure VM agent
    (`veritee-os/mkosi/rootfs/copy_services.sh.j2:14-25`; `README.md:166-169`). Terraform still sets
    an `admin_ssh_key` (`main.tf:263-268`). Provisioning is a custom wireserver "Ready" report
    (`veritee-os/mkosi/rootfs/mkosi.extra/var/azure-provisioning.py`).

## 6. Egress policy

- **Kernel firewall (iptables):**
  - Default DROP on INPUT and OUTPUT (`veritee-os/mkosi/rootfs/mkosi.extra/etc/iptables/rules.v4.j2:45-46`).
  - Container FORWARD is DROP until measured setup installs grants (`rules.v4.j2:6-10`).
  - The host may reach DHCP, IMDS `169.254.169.254:80` and the wireserver
    `168.63.129.16:80,32526` (`rules.v4.j2:18-25`).
  - Inbound is limited to 80/443, plus 8000 and 18080 from `br+` bridges (`rules.v4.j2:31-43`).
- **Egress proxy:** HTTP CONNECT only, run as two unprivileged users (`app` on 18080, `platform` on
  loopback 18081) (`veritee-os/mkosi/rootfs/mkosi.extra/etc/systemd/system/temenos-egress-proxy@.service`).
  - Hostname targets require an exact TLS SNI match and are resolved by the proxy through Azure DNS.
  - Non-public results are rejected (`server/egress_proxy/src/main.rs:191-207`, `:388-470`).
  - Literal IPs get a raw tunnel to the exact IP:port.
  - No plain HTTP. At most 256 tunnels; idle timeout 5 min (`server/egress_proxy/README.md:47-50`).
- **Profiles:**
  - Default: a measured allowlist in `metadata.json.outbound`.
  - `unrestricted`: any public TCP destination through the proxy (`main.rs:200-202`;
    `veritee-os/measured_setup/egress.py:766-767`).
  - `warden`: direct DNS, 443 and IMDS for one container, plus the Docker socket
    (`projects/warden/README.md:7-12`).
  - **The packaged MPC node uses `unrestricted`** (`projects/mpc-node/metadata.json:8`).
- **Compose validation:** blocks `privileged`, host namespaces, `network_mode` other than none,
  `cap_add` of ALL/BPF/NET_ADMIN/SYS_ADMIN/SYS_MODULE, runtime-socket mounts and `/dev/net/tun`
  (`egress.py:30-41`, `:240-292`). Host bind mounts and other devices (for example `/dev/tpmrm0`)
  are not blocked.
- **Limits stated by the repo:**
  - The proxy does not validate upstream certificates.
  - An approved endpoint is an approved exfiltration channel, and domain fronting remains possible
    (`server/egress_proxy/README.md:70-86`, `SECURITY.md:17-21`).
  - Root lifecycle hooks are outside the sandbox (`server/egress_proxy/README.md:62-68`;
    issue #42).

## 7. Determinism, updates and OS release approval

- **Build determinism:**
  - `SOURCE_DATE_EPOCH=946684800`, a fixed systemd-repart seed, and a fixed machine-id
    (`Earthfile:92-93`, `:574`, `:669`; `veritee-os/mkosi/rootfs/mkosi.postinst.j2:29-31`).
  - Pinned package versions (`mkosi.conf.j2:24-80`).
  - The README claims a third party "can rebuild the image and derive the same PCR4"
    (`README.md:32-36`).
  - The guest-attestation helper produced byte-identical OCI output on two builds with the same
    builder, "not independent-builder certification" (`server/guest_attestation/README.md:88-94`).
- **Updates:** no in-place update. A new image means a new deployment, a new measurement and a new
  registration (`docs/vm-inventory.md:1-4`). Any party who controls the Azure deployment can deploy
  any image; verifiers decide which measurements they accept.
- **OS release approval (phase one):**
  1. An enrolled developer ES256-signs a canonical manifest.
  2. Warden checks published `disk.raw`/`pcrs.json` hashes and the PCR4 file, and retains evidence
     in WORM storage.
  3. Warden publishes the release on-chain (`docs/os-release-approval.md:48-98`, `:158-166`).
  - Phase one does **not** rebuild the OS (`docs/os-release-approval.md:3-7`).
  - `require_reproduced_os` defaults to false (`:187-189`).
  - Released OS versions cannot be withdrawn (`:185-186`).
- **Checkout vs deployed:** the MPC node pins `base-os:0.4.0-raw-sev-snp@sha256:3ad5…`
  (`projects/mpc-node/metadata.json:5`), while the proof servers pin 0.5.3. Which source revision
  built 0.4.0 is not recorded here **[spec needed]**.

## 8. Trust assumptions

- **AMD:**
  - The SEV-SNP firmware and hardware are correct.
  - The VCEK chain is authentic. In raw mode the chain is fetched through Azure IMDS/THIM
    (`server/azure_attestation_server/src/imds_operations.rs:15-30`).
  - TCB/SVN floors are taken TOFU from the first deployment.
- **Azure:**
  - The HCL/paravisor (vTPM) is in the TCB. The SNP launch measurement covers it, but its PCR0-3
    are accepted TOFU.
  - The vTPM AK certificate chains to "Azure Virtual TPM Root Certificate Authority 2023"
    (`server/guest_attestation/veritee_attestation/document.py:242-255`).
  - The host controls disk, network, IMDS, wireserver, DNS (`168.63.129.16`) and Key Vault.
- **Microsoft Azure Attestation (maa mode):** nonce and key binding rest entirely on the MAA token
  signature. The MAA instance is hardcoded (`server/azure_attestation_server/src/main.rs:801`).
  Raw mode removes MAA but not the Azure HCL.
- **Warden:**
  - Verification is delegated to Warden (`docs/attested-channel-implementation-plan.md:110`).
  - The CLI verifies nothing cryptographic.
  - Warden runs as a Veritee workload with a Docker socket (`projects/warden/README.md:7-12`).
  - Its wallet seed comes from Key Vault.
  - Correctness of reproduction and PCR policy is **[spec needed]**.
- **Midnight:** holds the registration record and OS-release entries. Integrity of that ledger and
  of the contract is **[spec needed]**.
- **DApp image and hooks:** part of the TCB; the hooks run as root.

## 9. Known gaps and exposures

1. **Experimental, not audited** (`README.md:12-15`). On-CVM end-to-end testing of akx is pending
   (`docs/attested-channel-implementation-plan.md:3`, `:477-489`).
2. **Rollback / state replay:**
   - Nothing provides a monotonic counter or freshness for persisted state.
   - The persist partition can be snapshotted and restored, or forked to a second VM, by the
     operator **[inference]**.
   - The akx `epoch` counter is not a security counter and probably resets per boot **[inference]**.
   - Old attestations: the threat model asks Warden to enforce TCB and age floors
     (`docs/tls-channel-binding.md:419-425`, `:449-452`).
3. **Cloning:**
   - Two VMs from the same image produce identical measurements. Nothing in the repo distinguishes
     instances in the attestation (the fixed machine-id is in `veritee-os/mkosi/rootfs/mkosi.postinst.j2:30`).
   - Per-instance identity is only the fresh `pk_e` and the MAA `x-ms-azurevm-vmid` claim
     (`server/azure_attestation_server/src/maa_jwt.rs:33`).
4. **Attestation oracle** on `GET /` with caller-chosen payload (§4.3).
5. **Unbound TPM quotes.**
6. **TOFU policy hydration** for PCR0-3 and SNP fields.
7. **`compute-pcr15.py` is stale.**
8. **Side channels:**
   - "SEV-SNP does not eliminate timing/cache side channels, and even encrypted traffic leaks
     sizes/timing" (`docs/tls-channel-binding.md:458-461`).
   - No length padding is implemented.
   - Key hygiene and zeroization remain to do (`:482-485`).
   - DoS from expensive setup is only partly mitigated by the session cap (`:465-468`).
9. **No client authentication** on the channel (`docs/tls-channel-binding.md:474-477`).
10. **The `sk_e` compromise window** lasts until rotation, and rotation happens only per boot by
    default (`docs/attested-channel-implementation-plan.md:101-103`).

## 10. Primitives a signing committee can use

**Available (shown by code):**
- **Measured code identity per node:**
  - PCR4 commits to the OS (UKI; root via verity **[inference]**).
  - PCR15 commits to the app disk root hash and the TLS endpoint key.
  - The SNP report or MAA token commits to the platform.
  - Warden reproduces the app disk and records the registration on Midnight. The record format is
    **[spec needed]**.
- **An attested per-node signing public key** `pk_e` (Ed25519), bound by `report_data_for(epoch,
  pk_e)`.
  - It is regenerated at every attestation-server start, so it is per boot, not stable.
  - It signs only akx transcripts. `EpochKey::sign` is public in the crate (`epoch.rs:33-36`), but
    `EpochManager` exposes only `begin_session` (`epoch_manager.rs:105-108`), and no HTTP route
    signs caller-chosen messages.
  - Mind the oracle caveat in §4.3.
- **An interactive encrypted channel to a node:** HPKE-derived, forward-secret, replay-protected,
  carrying HTTP to allowlisted app paths. It terminates in the host attestation server and reaches
  the app as plaintext on loopback.
- **An attested TLS endpoint:** in `internal` mode the CA is generated per boot in the VM and
  committed to PCR15. In `azure_vault` mode the key is operator-supplied, so it is not an
  enclave-only key.
- **A nonce-bound fresh attestation** with a caller-chosen `payload` on `GET /tee_attestation`. A
  node could use this to bind its own app-level public key, for example a committee share key, by
  passing its hash as payload.
  - **[inference]** No code in this repo does this.
  - Any caller can request the same, so the verifier must get the key from the node over the
    attested channel or TLS, not from the evidence alone.
- **A measured egress allowlist** per node (the packaged MPC node uses `unrestricted`).

**Missing (not in code):**
- Sealed storage or TPM/SNP-derived keys. Keys do not survive a redeploy, and they survive a reboot
  only as unencrypted files on persist.
- A monotonic counter, anti-rollback or anti-fork protection for state.
- A static attested encryption key, so requests cannot be sealed offline to a node.
- An application-held attested key. The akx key is in the platform server, not the app.
- Attestation-gated key release, so the platform cannot provision a share only to a verified node.
- Secure erasure (`zeroize`) and side-channel hardening of app traffic.
- An instance-unique identity beyond the per-boot `pk_e` and the MAA `vmid` claim.
- Independent client-side verification. The repo delegates to Warden; a TypeScript verifier exists
  in another repo **[spec needed]**.
